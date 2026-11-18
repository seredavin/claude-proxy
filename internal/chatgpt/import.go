package chatgpt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Import переносит сеанс, полученный через локальный вход, в каталог
// состояния шлюза. Идентификатор хоста создаётся отдельно от профиля.
func (s *Store) Import(ctx context.Context, name string, input io.Reader) error {
	const maxProfile = 1 << 20
	data, err := io.ReadAll(io.LimitReader(input, maxProfile+1))
	if err != nil {
		return fmt.Errorf("не удалось прочитать профиль ChatGPT: %w", err)
	}
	var incoming profile
	if len(data) > maxProfile || json.Unmarshal(data, &incoming) != nil ||
		incoming.ClientID == "" || incoming.ClientID == dynamicClient || incoming.Subject == "" ||
		incoming.IDToken == "" || incoming.AccessToken == "" || incoming.RefreshToken == "" ||
		incoming.Expires.IsZero() || !hasPlan(incoming.Scope) ||
		strings.ContainsAny(incoming.AccessToken, " \r\n\t") {
		return errors.New("ожидается действующий профиль с разрешением ChatGPT plan usage")
	}
	if _, err := s.hostID(ctx); err != nil {
		return err
	}
	return s.locked(ctx, name, func(path string) error {
		p, err := readProfile(path)
		if errors.Is(err, os.ErrNotExist) {
			return saveProfile(path, incoming)
		}
		if err != nil {
			return err
		}
		if p.RefreshToken != "" || p.Subject != incoming.Subject || p.ClientID != incoming.ClientID {
			return errors.New("имя профиля занято. Используйте отдельное имя или завершите текущий сеанс перед повторным импортом")
		}
		return saveProfile(path, incoming)
	})
}
