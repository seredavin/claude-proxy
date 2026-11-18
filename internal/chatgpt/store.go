// Package chatgpt управляет локальными профилями Sign in with ChatGPT.
package chatgpt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/seredavin/claude-proxy/internal/config"
)

const (
	issuer   = "https://auth.openai.com"
	resource = "https://api.openai.com/v1"
	tokenURL = issuer + "/api/accounts/oauth/token"
)

type Store struct {
	dir    string
	client *http.Client
}

func NewStore(dir string) *Store {
	return &Store{dir: dir, client: &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

type profile struct {
	ClientID     string    `json:"client_id"`
	Subject      string    `json:"subject"`
	Email        string    `json:"email"`
	IDToken      string    `json:"id_token,omitempty"`
	AccessToken  string    `json:"access_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	Expires      time.Time `json:"expires"`
}

func (s *Store) locked(ctx context.Context, name string, fn func(string) error) error {
	if !config.ValidProfileName(name) {
		return fmt.Errorf("недопустимое имя профиля ChatGPT")
	}
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(s.dir, name+".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	timer := time.NewTicker(100 * time.Millisecond)
	defer timer.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			return fn(filepath.Join(s.dir, name+".json"))
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func readProfile(path string) (profile, error) {
	var p profile
	f, err := os.Open(path)
	if err != nil {
		return p, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return p, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return p, errors.New("файл профиля ChatGPT должен иметь права 0600")
	}
	if err := json.NewDecoder(f).Decode(&p); err != nil {
		return p, errors.New("не удалось прочитать профиль ChatGPT")
	}
	return p, nil
}

func saveProfile(path string, value any) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".chatgpt-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := json.NewEncoder(file).Encode(value); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func (s *Store) hostID(ctx context.Context) (string, error) {
	var host string
	err := s.locked(ctx, "host-id-internal", func(path string) error {
		path = filepath.Join(s.dir, "host-id")
		data, err := os.ReadFile(path)
		if err == nil {
			return json.Unmarshal(data, &host)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		b[6] = b[6]&0x0f | 0x40
		b[8] = b[8]&0x3f | 0x80
		id := hex.EncodeToString(b)
		host = "urn:uuid:" + id[:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:]
		return saveProfile(path, host)
	})
	return host, err
}

func hasPlan(scope string) bool {
	granted := make(map[string]bool)
	for _, item := range strings.Fields(scope) {
		granted[item] = true
	}
	return granted["resource.invoke"] && granted["chatgpt.tokens.use.direct"]
}

func (s *Store) AccessToken(ctx context.Context, name string) (string, error) {
	var token string
	err := s.locked(ctx, name, func(path string) error {
		p, err := readProfile(path)
		if errors.Is(err, os.ErrNotExist) || (err == nil && (!hasPlan(p.Scope) || p.RefreshToken == "")) {
			return fmt.Errorf("войдите в ChatGPT: claude-proxy chatgpt login --profile %s", name)
		}
		if err != nil {
			return err
		}
		if time.Until(p.Expires) < time.Minute || p.AccessToken == "" {
			next, err := s.exchange(ctx, url.Values{
				"grant_type": {"refresh_token"}, "client_id": {p.ClientID}, "refresh_token": {p.RefreshToken},
			})
			if errors.Is(err, errInvalidGrant) {
				p.AccessToken, p.RefreshToken, p.Scope = "", "", ""
				p.Expires = time.Time{}
				if err := saveProfile(path, p); err != nil {
					return err
				}
				return fmt.Errorf("сеанс ChatGPT завершён, повторите вход: claude-proxy chatgpt login --profile %s", name)
			}
			if err != nil {
				return err
			}
			// Сохраняем ID token, проверенный при входе.
			next.IDToken = ""
			applyTokens(&p, next)
			if err := saveProfile(path, p); err != nil {
				return err
			}
			if !hasPlan(p.Scope) {
				return fmt.Errorf("профиль %q больше не разрешает использование плана ChatGPT", name)
			}
		}
		token = p.AccessToken
		return nil
	})
	return token, err
}
