// Package auth хранит токены доступа к шлюзу и сверяет их за постоянное время.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Token — один пропуск на шлюз. Метка нужна только для логов и отзыва:
// в логи пишется она, само значение — никогда.
type Token struct {
	Label string
	Value string
}

// Set — набор действующих токенов.
type Set struct {
	tokens []Token
}

// DefaultLabel присваивается токену, заданному без метки
// (в том числе унаследованному из GATEWAY_TOKEN).
const DefaultLabel = "default"

// Parse разбирает спецификацию вида "team-a:HEX,team-b:HEX".
// Элемент без двоеточия считается токеном без метки.
// Пустая строка даёт пустой набор — это не ошибка, проверку делает вызывающий.
func Parse(spec string) (Set, error) {
	var s Set
	for _, raw := range strings.Split(spec, ",") {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}

		label, value := DefaultLabel, item
		if i := strings.Index(item, ":"); i >= 0 {
			label = strings.TrimSpace(item[:i])
			value = strings.TrimSpace(item[i+1:])
		}
		if label == "" {
			return Set{}, fmt.Errorf("пустая метка в %q", item)
		}
		if value == "" {
			return Set{}, fmt.Errorf("пустое значение токена для метки %q", label)
		}
		if strings.ContainsAny(value, " \t\r\n") {
			return Set{}, fmt.Errorf("токен %q содержит пробельные символы — вероятно, испорчен переводом строки", label)
		}
		if err := s.add(Token{Label: label, Value: value}); err != nil {
			return Set{}, err
		}
	}
	return s, nil
}

func (s *Set) add(t Token) error {
	for _, existing := range s.tokens {
		if existing.Label == t.Label {
			return fmt.Errorf("метка %q встречается дважды", t.Label)
		}
		if existing.Value == t.Value {
			return fmt.Errorf("метки %q и %q используют одно значение токена", existing.Label, t.Label)
		}
	}
	s.tokens = append(s.tokens, t)
	return nil
}

// Empty сообщает, что действующих токенов нет. Шлюз с пустым набором
// пропускал бы всех, поэтому такой конфиг отвергается на старте.
func (s Set) Empty() bool { return len(s.tokens) == 0 }

// Len возвращает количество токенов.
func (s Set) Len() int { return len(s.tokens) }

// Labels возвращает отсортированный список меток — для стартового лога.
func (s Set) Labels() []string {
	out := make([]string, 0, len(s.tokens))
	for _, t := range s.tokens {
		out = append(out, t.Label)
	}
	sort.Strings(out)
	return out
}

// Lookup ищет предъявленное значение среди известных токенов.
//
// Перебираются все токены до конца, сравнение — constant-time: время ответа
// не зависит ни от позиции совпавшего токена, ни от длины общего префикса.
// Утекает только длина значения, что для hex-токена несущественно.
func (s Set) Lookup(candidate string) (label string, ok bool) {
	var matched int
	for _, t := range s.tokens {
		if subtle.ConstantTimeCompare([]byte(t.Value), []byte(candidate)) == 1 {
			label = t.Label
			matched = 1
		}
	}
	return label, matched == 1
}

// Generate создаёт случайный токен: 32 байта энтропии в hex.
// Только hex — значение попадает в shell-команды на клиентах и в
// EnvironmentFile systemd, где спецсимволы пришлось бы экранировать.
func Generate() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand на поддерживаемых ОС не возвращает ошибку; если вернул —
		// продолжать с предсказуемым токеном нельзя.
		panic("claude-proxy: недоступен источник случайных чисел: " + err.Error())
	}
	return hex.EncodeToString(buf)
}

// First возвращает первый токен набора. Нужен подсказке для клиента:
// когда токен один, печатать его целиком удобнее, чем плейсхолдер.
func (s Set) First() (Token, bool) {
	if len(s.tokens) == 0 {
		return Token{}, false
	}
	return s.tokens[0], true
}
