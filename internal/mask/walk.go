package mask

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Stats — счётчики одного запроса для access-лога. Значений здесь нет.
type Stats struct {
	// Masked — подстановки в запросе по категориям: ip, host, secret и
	// имена пользовательских regex в нижнем регистре.
	Masked map[string]int
	// Unmasked — обратные подстановки в ответе.
	Unmasked int
	// Errors — события или тела ответа, которые не удалось разобрать.
	Errors int
}

func (st *Stats) add(category string) {
	if st.Masked == nil {
		st.Masked = map[string]int{}
	}
	st.Masked[category]++
}

// Categories — категории с ненулевыми счётчиками в стабильном порядке.
func (st *Stats) Categories() []string {
	keys := make([]string, 0, len(st.Masked))
	for k := range st.Masked {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// skipKeys — служебные поля Messages API, где подстановка сломала бы
// протокол, а секретов не бывает.
var skipKeys = map[string]bool{
	"model": true, "type": true, "role": true, "id": true, "tool_use_id": true,
	"name": true, "signature": true, "media_type": true,
}

// walkMode — что делать со строками поддерева.
type walkMode int

const (
	// modeDetect — детекторы плюс таблица: пользовательские ходы, system, tools.
	modeDetect walkMode = iota
	// modeForward — только замена известных значений на их суррогаты: ходы
	// модели, чей текст подписан (thinking.signature) и не должен меняться
	// иначе, чем мы сами его меняли при демаскировании.
	modeForward
	// modeReverse — суррогаты → значения: ответ апстрима.
	modeReverse
)

// MaskRequest маскирует все строки JSON-тела запроса. Ошибка — тело не
// разобралось или исчерпан пул суррогатов; вызывающий решает по политике
// сбоя, что делать.
func (s *Session) MaskRequest(body []byte) ([]byte, Stats, error) {
	var st Stats
	root, err := decode(body)
	if err != nil {
		return nil, st, err
	}
	if err := s.walk(root, modeDetect, &st); err != nil {
		return nil, st, err
	}
	out, err := encode(root)
	return out, st, err
}

// UnmaskJSON возвращает исходные значения в строки не-SSE ответа.
func (s *Session) UnmaskJSON(body []byte) ([]byte, int, error) {
	root, err := decode(body)
	if err != nil {
		return nil, 0, err
	}
	var st Stats
	if err := s.walk(root, modeReverse, &st); err != nil {
		return nil, 0, err
	}
	out, err := encode(root)
	return out, st.Unmasked, err
}

// decode разбирает JSON с сохранением чисел как есть.
func decode(body []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("тело не разобралось как JSON: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("тело не разобралось как JSON: лишние данные после значения")
	}
	return root, nil
}

// encode сериализует дерево, не трогая <, > и & в коде.
func encode(root any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// walk переписывает строки дерева на месте.
func (s *Session) walk(v any, mode walkMode, st *Stats) error {
	switch node := v.(type) {
	case map[string]any:
		if t, _ := node["type"].(string); t == "redacted_thinking" {
			return nil
		}
		childMode := mode
		if mode == modeDetect {
			if role, _ := node["role"].(string); role == "assistant" {
				childMode = modeForward
			}
		}
		for k, child := range node {
			if skipKeys[k] {
				continue
			}
			// Данные изображений и документов: base64, секретов там нет,
			// а JWT-подобные последовательности — есть.
			if k == "data" {
				if t, _ := node["type"].(string); t == "base64" {
					continue
				}
			}
			switch c := child.(type) {
			case string:
				out, err := s.rewrite(c, childMode, st)
				if err != nil {
					return err
				}
				node[k] = out
			default:
				if err := s.walk(c, childMode, st); err != nil {
					return err
				}
			}
		}
	case []any:
		for i, child := range node {
			switch c := child.(type) {
			case string:
				out, err := s.rewrite(c, mode, st)
				if err != nil {
					return err
				}
				node[i] = out
			default:
				if err := s.walk(c, mode, st); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// rewrite переписывает одну строку в заданном режиме.
func (s *Session) rewrite(text string, mode walkMode, st *Stats) (string, error) {
	if text == "" {
		return text, nil
	}
	switch mode {
	case modeReverse:
		out, n := s.unmaskText(text, nil)
		st.Unmasked += n
		return out, nil
	case modeForward:
		return s.maskText(text, false, st)
	default:
		return s.maskText(text, true, st)
	}
}

// maxPasses — предел повторных проходок при отброшенных перекрытиях.
const maxPasses = 3

// maskText заменяет совпадения детекторов суррогатами. create — создавать
// новые записи таблицы; иначе подставляются только уже известные.
func (s *Session) maskText(text string, create bool, st *Stats) (string, error) {
	for pass := 0; pass < maxPasses; pass++ {
		found := s.rules.detect(text, create)
		if !create {
			found = append(found, s.knownRegexValues(text)...)
		}
		matches, dropped := merge(found)
		if len(matches) == 0 {
			return text, nil
		}
		var b strings.Builder
		pos := 0
		replaced := 0
		for _, m := range matches {
			value := text[m.start:m.end]
			// Значение — уже наш суррогат (пользователь вставил в промпт кусок
			// ответа модели): маскировать его ещё раз нельзя.
			if s.isSurrogate(value) {
				continue
			}
			var sur string
			if create {
				var err error
				if sur, err = s.surrogateFor(value, m); err != nil {
					return "", err
				}
			} else {
				var ok bool
				if sur, ok = s.lookupSurrogate(value, m.category); !ok {
					continue
				}
			}
			b.WriteString(text[pos:m.start])
			b.WriteString(sur)
			pos = m.end
			replaced++
			st.add(m.category)
		}
		b.WriteString(text[pos:])
		text = b.String()
		if !dropped || replaced == 0 {
			return text, nil
		}
	}
	return text, nil
}
