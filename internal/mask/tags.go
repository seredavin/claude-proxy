package mask

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
)

// Режим меток (--mask-tags): IP, хосты и секреты уходят на апстрим не
// правдоподобными суррогатами, а метками <<m:категория:токен>>. Токен —
// значение, зашифрованное ключом по схеме SIV: тег — HMAC от категории и
// значения, он же IV для AES-CTR. Одно значение — одна метка, метка
// расшифровывается без таблицы, чужой ключ и подменённая категория не
// сходятся с тегом.

const (
	tagOpen    = "<<m:"
	tagClose   = ">>"
	tagMACSize = 8
	// maxTagHold — предел удержания незакрытой метки в SSE-потоке: дальше
	// хвост отдаётся как есть, иначе один «<<m:» держал бы весь блок.
	maxTagHold = 64 << 10
)

// tagPattern — метка целиком: категория и токен.
var tagPattern = regexp.MustCompile(`<<m:([a-z0-9]+):([a-z2-7]+)>>`)

// tagMACOf — тег SIV: HMAC по категории и значению. Нулевой байт между
// ними исключает склейку «категория + начало значения».
func (k *Key) tagMACOf(category string, value []byte) []byte {
	m := hmac.New(sha256.New, k.tagMAC)
	m.Write([]byte(category))
	m.Write([]byte{0})
	m.Write(value)
	return m.Sum(nil)[:tagMACSize]
}

func (k *Key) tagStream(tag []byte) cipher.Stream {
	iv := make([]byte, 16)
	copy(iv, tag)
	return cipher.NewCTR(k.tagEnc, iv)
}

// sealTag шифрует значение в метку. Имя хоста шифруется в нижнем
// регистре: Corp.Local и corp.local — одна метка.
func (k *Key) sealTag(category, value string) string {
	if category == categoryHost {
		value = strings.ToLower(value)
	}
	plain := []byte(value)
	tag := k.tagMACOf(category, plain)
	out := make([]byte, tagMACSize+len(plain))
	copy(out, tag)
	k.tagStream(tag).XORKeyStream(out[tagMACSize:], plain)
	return tagOpen + category + ":" + hostEncoding.EncodeToString(out) + tagClose
}

// OpenTag расшифровывает метку: категория и исходное значение (имя хоста
// — в нижнем регистре).
func (k *Key) OpenTag(tag string) (category, value string, err error) {
	m := tagPattern.FindStringSubmatch(tag)
	if m == nil || m[0] != tag {
		return "", "", fmt.Errorf("%q — не метка", tag)
	}
	category = m[1]
	raw, err := hostEncoding.DecodeString(m[2])
	if err != nil || len(raw) <= tagMACSize {
		return "", "", fmt.Errorf("метка %q повреждена", tag)
	}
	mac := raw[:tagMACSize]
	plain := make([]byte, len(raw)-tagMACSize)
	k.tagStream(mac).XORKeyStream(plain, raw[tagMACSize:])
	if !hmac.Equal(mac, k.tagMACOf(category, plain)) {
		return "", "", fmt.Errorf("метка %q не сходится с ключом", tag)
	}
	return category, string(plain), nil
}

// RevealTags заменяет в тексте метки, которые расшифровываются ключом,
// исходными значениями. Возвращает текст, число расшифрованных и число
// нерасшифрованных меток; последние остаются как есть.
func (k *Key) RevealTags(text string) (out string, revealed, failed int) {
	out = tagPattern.ReplaceAllStringFunc(text, func(tag string) string {
		_, value, err := k.OpenTag(tag)
		if err != nil {
			failed++
			return tag
		}
		revealed++
		return value
	})
	return out, revealed, failed
}

// tagSpans — границы меток в тексте: детекторы внутри них не работают.
func tagSpans(text string) [][]int {
	if !strings.Contains(text, tagOpen) {
		return nil
	}
	return tagPattern.FindAllStringIndex(text, -1)
}

// outsideTags отбрасывает совпадения, пересекающиеся с метками.
func outsideTags(ms []match, spans [][]int) []match {
	if len(spans) == 0 {
		return ms
	}
	kept := ms[:0]
	for _, m := range ms {
		inside := false
		for _, sp := range spans {
			if m.start < sp[1] && sp[0] < m.end {
				inside = true
				break
			}
		}
		if !inside {
			kept = append(kept, m)
		}
	}
	return kept
}

// tagTail — суффикс текста, который может быть началом метки, но ещё не
// закрыт: SSE-поток удерживает его до следующей дельты. Внутри метки
// после «<<» символа «<» нет, поэтому начало ищется от последнего «<».
func tagTail(text string) string {
	p := strings.LastIndexByte(text, '<')
	if p < 0 {
		return ""
	}
	if p > 0 && text[p-1] == '<' {
		p--
	}
	if len(text)-p > maxTagHold || !isTagPrefix(text[p:]) {
		return ""
	}
	return text[p:]
}

// isTagPrefix — является ли s собственным префиксом какой-нибудь метки.
func isTagPrefix(s string) bool {
	if len(s) <= len(tagOpen) {
		return strings.HasPrefix(tagOpen, s)
	}
	if !strings.HasPrefix(s, tagOpen) {
		return false
	}
	rest := s[len(tagOpen):]
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		return allIn(rest, isTagCategoryByte)
	}
	if colon == 0 || !allIn(rest[:colon], isTagCategoryByte) {
		return false
	}
	token := rest[colon+1:]
	if t, found := strings.CutSuffix(token, ">"); found {
		if t == "" {
			return false
		}
		token = t
	}
	return allIn(token, isTokenByte)
}

func allIn(s string, ok func(byte) bool) bool {
	for i := 0; i < len(s); i++ {
		if !ok(s[i]) {
			return false
		}
	}
	return true
}

func isTagCategoryByte(b byte) bool { return (b >= 'a' && b <= 'z') || isDigit(b) }

func isTokenByte(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= '2' && b <= '7') }
