// Package mask маскирует IP-адреса, имена хостов и секреты в телах запросов
// к апстриму и возвращает исходные значения в ответах.
//
// Модель видит правдоподобные суррогаты — IP того же класса, host-N.example,
// ghp_MASKED0001 — и продолжает нормально рассуждать, а наружу настоящие
// значения не уходят. Таблица «значение ↔ суррогат» живёт в памяти процесса,
// отдельная на каждую метку токена шлюза. Пакет не знает про HTTP: на входе
// и выходе — байты JSON и поток SSE.
package mask

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// IPMode — какие адреса ловит встроенный детектор IP.
type IPMode int

const (
	// IPAll — все адреса, кроме loopback и неопределённого.
	IPAll IPMode = iota
	// IPPrivate — только приватные диапазоны (RFC 1918, ULA).
	IPPrivate
	// IPOff — детектор выключен.
	IPOff
)

func (m IPMode) String() string {
	switch m {
	case IPPrivate:
		return "private"
	case IPOff:
		return "off"
	default:
		return "all"
	}
}

// regexRule — пользовательское правило regex: имя становится префиксом
// суррогата и категорией в счётчиках.
type regexRule struct {
	name string
	re   *regexp.Regexp
	// group — маскировать первую группу захвата, а не всё совпадение.
	group bool
}

// Rules — разобранный файл правил.
type Rules struct {
	IP IPMode
	// hostExact — точные имена хостов в нижнем регистре.
	hostExact map[string]bool
	// hostBare — имена без точки (gitlab-prod): точечный кандидат их не
	// находит, поэтому для каждого свой regex с границами слова.
	hostBare []*regexp.Regexp
	// hostSuffix — домены из правил вида *.corp.local, без «*.», в нижнем
	// регистре. Совпадает и сам домен, и любое имя под ним.
	hostSuffix []string
	// secrets — литералы, маскируемые в любом контексте.
	secrets []string
	regexes []regexRule
}

// regexName — имя категории пользовательского regex: латиница и цифры в
// верхнем регистре, чтобы суррогат PASSWORD0001 выглядел как константа.
var regexName = regexp.MustCompile(`^[A-Z][A-Z0-9]*$`)

// LoadRules читает и проверяет файл правил. Ошибка называет файл и строку.
func LoadRules(path string) (*Rules, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("файл правил маскирования: %w", err)
	}
	defer f.Close()
	return ParseRules(f, path)
}

// ParseRules разбирает правила из r; name нужен только для сообщений об
// ошибках. Одно правило на строку: ключевое слово, пробелы, значение.
// Пустые строки и строки, начинающиеся с #, пропускаются.
func ParseRules(r io.Reader, name string) (*Rules, error) {
	rules := &Rules{hostExact: map[string]bool{}}
	sc := bufio.NewScanner(r)
	// Строка с длинным regex или PEM-подобным литералом не должна упираться
	// в буфер по умолчанию (64 КиБ).
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)

	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keyword := strings.Fields(line)[0]
		rest := strings.TrimSpace(line[len(keyword):])
		if rest == "" {
			return nil, fmt.Errorf("%s:%d: у правила %q нет значения", name, lineNo, keyword)
		}

		switch keyword {
		case "host":
			addHost(rules, rest)
		case "secret":
			rules.secrets = append(rules.secrets, rest)
		case "regex":
			ruleName := strings.Fields(rest)[0]
			pattern := strings.TrimSpace(rest[len(ruleName):])
			if pattern == "" {
				return nil, fmt.Errorf("%s:%d: regex задаётся как «regex ИМЯ паттерн»", name, lineNo)
			}
			if !regexName.MatchString(ruleName) {
				return nil, fmt.Errorf("%s:%d: имя категории %q — только латиница и цифры в верхнем регистре", name, lineNo, ruleName)
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: некорректный regex: %v", name, lineNo, err)
			}
			rules.regexes = append(rules.regexes, regexRule{name: ruleName, re: re, group: re.NumSubexp() > 0})
		case "ip":
			switch strings.ToLower(rest) {
			case "all":
				rules.IP = IPAll
			case "private":
				rules.IP = IPPrivate
			case "off":
				rules.IP = IPOff
			default:
				return nil, fmt.Errorf("%s:%d: ip принимает all, private или off, получено %q", name, lineNo, rest)
			}
		default:
			return nil, fmt.Errorf("%s:%d: неизвестное правило %q (ожидается host, secret, regex или ip)", name, lineNo, keyword)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: чтение: %w", name, err)
	}
	return rules, nil
}

// addHost регистрирует правило host: «*.домен» — суффикс, иначе точное имя.
func addHost(rules *Rules, value string) {
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if suffix, found := strings.CutPrefix(value, "*."); found {
		rules.hostSuffix = append(rules.hostSuffix, suffix)
		return
	}
	rules.hostExact[value] = true
	if !strings.Contains(value, ".") {
		rules.hostBare = append(rules.hostBare, regexp.MustCompile(`(?i)\b`+regexp.QuoteMeta(value)+`\b`))
	}
}

// Summary — короткая сводка для стартового лога.
func (r *Rules) Summary() string {
	return fmt.Sprintf("ip=%s hosts=%d secrets=%d regex=%d",
		r.IP, len(r.hostExact)+len(r.hostSuffix), len(r.secrets), len(r.regexes))
}

// regexNames — имена пользовательских категорий; нужны сканеру суррогатов.
func (r *Rules) regexNames() []string {
	names := make([]string, 0, len(r.regexes))
	for _, rr := range r.regexes {
		names = append(names, rr.name)
	}
	return names
}
