package mask

import (
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// Категории совпадений. Пользовательские regex дают свою — имя правила
// в нижнем регистре.
const (
	categoryIP     = "ip"
	categoryHost   = "host"
	categorySecret = "secret"
)

// match — найденный в тексте фрагмент, подлежащий замене.
type match struct {
	start, end int
	category   string
	// prefix — опознавательная часть, которую суррогат сохраняет
	// (ghp_, AKIA, sk-ant-api03-). Пусто — суррогат без префикса.
	prefix string
	// pem — строки BEGIN/END PEM-блока: суррогат оборачивается в них.
	pemBegin, pemEnd string
	// regexName — имя пользовательского правила, для суррогата ИМЯnnnn.
	regexName string
}

// merge сортирует совпадения и убирает перекрытия: остаётся самое левое,
// при равном начале — самое длинное. Возвращает, было ли что-то отброшено:
// остаток проигравшего мог остаться незамаскированным, и вызывающий
// повторяет проходку.
func merge(ms []match) (kept []match, dropped bool) {
	sort.Slice(ms, func(i, j int) bool {
		if ms[i].start != ms[j].start {
			return ms[i].start < ms[j].start
		}
		return ms[i].end > ms[j].end
	})
	last := -1
	for _, m := range ms {
		if m.start < last {
			dropped = true
			continue
		}
		kept = append(kept, m)
		last = m.end
	}
	return kept, dropped
}

// detect запускает детекторы правил на тексте. withRegex — включать
// пользовательские regex: в forward-режиме их значения ищутся точным
// совпадением, а сам regex со своим контекстом только мешал бы.
func (r *Rules) detect(text string, withRegex bool) []match {
	var ms []match
	if r.IP != IPOff {
		ms = append(ms, detectIPs(text, r.IP)...)
	}
	ms = append(ms, r.detectHosts(text)...)
	ms = append(ms, detectBuiltinSecrets(text)...)
	ms = append(ms, r.detectLiterals(text)...)
	if withRegex {
		ms = append(ms, r.detectRegex(text)...)
	}
	return ms
}

// --- IP ---

var (
	ipv4Candidate = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	// IPv6 распознаётся не грамматикой, а кандидатом «hex и двоеточия» с
	// последующим netip.ParseAddr: грамматика v6 в regexp нечитаема, а
	// ParseAddr отсекает время 12:30:45 и MAC-адреса сам. Точечный
	// IPv4-хвост (::ffff:10.0.0.1) идёт сразу за последним двоеточием и
	// проверяется первым: иначе жадный класс обрывает адрес на точке.
	ipv6Candidate = regexp.MustCompile(`[0-9A-Fa-f:]*:(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]*)`)

	privateNets = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("fc00::/7"),
	}
)

func isPrivate(a netip.Addr) bool {
	for _, n := range privateNets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// maskable отвечает, подлежит ли адрес маскированию в данном режиме.
// IPv4-mapped адрес решается по вложенному IPv4: ::ffff:127.0.0.1 —
// loopback, ::ffff:192.168.1.5 — приватный.
func maskable(a netip.Addr, mode IPMode) bool {
	a = a.Unmap()
	if a.IsLoopback() || a.IsUnspecified() {
		return false
	}
	if mode == IPPrivate {
		return isPrivate(a)
	}
	return true
}

func detectIPs(text string, mode IPMode) []match {
	var ms []match
	for _, loc := range ipv4Candidate.FindAllStringIndex(text, -1) {
		start, end := loc[0], loc[1]
		// Точка с цифрой по краям — часть более длинной точечной
		// последовательности (версия 1.2.3.4.5), не адрес.
		if start >= 2 && text[start-1] == '.' && isDigit(text[start-2]) {
			continue
		}
		if end+1 < len(text) && text[end] == '.' && isDigit(text[end+1]) {
			continue
		}
		a, err := netip.ParseAddr(text[start:end])
		if err != nil || !maskable(a, mode) {
			continue
		}
		ms = append(ms, match{start: start, end: end, category: categoryIP})
	}
	for _, loc := range ipv6Candidate.FindAllStringIndex(text, -1) {
		start, end := loc[0], loc[1]
		if strings.Count(text[start:end], ":") < 2 {
			continue
		}
		// Буква или цифра вплотную — это середина слова (bad::1), не адрес.
		if (start > 0 && isWordByte(text[start-1])) || (end < len(text) && isWordByte(text[end])) {
			continue
		}
		a, err := netip.ParseAddr(text[start:end])
		if err != nil || !a.Is6() || !maskable(a, mode) {
			continue
		}
		// ::ffff:a.b.c.d — маскируется только IPv4-хвост, его находит
		// детектор IPv4: так вложенный адрес получает тот же суррогат, что
		// и в обычной записи, а префикс ::ffff: остаётся текстом. Исключение
		// — «.цифра» сразу за хвостом: детектор IPv4 принял бы его за номер
		// версии и пропустил, а с префиксом ::ffff: это адрес, и хвост
		// маскируется здесь.
		if a.Is4In6() && strings.Contains(text[start:end], ".") {
			if end+1 < len(text) && text[end] == '.' && isDigit(text[end+1]) {
				tail := strings.LastIndexByte(text[start:end], ':') + start + 1
				ms = append(ms, match{start: tail, end: end, category: categoryIP})
			}
			continue
		}
		ms = append(ms, match{start: start, end: end, category: categoryIP})
	}
	return ms
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func isWordByte(b byte) bool {
	return isDigit(b) || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_'
}

// --- Хосты ---

// hostCandidate — точечное имя, у которого последняя метка начинается с
// буквы: так IP-адреса и номера версий сюда не попадают.
var hostCandidate = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}\b`)

// builtinTLDs — непубличные TLD, имена под которыми маскируются без правил.
var builtinTLDs = []string{"local", "internal", "lan", "corp", "home", "intranet", "private"}

func (r *Rules) hostMatches(name string) bool {
	name = strings.ToLower(name)
	if name == "localhost" {
		return false
	}
	if r.hostExact[name] {
		return true
	}
	for _, suffix := range r.hostSuffix {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
	}
	if dot := strings.LastIndexByte(name, '.'); dot >= 0 {
		tld := name[dot+1:]
		for _, t := range builtinTLDs {
			if tld == t {
				return true
			}
		}
	}
	return false
}

func (r *Rules) detectHosts(text string) []match {
	var ms []match
	for _, loc := range hostCandidate.FindAllStringIndex(text, -1) {
		if r.hostMatches(text[loc[0]:loc[1]]) {
			ms = append(ms, match{start: loc[0], end: loc[1], category: categoryHost})
		}
	}
	// Точные имена без точки (gitlab-prod) кандидатом выше не ловятся.
	for _, re := range r.hostBare {
		for _, loc := range re.FindAllStringIndex(text, -1) {
			ms = append(ms, match{start: loc[0], end: loc[1], category: categoryHost})
		}
	}
	return ms
}

// --- Секреты ---

// builtinSecret — известный формат ключа: первая группа — сохраняемый префикс.
type builtinSecret struct {
	re *regexp.Regexp
	// prefixOverride — префикс суррогата, если он отличается от группы
	// (JWT: три base64-сегмента сворачиваются в eyJ.MASKEDnnnn).
	prefixOverride string
}

var builtinSecrets = []builtinSecret{
	{re: regexp.MustCompile(`\b(sk-ant-[a-z0-9]+-)[A-Za-z0-9_-]{16,}`)},
	{re: regexp.MustCompile(`\b(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]{20,}`)},
	{re: regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`)},
	{re: regexp.MustCompile(`\b(xox[abpr]-)[A-Za-z0-9-]{10,}`)},
	{re: regexp.MustCompile(`\b(eyJ)[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), prefixOverride: "eyJ."},
}

// pemBlock — приватный ключ в PEM. (?s) — тело многострочное.
var pemBlock = regexp.MustCompile(`(?s)(-----BEGIN [A-Z ]*PRIVATE KEY-----).*?(-----END [A-Z ]*PRIVATE KEY-----)`)

func detectBuiltinSecrets(text string) []match {
	var ms []match
	for _, loc := range pemBlock.FindAllStringSubmatchIndex(text, -1) {
		ms = append(ms, match{
			start: loc[0], end: loc[1], category: categorySecret,
			pemBegin: text[loc[2]:loc[3]], pemEnd: text[loc[4]:loc[5]],
		})
	}
	for _, b := range builtinSecrets {
		for _, loc := range b.re.FindAllStringSubmatchIndex(text, -1) {
			prefix := b.prefixOverride
			if prefix == "" {
				prefix = text[loc[2]:loc[3]]
			}
			ms = append(ms, match{start: loc[0], end: loc[1], category: categorySecret, prefix: prefix})
		}
	}
	return ms
}

func (r *Rules) detectLiterals(text string) []match {
	var ms []match
	for _, lit := range r.secrets {
		for pos := 0; ; {
			i := strings.Index(text[pos:], lit)
			if i < 0 {
				break
			}
			start := pos + i
			ms = append(ms, match{start: start, end: start + len(lit), category: categorySecret})
			pos = start + len(lit)
		}
	}
	return ms
}

func (r *Rules) detectRegex(text string) []match {
	var ms []match
	for _, rr := range r.regexes {
		for _, loc := range rr.re.FindAllStringSubmatchIndex(text, -1) {
			start, end := loc[0], loc[1]
			if rr.group {
				// Группа не участвовала в совпадении — маскировать нечего.
				if loc[2] < 0 {
					continue
				}
				start, end = loc[2], loc[3]
			}
			if start == end {
				continue
			}
			ms = append(ms, match{
				start: start, end: end,
				category:  strings.ToLower(rr.name),
				regexName: rr.name,
			})
		}
	}
	return ms
}
