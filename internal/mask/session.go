package mask

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"
	"sync"
)

// Options — настройки реестра.
type Options struct {
	// Debug — писать в лог каждую подстановку с исходным значением и
	// суррогатом. Это настоящие секреты открытым текстом.
	Debug  bool
	Logger *slog.Logger
}

// Registry — таблицы всех меток. Одна на процесс.
type Registry struct {
	rules   *Rules
	opts    Options
	scanner *regexp.Regexp

	mu       sync.Mutex
	sessions map[string]*Session
}

// NewRegistry создаёт реестр по правилам.
func NewRegistry(rules *Rules, opts Options) *Registry {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Registry{
		rules:    rules,
		opts:     opts,
		scanner:  surrogateScanner(rules.regexNames()),
		sessions: map[string]*Session{},
	}
}

// Rules — правила реестра.
func (r *Registry) Rules() *Rules { return r.rules }

// Session возвращает таблицу метки, создавая её при первом обращении.
func (r *Registry) Session(label string) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[label]
	if !ok {
		s = &Session{
			label:       label,
			rules:       r.rules,
			scanner:     r.scanner,
			debug:       r.opts.Debug,
			log:         r.opts.Logger,
			forward:     map[string]string{},
			reverse:     map[string]string{},
			prefixes:    map[string]struct{}{},
			regexValues: map[string]match{},
			nets:        map[netip.Prefix]netip.Prefix{},
			netHosts:    map[netip.Prefix]int{},
			usedNets:    map[netip.Prefix]bool{},
		}
		r.sessions[label] = s
	}
	return s
}

// Session — таблица «значение ↔ суррогат» одной метки токена.
//
// Биективна: одно значение всегда получает один суррогат, суррогат никогда
// не выдаётся дважды. Записи не вытесняются — удаление сломало бы
// демаскирование продолжающейся сессии Claude Code.
type Session struct {
	label   string
	rules   *Rules
	scanner *regexp.Regexp
	debug   bool
	log     *slog.Logger

	mu       sync.Mutex
	forward  map[string]string // значение → суррогат
	reverse  map[string]string // суррогат → значение
	prefixes map[string]struct{}
	// maxLen — длина самого длинного суррогата: столько байт максимум
	// удерживает SSE-поток в ожидании продолжения.
	maxLen  int
	counter int
	// regexValues — значения, найденные пользовательскими regex. Их
	// контекст (password=) в ходе модели может отсутствовать, поэтому в
	// forward-режиме они ищутся точным совпадением, а не детектором.
	regexValues map[string]match

	// nets — реальная сеть (/24 или /64) → суррогатная; в одной реальной
	// сети адреса получают суррогаты из одной суррогатной.
	nets     map[netip.Prefix]netip.Prefix
	netHosts map[netip.Prefix]int // суррогатная сеть → следующий номер хоста
	usedNets map[netip.Prefix]bool
}

// Label — метка токена, которой принадлежит таблица.
func (s *Session) Label() string { return s.label }

// Size — число записей таблицы.
func (s *Session) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.forward)
}

// lookupSurrogate — суррогат для значения, если уже выдан.
func (s *Session) lookupSurrogate(value string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sur, ok := s.forward[value]
	return sur, ok
}

// isSurrogate — выдавала ли таблица такой суррогат.
func (s *Session) isSurrogate(value string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.reverse[value]
	return ok
}

// surrogateFor возвращает суррогат для совпадения, создавая запись при
// первом обращении.
func (s *Session) surrogateFor(value string, m match) (sur string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := value
	if m.category == categoryHost {
		// Имена хостов регистронезависимы: Corp.Local и corp.local — одно.
		key = strings.ToLower(value)
	}
	if sur, ok := s.forward[key]; ok {
		return sur, nil
	}

	// Суррогат не должен совпасть ни с выданным ранее, ни с реальным
	// значением из таблицы: второе сделало бы обратную подстановку
	// неоднозначной. Для IP это отдельный генератор со своим перебором.
	for attempt := 0; attempt < 8; attempt++ {
		switch {
		case m.category == categoryIP:
			sur, err = s.ipSurrogate(value)
			if err != nil {
				return "", err
			}
		case m.category == categoryHost:
			sur = fmt.Sprintf("host-%d.example", s.next())
		case m.pemBegin != "":
			sur = fmt.Sprintf("%sMASKED%04d%s", m.pemBegin, s.next(), m.pemEnd)
		case m.regexName != "":
			sur = fmt.Sprintf("%s%04d", m.regexName, s.next())
		case m.prefix != "":
			sur = fmt.Sprintf("%sMASKED%04d", m.prefix, s.next())
		default:
			sur = fmt.Sprintf("SECRET%04d", s.next())
		}
		if _, taken := s.reverse[sur]; taken {
			continue
		}
		if _, real := s.forward[sur]; real {
			continue
		}
		s.forward[key] = sur
		s.reverse[sur] = value
		if m.regexName != "" {
			s.regexValues[value] = match{category: m.category, regexName: m.regexName}
		}
		for i := 1; i < len(sur); i++ {
			s.prefixes[sur[:i]] = struct{}{}
		}
		if len(sur) > s.maxLen {
			s.maxLen = len(sur)
		}
		if s.debug {
			s.log.Info("mask", "token", s.label, "category", m.category, "from", value, "to", sur)
		}
		return sur, nil
	}
	return "", fmt.Errorf("не удалось подобрать уникальный суррогат для категории %s", m.category)
}

func (s *Session) next() int {
	s.counter++
	return s.counter
}

// realFor — исходное значение по суррогату.
func (s *Session) realFor(sur string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	real, ok := s.reverse[sur]
	if ok && s.debug {
		s.log.Info("unmask", "token", s.label, "from", sur, "to", real)
	}
	return real, ok
}

// knownRegexValues находит точные вхождения значений, выданных
// пользовательскими regex.
func (s *Session) knownRegexValues(text string) []match {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ms []match
	for value, proto := range s.regexValues {
		for pos := 0; ; {
			i := strings.Index(text[pos:], value)
			if i < 0 {
				break
			}
			start := pos + i
			m := proto
			m.start, m.end = start, start+len(value)
			ms = append(ms, m)
			pos = m.end
		}
	}
	return ms
}

// heldTail — самый длинный суффикс текста, который является собственным
// префиксом какого-либо суррогата. Ровно столько SSE-поток удерживает до
// следующей дельты: суррогат мог быть разрезан границей событий.
func (s *Session) heldTail(text string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := s.maxLen - 1
	if limit > len(text) {
		limit = len(text)
	}
	for n := limit; n > 0; n-- {
		if _, ok := s.prefixes[text[len(text)-n:]]; ok {
			return text[len(text)-n:]
		}
	}
	return ""
}

// --- Суррогаты IP ---

var (
	docNets = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("192.0.2.0/24")}
	ulaV6   = netip.MustParsePrefix("fc00::/7")
)

// ipSurrogate выдаёт адрес того же класса из суррогатной сети, закреплённой
// за реальной /24 (/64). Порядковый номер хоста — счётчик сети.
func (s *Session) ipSurrogate(value string) (string, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return "", err
	}
	bits := 24
	if addr.Is6() {
		bits = 64
	}
	realNet, _ := addr.Prefix(bits)

	for attempt := 0; attempt < 3; attempt++ {
		surNet, ok := s.nets[realNet]
		if !ok {
			surNet, err = s.allocNet(addr)
			if err != nil {
				return "", err
			}
			s.nets[realNet] = surNet
		}
		host := s.netHosts[surNet] + 1
		if (addr.Is4() && host > 254) || (addr.Is6() && host > 0xffff) {
			// Сеть заполнена — реальная сеть переезжает в новую суррогатную.
			delete(s.nets, realNet)
			continue
		}
		s.netHosts[surNet] = host
		return withHost(surNet, host).String(), nil
	}
	return "", fmt.Errorf("исчерпан пул суррогатных сетей для %s", value)
}

// allocNet выбирает ещё не занятую суррогатную сеть того же класса.
func (s *Session) allocNet(addr netip.Addr) (netip.Prefix, error) {
	for attempt := 0; attempt < 64; attempt++ {
		var net netip.Prefix
		switch {
		case addr.Is4() && privateNets[0].Contains(addr):
			net = netip.PrefixFrom(netip.AddrFrom4([4]byte{10, randByte(), randByte(), 0}), 24)
		case addr.Is4() && privateNets[1].Contains(addr):
			net = netip.PrefixFrom(netip.AddrFrom4([4]byte{172, 16 + randByte()%16, randByte(), 0}), 24)
		case addr.Is4() && privateNets[2].Contains(addr):
			net = netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, randByte(), 0}), 24)
		case addr.Is4():
			net = s.publicV4Net(attempt)
		case ulaV6.Contains(addr):
			net = netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfd, randByte(), randByte(), randByte(), randByte(), randByte(), randByte(), randByte()}), 64)
		default:
			net = netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, randByte(), randByte(), randByte(), randByte()}), 64)
		}
		if s.usedNets[net] {
			continue
		}
		s.usedNets[net] = true
		return net, nil
	}
	return netip.Prefix{}, fmt.Errorf("исчерпан пул суррогатных сетей для %s", addr)
}

// publicV4Net — документационные /24 в случайном порядке, затем общее
// адресное пространство 100.64.0.0/10 (RFC 6598).
func (s *Session) publicV4Net(attempt int) netip.Prefix {
	if attempt < len(docNets) {
		free := make([]netip.Prefix, 0, len(docNets))
		for _, n := range docNets {
			if !s.usedNets[n] {
				free = append(free, n)
			}
		}
		if len(free) > 0 {
			return free[int(randByte())%len(free)]
		}
	}
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64 + randByte()%64, randByte(), 0}), 24)
}

// withHost подставляет номер хоста в сеть.
func withHost(net netip.Prefix, host int) netip.Addr {
	if net.Addr().Is4() {
		b := net.Addr().As4()
		b[3] = byte(host)
		return netip.AddrFrom4(b)
	}
	b := net.Addr().As16()
	binary.BigEndian.PutUint16(b[14:], uint16(host))
	return netip.AddrFrom16(b)
}

func isLetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }

func randByte() byte {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return b[0]
}

// --- Сканер суррогатов ---

// surrogateScanner — regex всех форм суррогатов. Совпадение — только
// кандидат: подставляется лишь то, что есть в обратной таблице.
func surrogateScanner(regexNames []string) *regexp.Regexp {
	names := append([]string{"SECRET"}, regexNames...)
	for i, n := range names {
		names[i] = regexp.QuoteMeta(n)
	}
	pattern := strings.Join([]string{
		`-----BEGIN [A-Z ]*PRIVATE KEY-----MASKED\d{4,}-----END [A-Z ]*PRIVATE KEY-----`,
		`(?:sk-ant-[a-z0-9]+-|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|AKIA|ASIA|xox[abpr]-|eyJ\.)MASKED\d{4,}`,
		`(?:` + strings.Join(names, "|") + `)\d{4,}`,
		`host-\d+\.example`,
		`\d{1,3}(?:\.\d{1,3}){3}`,
		`[0-9A-Fa-f:]*:[0-9A-Fa-f:]*`,
	}, "|")
	re := regexp.MustCompile(pattern)
	re.Longest()
	return re
}

// unmaskText заменяет известные суррогаты исходными значениями. escape
// преобразует значение перед вставкой (JSON-экранирование для partial_json).
// Возвращает текст и число подстановок.
func (s *Session) unmaskText(text string, escape func(string) string) (string, int) {
	var b strings.Builder
	n := 0
	pos := 0
	for pos < len(text) {
		loc := s.scanner.FindStringIndex(text[pos:])
		if loc == nil {
			break
		}
		start, end := pos+loc[0], pos+loc[1]
		real, ok := s.realFor(text[start:end])
		// Счётчик суррогата — четыре и более цифр, а SECRET0001000 из
		// hunter2000 — это SECRET0001 и хвост: укорачиваем, пока не найдём.
		// IP-суррогаты не укорачиваются: 10.7.3.90 — не 10.7.3.9 с хвостом.
		if !ok && isLetter(text[start]) && !strings.HasPrefix(text[start:end], "host-") {
			for cand := end - 1; cand > start && isDigit(text[cand]); cand-- {
				if real, ok = s.realFor(text[start:cand]); ok {
					end = cand
					break
				}
			}
		}
		if !ok {
			// Кандидат не наш — сдвигаемся на байт, а не за него: внутри
			// мог начинаться настоящий суррогат.
			b.WriteString(text[pos : start+1])
			pos = start + 1
			continue
		}
		b.WriteString(text[pos:start])
		if escape != nil {
			real = escape(real)
		}
		b.WriteString(real)
		n++
		pos = end
	}
	b.WriteString(text[pos:])
	return b.String(), n
}
