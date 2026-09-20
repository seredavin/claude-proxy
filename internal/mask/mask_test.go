package mask

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"
)

func mustRules(t *testing.T, text string) *Rules {
	t.Helper()
	r, err := ParseRules(strings.NewReader(text), "rules")
	if err != nil {
		t.Fatalf("правила: %v", err)
	}
	return r
}

func newSession(t *testing.T, rulesText string) *Session {
	t.Helper()
	return NewRegistry(mustRules(t, rulesText), Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Session("test")
}

// maskString маскирует одну строку через полный обход JSON.
func maskString(t *testing.T, s *Session, text string) (string, Stats) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "user", "content": text}}})
	out, st, err := s.MaskRequest(body)
	if err != nil {
		t.Fatalf("MaskRequest: %v", err)
	}
	var v struct {
		Messages []struct{ Content string } `json:"messages"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("ответ не JSON: %v\n%s", err, out)
	}
	return v.Messages[0].Content, st
}

// --- Правила ---

func TestПравилаКомментарииИПустыеСтроки(t *testing.T) {
	r := mustRules(t, "# прод\n\n  host *.corp.local\n")
	if len(r.hostSuffix) != 1 || r.hostSuffix[0] != "corp.local" {
		t.Fatalf("suffix = %v", r.hostSuffix)
	}
	if r.Summary() != "ip=all hosts=1 secrets=0 regex=0" {
		t.Errorf("summary = %q", r.Summary())
	}
}

func TestПравилаПустойФайлВключаетВстроенные(t *testing.T) {
	s := newSession(t, "")
	out, st := maskString(t, s, "ssh 10.0.0.5")
	if strings.Contains(out, "10.0.0.5") || st.Masked["ip"] != 1 {
		t.Errorf("out = %q stats = %v", out, st.Masked)
	}
}

func TestПравилаОшибкаСНомеромСтроки(t *testing.T) {
	tests := []struct{ text, want string }{
		{"host a\n\n\n\n\n\nbogus x\n", "rules:7"},
		{"regex PASSWORD (\n", "rules:1"},
		{"regex password x\n", "верхнем регистре"},
		{"ip sometimes\n", "all, private или off"},
		{"secret\n", "нет значения"},
	}
	for _, tt := range tests {
		_, err := ParseRules(strings.NewReader(tt.text), "rules")
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%q: err = %v, ожидалось %q", tt.text, err, tt.want)
		}
	}
}

// --- IP ---

func TestIPПодсетьСохраняется(t *testing.T) {
	s := newSession(t, "")
	out, _ := maskString(t, s, "a=10.20.30.40 b=10.20.30.41 c=10.99.1.1")
	re := regexp.MustCompile(`a=(\S+) b=(\S+) c=(\S+)`)
	m := re.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("out = %q", out)
	}
	a, b, c := netip.MustParseAddr(m[1]), netip.MustParseAddr(m[2]), netip.MustParseAddr(m[3])
	for _, x := range []netip.Addr{a, b, c} {
		if !netip.MustParsePrefix("10.0.0.0/8").Contains(x) {
			t.Errorf("%s не в 10/8", x)
		}
		if x == netip.MustParseAddr("10.20.30.40") || x == netip.MustParseAddr("10.20.30.41") {
			t.Errorf("суррогат совпал с исходным: %s", x)
		}
	}
	pa, _ := a.Prefix(24)
	pb, _ := b.Prefix(24)
	if pa != pb {
		t.Errorf("a и b в разных /24: %s %s", a, b)
	}
	if a == b {
		t.Errorf("a и b совпали: %s", a)
	}
}

func TestIPLoopbackНеТрогается(t *testing.T) {
	s := newSession(t, "")
	in := "127.0.0.1:9443 http://localhost:9443 0.0.0.0 ::1"
	if out, _ := maskString(t, s, in); out != in {
		t.Errorf("out = %q", out)
	}
}

func TestIPПортИПрефиксСохраняются(t *testing.T) {
	s := newSession(t, "")
	out, _ := maskString(t, s, "ssh 10.0.0.5:2222 net 10.0.0.0/24")
	if !regexp.MustCompile(`ssh 10\.\d+\.\d+\.\d+:2222 net 10\.\d+\.\d+\.\d+/24`).MatchString(out) {
		t.Errorf("out = %q", out)
	}
}

func TestIPПубличныйМаскируетсяДокументационным(t *testing.T) {
	s := newSession(t, "")
	out, _ := maskString(t, s, "dns 93.184.216.34")
	addr := netip.MustParseAddr(strings.TrimPrefix(out, "dns "))
	if !netip.MustParsePrefix("203.0.113.0/24").Contains(addr) &&
		!netip.MustParsePrefix("198.51.100.0/24").Contains(addr) &&
		!netip.MustParsePrefix("192.0.2.0/24").Contains(addr) {
		t.Errorf("суррогат %s не из документационного диапазона", addr)
	}
}

func TestIPТолькоПриватные(t *testing.T) {
	s := newSession(t, "ip private")
	out, _ := maskString(t, s, "93.184.216.34 192.168.1.10")
	if !strings.HasPrefix(out, "93.184.216.34 ") || strings.Contains(out, "192.168.1.10") {
		t.Errorf("out = %q", out)
	}
}

func TestIPВыключен(t *testing.T) {
	s := newSession(t, "ip off")
	if out, _ := maskString(t, s, "10.0.0.5"); out != "10.0.0.5" {
		t.Errorf("out = %q", out)
	}
}

func TestIPВерсииИСловаНеАдреса(t *testing.T) {
	s := newSession(t, "")
	in := "v1.2.3.4 go1.2.3.4.5 std::string foo::bar time 12:30:45 mac aa:bb:cc:dd:ee:ff"
	if out, _ := maskString(t, s, in); out != in {
		t.Errorf("out = %q", out)
	}
}

func TestIPv6(t *testing.T) {
	s := newSession(t, "")
	out, _ := maskString(t, s, "addr [2001:4860:4860::8888]:53 ula fd12::1")
	m := regexp.MustCompile(`addr \[([0-9a-f:]+)\]:53 ula ([0-9a-f:]+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("out = %q", out)
	}
	if !netip.MustParsePrefix("2001:db8::/32").Contains(netip.MustParseAddr(m[1])) {
		t.Errorf("публичный v6 → %s", m[1])
	}
	if !netip.MustParsePrefix("fc00::/7").Contains(netip.MustParseAddr(m[2])) {
		t.Errorf("ULA → %s", m[2])
	}
}

func TestIPПереходВОбщееПространствоБезПовторов(t *testing.T) {
	s := newSession(t, "")
	seen := map[string]bool{}
	for i := 0; i < 900; i++ {
		// 900 адресов в разных публичных /24: три документационных сети
		// вмещают 762, дальше — 100.64/10.
		addr := netip.AddrFrom4([4]byte{8, byte(i / 256), byte(i % 256), 1}).String()
		sur, err := s.surrogateFor(addr, match{category: categoryIP})
		if err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		if seen[sur] {
			t.Fatalf("суррогат %s выдан дважды", sur)
		}
		seen[sur] = true
	}
	shared := 0
	for sur := range seen {
		if netip.MustParsePrefix("100.64.0.0/10").Contains(netip.MustParseAddr(sur)) {
			shared++
		}
	}
	if shared == 0 {
		t.Error("после исчерпания документационных сетей ожидались адреса из 100.64/10")
	}
}

// --- Хосты ---

func TestХостыСуффиксДомена(t *testing.T) {
	s := newSession(t, "host *.corp.local")
	out, st := maskString(t, s, "prod-db.corp.local Corp.Local api.github.com")
	if !regexp.MustCompile(`^host-\d+\.example host-\d+\.example api\.github\.com$`).MatchString(out) {
		t.Errorf("out = %q", out)
	}
	if st.Masked["host"] != 2 {
		t.Errorf("stats = %v", st.Masked)
	}
}

func TestХостыНепубличныйTLDБезПравила(t *testing.T) {
	s := newSession(t, "")
	out, _ := maskString(t, s, "git clone gitlab.internal/repo; localhost ok")
	if !regexp.MustCompile(`^git clone host-\d+\.example/repo; localhost ok$`).MatchString(out) {
		t.Errorf("out = %q", out)
	}
}

func TestХостыВURLИEmailИБезТочки(t *testing.T) {
	s := newSession(t, "host *.corp.local\nhost gitlab-prod")
	out, _ := maskString(t, s, "https://wiki.corp.local/page admin@mail.corp.local ssh gitlab-prod:22 gitlab-production")
	want := regexp.MustCompile(`^https://host-\d+\.example/page admin@host-\d+\.example ssh host-\d+\.example:22 gitlab-production$`)
	if !want.MatchString(out) {
		t.Errorf("out = %q", out)
	}
}

// --- Секреты ---

func TestСекретыВстроенныеФорматы(t *testing.T) {
	s := newSession(t, "")
	tests := []struct{ in, want string }{
		{"GITHUB_TOKEN=ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", `^GITHUB_TOKEN=ghp_MASKED\d{4}$`},
		{"key sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789", `^key sk-ant-api03-MASKED\d{4}$`},
		{"AWS_KEY=AKIAIOSFODNN7EXAMPLE", `^AWS_KEY=AKIAMASKED\d{4}$`},
		{"jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", `^jwt eyJ\.MASKED\d{4}$`},
	}
	for _, tt := range tests {
		out, _ := maskString(t, s, tt.in)
		if !regexp.MustCompile(tt.want).MatchString(out) {
			t.Errorf("%q → %q, ожидалось %s", tt.in, out, tt.want)
		}
	}
}

func TestСекретыЛитералВЛюбомКонтексте(t *testing.T) {
	s := newSession(t, "secret hunter2")
	out, _ := maskString(t, s, "pass: hunter2 and hunter2000")
	if out != "pass: SECRET0001 and SECRET0001000" {
		t.Errorf("out = %q", out)
	}
}

func TestСекретыPEMЦеликом(t *testing.T) {
	s := newSession(t, "")
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHt5dS1v\nabc==\n-----END RSA PRIVATE KEY-----"
	out, st := maskString(t, s, "key:\n"+pem+"\nend")
	if !regexp.MustCompile(`^key:\n-----BEGIN RSA PRIVATE KEY-----MASKED\d{4}-----END RSA PRIVATE KEY-----\nend$`).MatchString(out) {
		t.Errorf("out = %q", out)
	}
	if st.Masked["secret"] != 1 {
		t.Errorf("stats = %v (PEM и JWT-подобное тело должны дать одно совпадение)", st.Masked)
	}
}

func TestСекретыRegexСГруппойИБез(t *testing.T) {
	s := newSession(t, "regex PASSWORD (?i)password=(\\S+)\nregex EMPLOYEE \\bEMP-\\d{6}\\b")
	out, st := maskString(t, s, "password=hunter2 id EMP-004512")
	if !regexp.MustCompile(`^password=PASSWORD\d{4} id EMPLOYEE\d{4}$`).MatchString(out) {
		t.Errorf("out = %q", out)
	}
	if st.Masked["password"] != 1 || st.Masked["employee"] != 1 {
		t.Errorf("stats = %v", st.Masked)
	}
}

func TestПерекрытиеРазныхКатегорий(t *testing.T) {
	// Литерал начинается раньше хоста и накрывает его начало; остаток
	// хоста должен уйти второй проходкой.
	s := newSession(t, "secret abc db\nhost *.corp.local")
	out, _ := maskString(t, s, "abc db.corp.local")
	if strings.Contains(out, "corp.local") || strings.Contains(out, "abc db") {
		t.Errorf("out = %q", out)
	}
}

// --- Таблица ---

func TestТаблицаСтабильностьИИдемпотентность(t *testing.T) {
	s := newSession(t, "host *.corp.local")
	first, _ := maskString(t, s, "10.0.0.5 prod-db.corp.local")
	second, _ := maskString(t, s, "10.0.0.5 prod-db.corp.local")
	if first != second {
		t.Errorf("суррогаты изменились: %q → %q", first, second)
	}
	// Пользователь вставил суррогаты в промпт: они не маскируются заново.
	again, st := maskString(t, s, first)
	if again != first || len(st.Masked) != 0 {
		t.Errorf("суррогат замаскирован повторно: %q stats=%v", again, st.Masked)
	}
}

func TestТаблицаБиективность(t *testing.T) {
	s := newSession(t, "")
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		sur, err := s.surrogateFor("secret-"+string(rune('a'+i%26))+strings.Repeat("x", i%7)+strings.Repeat("y", i/26), match{category: categorySecret})
		if err != nil {
			t.Fatal(err)
		}
		if seen[sur] {
			t.Fatalf("суррогат %s выдан дважды", sur)
		}
		seen[sur] = true
	}
}

func TestТаблицаИзоляцияПоМетке(t *testing.T) {
	reg := NewRegistry(mustRules(t, "host *.corp.local"), Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	dev := reg.Session("dev-team")
	out, _ := maskString(t, dev, "prod-db.corp.local")
	analytics := reg.Session("analytics")
	got, n, err := analytics.UnmaskJSON([]byte(`{"text":"` + out + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 || !strings.Contains(string(got), out) {
		t.Errorf("суррогат чужой метки подставлен: %s", got)
	}
}

func TestDebugПишетПары(t *testing.T) {
	var logs bytes.Buffer
	reg := NewRegistry(mustRules(t, ""), Options{Debug: true, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	s := reg.Session("t")
	out, _ := maskString(t, s, "10.0.0.5")
	if _, _, err := s.UnmaskJSON([]byte(`{"a":"` + out + `"}`)); err != nil {
		t.Fatal(err)
	}
	text := logs.String()
	if !strings.Contains(text, "msg=mask") || !strings.Contains(text, "from=10.0.0.5") || !strings.Contains(text, "to="+out) {
		t.Errorf("нет записи mask: %s", text)
	}
	if !strings.Contains(text, "msg=unmask") || !strings.Contains(text, "to=10.0.0.5") {
		t.Errorf("нет записи unmask: %s", text)
	}

	logs.Reset()
	quiet := NewRegistry(mustRules(t, ""), Options{Logger: slog.New(slog.NewTextHandler(&logs, nil))}).Session("t")
	maskString(t, quiet, "10.0.0.5")
	if strings.Contains(logs.String(), "10.0.0.5") {
		t.Errorf("без Debug значение попало в лог: %s", logs.String())
	}
}

// --- JSON ---

func TestJSONОхватИСлужебныеПоля(t *testing.T) {
	s := newSession(t, "secret toolu_01")
	body := `{
	 "model":"claude-x","system":"cwd 10.0.0.5",
	 "messages":[
	  {"role":"user","content":[
	    {"type":"tool_result","tool_use_id":"toolu_01ABC","content":"host 10.0.0.5"},
	    {"type":"image","source":{"type":"base64","media_type":"image/png","data":"eyJabcdefghijklmn.eyJabcdefghijklmn.abcdefghijklmnop"}}]},
	  {"role":"assistant","content":[{"type":"tool_use","id":"toolu_01ABC","name":"Bash","input":{"command":"ping 10.0.0.5"}}]}
	 ],
	 "max_tokens":32000,"temperature":1e-7,"note":"a<b&c"
	}`
	out, st, err := s.MaskRequest([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	surs := regexp.MustCompile(`10\.\d+\.\d+\.\d+`).FindAllString(text, -1)
	if len(surs) != 3 || surs[0] != surs[1] || surs[1] != surs[2] || surs[0] == "10.0.0.5" {
		t.Errorf("адрес не заменён единым суррогатом: %v", surs)
	}
	for _, want := range []string{`"toolu_01ABC"`, `"claude-x"`, `eyJabcdefghijklmn.eyJabcdefghijklmn.abcdefghijklmnop`, `32000`, `1e-7`, `a<b&c`} {
		if !strings.Contains(text, want) {
			t.Errorf("потеряно %s в %s", want, text)
		}
	}
	if st.Masked["ip"] != 3 || st.Masked["secret"] != 0 {
		t.Errorf("stats = %v", st.Masked)
	}
}

func TestJSONThinkingНеМеняется(t *testing.T) {
	s := newSession(t, "")
	body := `{"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"dns 8.8.8.8","signature":"abc10.0.0.5"}]}]}`
	out, st, err := s.MaskRequest([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"dns 8.8.8.8"`) || !strings.Contains(string(out), `"abc10.0.0.5"`) || len(st.Masked) != 0 {
		t.Errorf("assistant-ход изменён: %s stats=%v", out, st.Masked)
	}
}

func TestJSONВозвращённоеЗначениеПеремаскируется(t *testing.T) {
	s := newSession(t, "host *.corp.local\nregex PASSWORD password=(\\S+)")
	sur, _ := maskString(t, s, "prod-db.corp.local password=hunter2")
	// Модель ответила суррогатами, шлюз вернул клиенту настоящие значения;
	// клиент присылает их в истории как ход assistant.
	unmasked, _, err := s.UnmaskJSON([]byte(`{"t":"` + sur + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unmasked), "prod-db.corp.local") || !strings.Contains(string(unmasked), "hunter2") {
		t.Fatalf("unmask = %s", unmasked)
	}
	body := `{"messages":[{"role":"assistant","content":"see prod-db.corp.local and password=hunter2, also 8.8.8.8"}]}`
	out, _, err := s.MaskRequest([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	hostSur, passSur, _ := strings.Cut(sur, " password=")
	want := "see " + hostSur + " and password=" + passSur + ", also 8.8.8.8"
	if !strings.Contains(string(out), want) {
		t.Errorf("out = %s, ожидалось %q", out, want)
	}
}

func TestJSONНевалидноеТело(t *testing.T) {
	s := newSession(t, "")
	if _, _, err := s.MaskRequest([]byte("not json")); err == nil {
		t.Error("ожидалась ошибка")
	}
	if _, _, err := s.MaskRequest([]byte(`{"a":1} {"b":2}`)); err == nil {
		t.Error("ожидалась ошибка на лишних данных")
	}
}

// --- SSE ---

func sse(events ...string) string {
	return strings.Join(events, "\n\n") + "\n\n"
}

func delta(idx int, typ, field, text string) string {
	b, _ := json.Marshal(map[string]any{"type": "content_block_delta", "index": idx, "delta": map[string]any{"type": typ, field: text}})
	return "event: content_block_delta\ndata: " + string(b)
}

func readAll(t *testing.T, st *Stream) string {
	t.Helper()
	out, err := io.ReadAll(st)
	if err != nil {
		t.Fatalf("чтение потока: %v", err)
	}
	return string(out)
}

func TestSSEToolUseВосстанавливается(t *testing.T) {
	s := newSession(t, "")
	sur, _ := maskString(t, s, "10.0.0.5")
	in := sse(delta(0, "input_json_delta", "partial_json", `{"command": "ssh admin@`+sur+`"}`),
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}")
	out := readAll(t, s.UnmaskStream(io.NopCloser(strings.NewReader(in))))
	if !strings.Contains(out, `ssh admin@10.0.0.5`) {
		t.Errorf("out = %s", out)
	}
}

func TestSSEСуррогатРазрезанМеждуСобытиями(t *testing.T) {
	s := newSession(t, "host *.corp.local")
	sur, _ := maskString(t, s, "prod-db.corp.local")
	cut := len("host-1")
	in := sse(delta(0, "text_delta", "text", "see "+sur[:cut]), delta(0, "text_delta", "text", sur[cut:]+" now"))
	st := s.UnmaskStream(io.NopCloser(strings.NewReader(in)))
	out := readAll(t, st)
	texts := deltaTexts(t, out, "text")
	if strings.Join(texts, "") != "see prod-db.corp.local now" {
		t.Errorf("texts = %q", texts)
	}
	if st.Stats().Unmasked != 1 {
		t.Errorf("unmasked = %d", st.Stats().Unmasked)
	}
}

func TestSSEРазрезВнутриIPПередЦифрой(t *testing.T) {
	s := newSession(t, "")
	sur, _ := maskString(t, s, "10.0.0.5")
	cut := len(sur) - 1
	in := sse(delta(0, "text_delta", "text", sur[:cut]), delta(0, "text_delta", "text", sur[cut:]+"0 is other"))
	out := readAll(t, s.UnmaskStream(io.NopCloser(strings.NewReader(in))))
	joined := strings.Join(deltaTexts(t, out, "text"), "")
	if joined != sur+"0 is other" {
		t.Errorf("out = %q: суррогат перед цифрой не должен подставляться", joined)
	}
}

func TestSSEХвостНаStopEOFИError(t *testing.T) {
	s := newSession(t, "host *.corp.local")
	sur, _ := maskString(t, s, "prod-db.corp.local")
	held := sur[:len("host-1")]
	cases := map[string]string{
		"stop":  sse(delta(0, "text_delta", "text", "x "+held), `event: content_block_stop`+"\n"+`data: {"type":"content_block_stop","index":0}`),
		"eof":   sse(delta(0, "text_delta", "text", "x "+held)),
		"error": sse(delta(0, "text_delta", "text", "x "+held), `event: error`+"\n"+`data: {"type":"error","error":{"type":"overloaded_error","message":"x"}}`),
		"index": sse(delta(0, "text_delta", "text", "x "+held), delta(1, "text_delta", "text", "y")),
	}
	for name, in := range cases {
		out := readAll(t, s.UnmaskStream(io.NopCloser(strings.NewReader(in))))
		if joined := strings.Join(deltaTexts(t, out, "text"), ""); !strings.HasPrefix(joined, "x "+held) {
			t.Errorf("%s: хвост потерян: %q\n%s", name, joined, out)
		}
	}
}

func TestSSEНеизвестныйСуррогатИНевалидноеСобытие(t *testing.T) {
	s := newSession(t, "")
	in := sse(delta(0, "text_delta", "text", "see host-99.example"),
		"event: ping\ndata: not json at all",
		delta(0, "text_delta", "text", "tail"))
	st := s.UnmaskStream(io.NopCloser(strings.NewReader(in)))
	out := readAll(t, st)
	if !strings.Contains(out, "host-99.example") || !strings.Contains(out, "data: not json at all\n") {
		t.Errorf("out = %s", out)
	}
	if texts := deltaTexts(t, out, "text"); len(texts) != 2 || texts[1] != "tail" {
		t.Errorf("следующие события не обработаны: %q", texts)
	}
	if st.Stats().Errors != 1 {
		t.Errorf("errors = %d", st.Stats().Errors)
	}
}

func TestSSEПервоеСобытиеДоКонцаВвода(t *testing.T) {
	s := newSession(t, "")
	pr, pw := io.Pipe()
	st := s.UnmaskStream(pr)
	go func() { _, _ = io.WriteString(pw, "event: message_start\ndata: {\"type\":\"message_start\"}\n\n") }()
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := st.Read(buf)
		got <- string(buf[:n])
	}()
	select {
	case first := <-got:
		if !strings.Contains(first, "message_start") {
			t.Errorf("first = %q", first)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("первое событие не отдано до конца потока")
	}
	_ = pw.Close()
}

func TestSSEPartialJSONЭкранируется(t *testing.T) {
	s := newSession(t, `secret he said "hi"\`)
	sur, _ := maskString(t, s, `he said "hi"\`)
	in := sse(delta(0, "input_json_delta", "partial_json", `{"text": "`+sur+`"}`))
	out := readAll(t, s.UnmaskStream(io.NopCloser(strings.NewReader(in))))
	texts := deltaTexts(t, out, "partial_json")
	var v struct{ Text string }
	if err := json.Unmarshal([]byte(strings.Join(texts, "")), &v); err != nil {
		t.Fatalf("partial_json невалиден: %v: %q", err, texts)
	}
	if v.Text != `he said "hi"\` {
		t.Errorf("text = %q", v.Text)
	}
}

// deltaTexts собирает поле field из всех дельт потока по порядку.
func deltaTexts(t *testing.T, stream, field string) []string {
	t.Helper()
	var texts []string
	for _, line := range strings.Split(stream, "\n") {
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var ev struct {
			Type  string         `json:"type"`
			Delta map[string]any `json:"delta"`
		}
		if err := json.Unmarshal([]byte(data), &ev); err != nil || ev.Type != "content_block_delta" {
			continue
		}
		if v, ok := ev.Delta[field].(string); ok {
			texts = append(texts, v)
		}
	}
	return texts
}
