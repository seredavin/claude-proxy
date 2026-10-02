package mask

import (
	"encoding/json"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"testing"
)

// --- Шифрование меток ---

var tagShape = regexp.MustCompile(`^<<m:[a-z0-9]+:[a-z2-7]+>>$`)

const testPEM = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----"

func TestМеткаОбратима(t *testing.T) {
	k := testKey(t)
	cases := []struct{ category, value, want string }{
		{categoryHost, "prod-db.corp.local", "prod-db.corp.local"},
		{categoryHost, "Prod-DB.Corp.Local", "prod-db.corp.local"},
		{categorySecret, "ghp_" + strings.Repeat("a1B2", 9), "ghp_" + strings.Repeat("a1B2", 9)},
		{categorySecret, testPEM, testPEM},
		{"password", "пароль с пробелом и ✓", "пароль с пробелом и ✓"},
	}
	for _, c := range cases {
		tag := k.sealTag(c.category, c.value)
		if !tagShape.MatchString(tag) {
			t.Errorf("метка %q не в формате", tag)
		}
		if !strings.HasPrefix(tag, "<<m:"+c.category+":") {
			t.Errorf("метка %q: ожидалась категория %s", tag, c.category)
		}
		category, value, err := k.OpenTag(tag)
		if err != nil || category != c.category || value != c.want {
			t.Errorf("OpenTag(%q) = %q, %q, %v; ожидалось %q, %q", tag, category, value, err, c.category, c.want)
		}
	}
}

func TestМеткаДетерминирована(t *testing.T) {
	a, b := testKey(t), testKey(t)
	if a.sealTag(categoryHost, "db.corp.local") != b.sealTag(categoryHost, "DB.corp.local") {
		t.Error("одно имя под одним ключом дало разные метки")
	}
	if a.sealTag(categorySecret, "hunter2") == a.sealTag(categorySecret, "hunter3") {
		t.Error("разные значения дали одну метку")
	}
	if a.sealTag(categorySecret, "hunter2") == keyFromSeed(t, 9).sealTag(categorySecret, "hunter2") {
		t.Error("разные ключи дали одну метку")
	}
}

func TestМеткаЗолотая(t *testing.T) {
	// Схема не должна меняться незаметно: метки из трасс и истории
	// перестали бы расшифровываться.
	const want = "<<m:host:3lohtovthrsw4bnxtsuib5lscuh76suuhtbyogpyju>>"
	if got := testKey(t).sealTag(categoryHost, "prod-db.corp.local"); got != want {
		t.Errorf("метка = %q, ожидалось %q", got, want)
	}
}

func TestМеткаЧужойКлючИПодмена(t *testing.T) {
	k := testKey(t)
	tag := k.sealTag(categoryHost, "prod-db.corp.local")
	if _, _, err := keyFromSeed(t, 9).OpenTag(tag); err == nil || !strings.Contains(err.Error(), "не сходится") {
		t.Errorf("чужой ключ: ошибка %v", err)
	}
	swapped := strings.Replace(tag, ":host:", ":secret:", 1)
	if _, _, err := k.OpenTag(swapped); err == nil {
		t.Error("метка с подменённой категорией расшифровалась")
	}
	for _, bad := range []string{"<<m:host:abc>>", "<<m:host:>>", "<<m:host:a>>", tag + "x", "host"} {
		if _, _, err := k.OpenTag(bad); err == nil {
			t.Errorf("%q расшифровалось", bad)
		}
	}
}

func TestRevealTags(t *testing.T) {
	k := testKey(t)
	host := k.sealTag(categoryHost, "prod-db.corp.local")
	alien := keyFromSeed(t, 9).sealTag(categorySecret, "x")
	out, revealed, failed := k.RevealTags("ssh " + host + " && echo " + alien)
	if out != "ssh prod-db.corp.local && echo "+alien || revealed != 1 || failed != 1 {
		t.Errorf("RevealTags = %q, %d, %d", out, revealed, failed)
	}
}

func TestНачалоМетки(t *testing.T) {
	held := []string{"<", "<<", "<<m", "<<m:", "<<m:ho", "<<m:host:", "<<m:host:ab2", "<<m:host:ab2>"}
	for _, s := range held {
		if got := tagTail("ssh " + s); got != s {
			t.Errorf("tagTail(%q) = %q", "ssh "+s, got)
		}
	}
	for _, s := range []string{"a < b", "<<EOF", "<<m:host:ab>>", "<<m:Host:", "<<m::", "<<m:host:ab1", "<<m:host:>"} {
		if got := tagTail(s); got != "" {
			t.Errorf("tagTail(%q) = %q, ожидалось пусто", s, got)
		}
	}
	long := "<<m:secret:" + strings.Repeat("a", maxTagHold)
	if got := tagTail(long); got != "" {
		t.Errorf("хвост длиннее предела удержан (%d байт)", len(got))
	}
}

// --- Режим меток в сессии ---

func newTagSession(t *testing.T, rulesText string, k *Key) *Session {
	t.Helper()
	return NewRegistry(mustRules(t, rulesText), Options{Key: k, Tags: true, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Session("test")
}

func TestМеткиВместоСуррогатов(t *testing.T) {
	s := newTagSession(t, "host *.corp.local\nsecret hunter2\nregex PASSWORD password=(\\S+)", testKey(t))
	ghp := "ghp_" + strings.Repeat("a1B2", 9)
	in := "ssh prod-db.corp.local; token " + ghp + "; pw hunter2; password=s3cr3t; ip 10.0.0.5\n" + testPEM
	out, st := maskString(t, s, in)
	for _, leak := range []string{"prod-db", "corp.local", ".example", "ghp_", "MASKED", "hunter2", "s3cr3t", "BEGIN", "END", "10.0.0.5"} {
		if strings.Contains(out, leak) {
			t.Errorf("в запросе осталось %q: %s", leak, out)
		}
	}
	tags := tagPattern.FindAllString(out, -1)
	if len(tags) != 5 {
		t.Fatalf("меток %d, ожидалось 5: %s", len(tags), out)
	}
	for _, prefix := range []string{"ssh <<m:host:", "token <<m:secret:", "pw <<m:secret:", "password=<<m:password:"} {
		if !strings.Contains(out, prefix) {
			t.Errorf("нет %q: %s", prefix, out)
		}
	}
	if !strings.HasSuffix(out, "\n<<m:secret:"+strings.TrimPrefix(tags[4], "<<m:secret:")) {
		t.Errorf("PEM не заменён одной меткой: %s", out)
	}
	if !regexp.MustCompile(`ip 10\.\d+\.\d+\.\d+`).MatchString(out) {
		t.Errorf("IP не суррогат по ключу: %s", out)
	}
	if st.Masked["host"] != 1 || st.Masked["secret"] != 3 || st.Masked["password"] != 1 || st.Masked["ip"] != 1 {
		t.Errorf("счётчики %v", st.Masked)
	}
}

func TestМеткиБезРежимаПрежние(t *testing.T) {
	s := newKeyedSession(t, "host *.corp.local")
	out, _ := maskString(t, s, "prod-db.corp.local ghp_"+strings.Repeat("a1B2", 9))
	if strings.Contains(out, "<<m:") || !strings.Contains(out, ".example") || !strings.Contains(out, "ghp_MASKED") {
		t.Errorf("без режима меток вид суррогатов изменился: %s", out)
	}
	// Без ключа флаг не действует.
	s = NewRegistry(mustRules(t, ""), Options{Tags: true, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Session("x")
	if out, _ := maskString(t, s, "db.corp.local"); strings.Contains(out, "<<m:") {
		t.Errorf("метка без ключа: %s", out)
	}
}

func TestМеткиОдинаковыВПроцессах(t *testing.T) {
	a := newTagSession(t, "", testKey(t))
	b := newTagSession(t, "", testKey(t))
	x, _ := maskString(t, a, "Prod-DB.corp.local")
	y, _ := maskString(t, b, "prod-db.corp.local")
	if x != y {
		t.Errorf("%q != %q", x, y)
	}
}

func TestМеткиОтветJSONИЧужиеМетки(t *testing.T) {
	k := testKey(t)
	issued := newTagSession(t, "", k)
	tag, _ := maskString(t, issued, "prod-db.corp.local")
	// Другой процесс с тем же ключом: в его таблице метки нет.
	s := newTagSession(t, "", k)
	alien := keyFromSeed(t, 9).sealTag(categoryHost, "x.corp.local")
	body, _ := json.Marshal(map[string]string{"t": "ssh " + tag + " " + alien + " <<m:host:abc>>"})
	out, n, err := s.UnmaskJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	var v struct{ T string }
	_ = json.Unmarshal(out, &v)
	if v.T != "ssh prod-db.corp.local "+alien+" <<m:host:abc>>" || n != 1 {
		t.Errorf("unmask = %q, n=%d", v.T, n)
	}
	// Ход модели с раскрытым значением перемаскируется в ту же метку.
	again, _, err := s.MaskRequest([]byte(`{"messages":[{"role":"assistant","content":"see prod-db.corp.local"}]}`))
	if err != nil || !strings.Contains(string(again), "see "+tag) {
		t.Errorf("ход модели = %s, %v", again, err)
	}
}

func TestМеткиSSEРазрезВЛюбомМесте(t *testing.T) {
	k := testKey(t)
	tag := k.sealTag(categoryHost, "prod-db.corp.local")
	for cut := 1; cut < len(tag); cut++ {
		// Сессия без таблицы: метка выдана другим процессом.
		s := newTagSession(t, "", k)
		in := sse(delta(0, "text_delta", "text", "see "+tag[:cut]), delta(0, "text_delta", "text", tag[cut:]+" now"))
		out := readAll(t, s.UnmaskStream(io.NopCloser(strings.NewReader(in))))
		if joined := strings.Join(deltaTexts(t, out, "text"), ""); joined != "see prod-db.corp.local now" {
			t.Fatalf("разрез %d: %q", cut, joined)
		}
	}
}

func TestМеткиSSEPartialJSONИХвост(t *testing.T) {
	k := testKey(t)
	s := newTagSession(t, "", k)
	tag := k.sealTag(categorySecret, `he said "hi"\`)
	in := sse(delta(0, "input_json_delta", "partial_json", `{"text": "`+tag[:7]), delta(0, "input_json_delta", "partial_json", tag[7:]+`"}`))
	out := readAll(t, s.UnmaskStream(io.NopCloser(strings.NewReader(in))))
	var v struct{ Text string }
	if err := json.Unmarshal([]byte(strings.Join(deltaTexts(t, out, "partial_json"), "")), &v); err != nil || v.Text != `he said "hi"\` {
		t.Errorf("partial_json: %q, %v", v.Text, err)
	}
	// Незакрытое начало метки отдаётся на конце блока.
	in = sse(delta(0, "text_delta", "text", "cat <<EOF and <<m:ho"), "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}")
	out = readAll(t, s.UnmaskStream(io.NopCloser(strings.NewReader(in))))
	if joined := strings.Join(deltaTexts(t, out, "text"), ""); joined != "cat <<EOF and <<m:ho" {
		t.Errorf("хвост: %q", joined)
	}
}

func TestМеткиНеТрогаютсяДетекторами(t *testing.T) {
	k := testKey(t)
	tag := k.sealTag(categoryHost, "prod-db.corp.local")
	token := tag[len("<<m:host:") : len(tag)-2]
	lit := token[3:9]
	s := newTagSession(t, "secret "+lit+"\nregex TOK ("+token[10:16]+")", k)
	out, st := maskString(t, s, "see "+tag+" and "+lit)
	if !strings.HasPrefix(out, "see "+tag+" and <<m:secret:") || len(st.Masked) != 1 {
		t.Errorf("метка тронута: %s %v", out, st.Masked)
	}
}
