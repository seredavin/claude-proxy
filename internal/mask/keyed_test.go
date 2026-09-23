package mask

import (
	"encoding/base64"
	"io"
	"log/slog"
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// testKey — фиксированный ключ: байты 0..31.
func testKey(t *testing.T) *Key {
	t.Helper()
	return keyFromSeed(t, 0)
}

func keyFromSeed(t *testing.T, seed byte) *Key {
	t.Helper()
	b := make([]byte, KeySize)
	for i := range b {
		b[i] = seed + byte(i)
	}
	k, err := NewKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newKeyedRegistry(t *testing.T, rulesText string, k *Key) *Registry {
	t.Helper()
	return NewRegistry(mustRules(t, rulesText), Options{Key: k, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
}

func newKeyedSession(t *testing.T, rulesText string) *Session {
	t.Helper()
	return newKeyedRegistry(t, rulesText, testKey(t)).Session("test")
}

// --- Ключ ---

func TestКлючРазбор(t *testing.T) {
	raw := make([]byte, KeySize)
	padded := base64.StdEncoding.EncodeToString(raw)
	for _, s := range []string{padded + "\n", "  " + strings.TrimRight(padded, "=") + "\r\n"} {
		if _, err := ParseKey(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	_, err := ParseKey(base64.StdEncoding.EncodeToString(make([]byte, 16)))
	if err == nil || !strings.Contains(err.Error(), "32 байт") {
		t.Errorf("16 байт: ошибка %v, ожидалась с длиной", err)
	}
	if _, err := ParseKey("не base64!"); err == nil {
		t.Error("мусор принят как ключ")
	}
}

func TestКлючФайлПрава(t *testing.T) {
	dir := t.TempDir()
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte(key+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = LoadKeyFile(path)
	if err == nil || !strings.Contains(err.Error(), "chmod 600 "+path) {
		t.Fatalf("права 644: ошибка %v, ожидалась с chmod 600 и путём", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFile(path); err != nil {
		t.Fatalf("права 600: %v", err)
	}

	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFile(bad); err == nil || !strings.Contains(err.Error(), bad) {
		t.Errorf("битый ключ: ошибка %v, ожидалась с путём", err)
	}
}

func TestКлючОтпечатокИГенерация(t *testing.T) {
	a, b := testKey(t), testKey(t)
	if a.Fingerprint() != b.Fingerprint() || !regexp.MustCompile(`^[0-9a-f]{8}$`).MatchString(a.Fingerprint()) {
		t.Errorf("отпечаток %q / %q", a.Fingerprint(), b.Fingerprint())
	}
	if a.Fingerprint() != "e232ab66" {
		t.Errorf("отпечаток фиксированного ключа изменился: %s — схема вывода подключей поменялась?", a.Fingerprint())
	}
	if keyFromSeed(t, 1).Fingerprint() == a.Fingerprint() {
		t.Error("разные ключи — одинаковый отпечаток")
	}
	k1, _ := GenerateKey()
	k2, _ := GenerateKey()
	if k1 == k2 {
		t.Error("два ключа совпали")
	}
	if _, err := ParseKey(k1); err != nil {
		t.Errorf("сгенерированный ключ не разбирается: %v", err)
	}
}

// --- Фейстель ---

func TestФейстельБиекцияМалыхДоменов(t *testing.T) {
	f := testKey(t).ip4Net
	for _, width := range []uint{8, 12, 16} {
		n := uint64(1) << width
		seen := make([]bool, n)
		for x := uint64(0); x < n; x++ {
			y := f.encrypt(x, width, 1, 42)
			if y >= n {
				t.Fatalf("width %d: %d → %d вне домена", width, x, y)
			}
			if seen[y] {
				t.Fatalf("width %d: %d выдан дважды", width, y)
			}
			seen[y] = true
			if back := f.decrypt(y, width, 1, 42); back != x {
				t.Fatalf("width %d: %d → %d → %d", width, x, y, back)
			}
		}
	}
}

func TestФейстельОбратимостьШирокихДоменов(t *testing.T) {
	f := testKey(t).ip6Host
	rnd := rand.New(rand.NewSource(1))
	for _, width := range []uint{56, 64} {
		for i := 0; i < 10000; i++ {
			x := rnd.Uint64() & mask64(width)
			y := f.encrypt(x, width, 2, uint64(i))
			if y&^mask64(width) != 0 {
				t.Fatalf("width %d: выход за домен", width)
			}
			if back := f.decrypt(y, width, 2, uint64(i)); back != x {
				t.Fatalf("width %d: %x → %x → %x", width, x, y, back)
			}
		}
	}
}

func TestФейстельТвикИДиапазон(t *testing.T) {
	f := testKey(t).ip4Host
	same := 0
	for x := uint64(0); x < 256; x++ {
		if f.encrypt(x, 8, 1, 1) == f.encrypt(x, 8, 1, 2) {
			same++
		}
	}
	if same > 16 {
		t.Errorf("твики 1 и 2 дали почти одну перестановку: %d совпадений", same)
	}
	seen := map[uint64]bool{}
	for x := uint64(0); x < 256; x++ {
		y := f.encryptRange(x, 8, 1, 254, 1, 7)
		if (x == 0 || x == 255) && y != x {
			t.Errorf("неподвижная точка %d → %d", x, y)
		}
		if x >= 1 && x <= 254 && (y < 1 || y > 254) {
			t.Errorf("%d → %d вне 1..254", x, y)
		}
		if seen[y] {
			t.Fatalf("%d выдан дважды", y)
		}
		seen[y] = true
		if back := f.decryptRange(y, 8, 1, 254, 1, 7); back != x {
			t.Errorf("%d → %d → %d", x, y, back)
		}
	}
}

// --- Суррогаты по ключу ---

func TestКлючПриватныеIPКлассИПодсеть(t *testing.T) {
	k := testKey(t)
	for _, tc := range []struct{ a, b, class string }{
		{"10.20.30.40", "10.20.30.41", "10.0.0.0/8"},
		{"172.20.1.5", "172.20.1.6", "172.16.0.0/12"},
		{"192.168.1.10", "192.168.1.11", "192.168.0.0/16"},
		{"fd12:3456:789a:1::5", "fd12:3456:789a:1::6", "fd00::/8"},
		{"fc00:1::5", "fc00:1::6", "fc00::/8"},
	} {
		s := newKeyedRegistry(t, "", k).Session("t")
		sa, err := s.surrogateFor(tc.a, match{category: categoryIP})
		if err != nil {
			t.Fatal(err)
		}
		sb, _ := s.surrogateFor(tc.b, match{category: categoryIP})
		pa, pb := netip.MustParseAddr(sa), netip.MustParseAddr(sb)
		class := netip.MustParsePrefix(tc.class)
		if !class.Contains(pa) || !class.Contains(pb) {
			t.Errorf("%s → %s, %s → %s: вне %s", tc.a, sa, tc.b, sb, tc.class)
		}
		bits := 24
		if pa.Is6() {
			bits = 64
		}
		na, _ := pa.Prefix(bits)
		nb, _ := pb.Prefix(bits)
		if na != nb || sa == sb {
			t.Errorf("%s → %s, %s → %s: ожидалась одна подсеть и разные хосты", tc.a, sa, tc.b, sb)
		}
		for _, pair := range [][2]string{{tc.a, sa}, {tc.b, sb}} {
			if got, err := k.RevealIP(pair[1]); err != nil || got != pair[0] {
				t.Errorf("RevealIP(%s) = %s, %v; ожидалось %s", pair[1], got, err, pair[0])
			}
		}
	}
}

func TestКлючАдресСетиОстаётся(t *testing.T) {
	s := newKeyedSession(t, "")
	out, _ := maskString(t, s, "10.0.0.0/24 и 10.0.0.255")
	m := regexp.MustCompile(`^10\.\d+\.\d+\.0/24 и 10\.\d+\.\d+\.255$`)
	if !m.MatchString(out) {
		t.Errorf("out = %q", out)
	}
}

func TestКлючЗолотыеСуррогаты(t *testing.T) {
	s := newKeyedSession(t, "host *.corp.local")
	out, _ := maskString(t, s, "10.20.30.40 prod-db.corp.local 93.184.216.34")
	// Смена этих значений значит, что схема суррогатов поменялась, и
	// суррогаты разошлись с уже выданными: такое допустимо только со
	// сменой версии в keyContext.
	want := "10.19.199.83 host-bte3kez2gqtzbeggvia5car5f7su4kof.example 100.75.250.22"
	if out != want {
		t.Errorf("out  = %q\nwant = %q", out, want)
	}
}

func TestКлючПубличныеIP(t *testing.T) {
	s := newKeyedSession(t, "")
	out, _ := maskString(t, s, "93.184.216.34 93.184.216.35 2606:4700::1111")
	f := strings.Fields(out)
	a, b, c := netip.MustParseAddr(f[0]), netip.MustParseAddr(f[1]), netip.MustParseAddr(f[2])
	shared := netip.MustParsePrefix("100.64.0.0/10")
	if !shared.Contains(a) || !shared.Contains(b) {
		t.Errorf("публичные IPv4 вне 100.64/10: %s", out)
	}
	na, _ := a.Prefix(24)
	nb, _ := b.Prefix(24)
	if na != nb || a == b {
		t.Errorf("ожидалась одна /24 и разные хосты: %s", out)
	}
	if !netip.MustParsePrefix("2001:db8::/32").Contains(c) {
		t.Errorf("публичный IPv6 вне 2001:db8::/32: %s", out)
	}
	if _, err := testKey(t).RevealIP(f[0]); err == nil {
		t.Error("публичный суррогат не должен восстанавливаться ключом")
	}
}

func TestКлючКоллизияПубличныхСетей(t *testing.T) {
	k := testKey(t)
	// Ищем две реальные /24, у которых первая проба совпадает.
	first := map[netip.Prefix]netip.Prefix{}
	var x, y netip.Prefix
	for i := 0; ; i++ {
		real := netip.PrefixFrom(netip.AddrFrom4([4]byte{8, byte(i >> 8), byte(i), 0}), 24)
		sur := k.publicNet(real, 0)
		if prev, ok := first[sur]; ok {
			x, y = prev, real
			break
		}
		first[sur] = real
	}
	s := newKeyedRegistry(t, "", k).Session("t")
	seen := map[string]bool{}
	for _, real := range []netip.Prefix{x, y} {
		for h := 1; h <= 254; h++ {
			b := real.Addr().As4()
			b[3] = byte(h)
			sur, err := s.surrogateFor(netip.AddrFrom4(b).String(), match{category: categoryIP})
			if err != nil {
				t.Fatal(err)
			}
			if seen[sur] {
				t.Fatalf("суррогат %s выдан дважды", sur)
			}
			seen[sur] = true
		}
	}
	if s.nets[x] == s.nets[y] {
		t.Errorf("сети %s и %s получили одну суррогатную %s", x, y, s.nets[x])
	}
}

func TestКлючХосты(t *testing.T) {
	k := testKey(t)
	s := newKeyedRegistry(t, "host *.corp.local", k).Session("t")
	out, _ := maskString(t, s, "Corp.Local corp.local Prod-DB.corp.local")
	f := strings.Fields(out)
	if f[0] != f[1] {
		t.Errorf("регистр изменил суррогат: %s", out)
	}
	if got, err := k.RevealHost(f[2]); err != nil || got != "prod-db.corp.local" {
		t.Errorf("RevealHost = %q, %v", got, err)
	}
	if _, err := keyFromSeed(t, 9).RevealHost(f[2]); err == nil || !strings.Contains(err.Error(), "не сходится") {
		t.Errorf("чужой ключ: ошибка %v, ожидалась ошибка подписи", err)
	}
}

var dnsName = regexp.MustCompile(`^[a-z0-9-]+(?:\.[a-z0-9-]+)*$`)

func TestКлючДлинныеХосты(t *testing.T) {
	k := testKey(t)
	name := "very-long-service-name.region-1.prod.corp.local"
	for i := 0; i < 3; i++ {
		name = "segment-" + name
	}
	for _, n := range []string{"very-long-service-name.region-1.prod.corp.local", name} {
		sur, err := k.maskHost(n)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(sur, "host-") || !strings.HasSuffix(sur, ".example") || !dnsName.MatchString(sur) || len(sur) > 253 {
			t.Errorf("%q → %q: не DNS-имя", n, sur)
		}
		for _, label := range strings.Split(sur, ".") {
			if len(label) > 63 {
				t.Errorf("метка %q длиннее 63", label)
			}
		}
		if got, _ := k.RevealHost(sur); got != n {
			t.Errorf("RevealHost = %q, ожидалось %q", got, n)
		}
	}
	long := strings.Repeat("a.", 120) + "local"
	if _, err := k.maskHost(long); err != errHostUnkeyable {
		t.Errorf("имя %d символов: %v, ожидался отказ", len(long), err)
	}
	// Сессия на слишком длинном имени откатывается к host-N.example.
	s := newKeyedSession(t, "")
	sur, err := s.surrogateFor(long, match{category: categoryHost})
	if err != nil || !regexp.MustCompile(`^host-\d+\.example$`).MatchString(sur) {
		t.Errorf("откат: %q, %v", sur, err)
	}
}

// --- Сессия с ключом ---

func TestКлючДваПроцессаОдинСуррогат(t *testing.T) {
	text := "10.0.0.5 prod-db.corp.local 8.8.8.8 fd00::1"
	a, _ := maskString(t, newKeyedRegistry(t, "host *.corp.local", testKey(t)).Session("dev-team"), text)
	b, _ := maskString(t, newKeyedRegistry(t, "host *.corp.local", testKey(t)).Session("analytics"), text)
	if a != b {
		t.Errorf("перезапуск или другая метка изменили суррогаты:\n%s\n%s", a, b)
	}
	c, _ := maskString(t, newKeyedRegistry(t, "host *.corp.local", keyFromSeed(t, 5)).Session("dev-team"), text)
	if c == a {
		t.Error("другой ключ дал те же суррогаты")
	}
}

func TestКлючИзоляцияПоМеткеСохраняется(t *testing.T) {
	reg := newKeyedRegistry(t, "host *.corp.local", testKey(t))
	out, _ := maskString(t, reg.Session("dev-team"), "prod-db.corp.local")
	got, n, err := reg.Session("analytics").UnmaskJSON([]byte(`{"text":"` + out + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 || !strings.Contains(string(got), out) {
		t.Errorf("суррогат чужой метки подставлен: %s", got)
	}
	got, n, _ = reg.Session("dev-team").UnmaskJSON([]byte(`{"text":"` + out + `"}`))
	if n != 1 || !strings.Contains(string(got), "prod-db.corp.local") {
		t.Errorf("своя метка не демаскирует: %s", got)
	}
}

func TestКлючПридуманныйАдресНеРасшифровывается(t *testing.T) {
	s := newKeyedSession(t, "")
	maskString(t, s, "10.0.0.5")
	got, n, err := s.UnmaskJSON([]byte(`{"text":"10.99.99.99"}`))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 || !strings.Contains(string(got), "10.99.99.99") {
		t.Errorf("адрес не из таблицы изменён: %s", got)
	}
}

func TestКлючРазныеЗаписиОдногоIPv6(t *testing.T) {
	s := newKeyedSession(t, "")
	out, _ := maskString(t, s, "fd00::1 fd00:0::1")
	f := strings.Fields(out)
	if f[0] != f[1] {
		t.Errorf("одна сущность — разные суррогаты: %s", out)
	}
	got, _, _ := s.UnmaskJSON([]byte(`{"text":"` + f[0] + `"}`))
	if !strings.Contains(string(got), "fd00::1") {
		t.Errorf("обратная подстановка: %s", got)
	}
}

func TestКлючSSEХостРазрезанМеждуСобытиями(t *testing.T) {
	s := newKeyedSession(t, "host *.corp.local")
	sur, _ := maskString(t, s, "prod-db.corp.local")
	cut := len(sur) / 2
	in := sse(delta(0, "text_delta", "text", "see "+sur[:cut]), delta(0, "text_delta", "text", sur[cut:]+" now"))
	st := s.UnmaskStream(io.NopCloser(strings.NewReader(in)))
	out := readAll(t, st)
	if joined := strings.Join(deltaTexts(t, out, "text"), ""); joined != "see prod-db.corp.local now" {
		t.Errorf("texts = %q", joined)
	}
}
