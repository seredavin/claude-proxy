package mask

import (
	"net/netip"
	"regexp"
	"strings"
	"testing"
)

// sessionsWithAndWithoutKey — одна и та же проверка должна держаться и со
// случайными суррогатами, и с суррогатами по ключу.
func sessionsWithAndWithoutKey(t *testing.T, rules string) map[string]*Session {
	return map[string]*Session{"без ключа": newSession(t, rules), "с ключом": newKeyedSession(t, rules)}
}

func TestMappedТочечнаяЗаписьСогласованаИБезУтечки(t *testing.T) {
	for name, s := range sessionsWithAndWithoutKey(t, "") {
		out, _ := maskString(t, s, "10.0.0.1 [::ffff:10.0.0.1]:22")
		f := strings.Fields(out)
		want := "[::ffff:" + f[0] + "]:22"
		if f[1] != want {
			t.Errorf("%s: %q, ожидалось %q", name, out, want)
		}
		if !netip.MustParsePrefix("10.0.0.0/8").Contains(netip.MustParseAddr(f[0])) {
			t.Errorf("%s: суррогат %s вне 10/8", name, f[0])
		}
		if strings.Contains(out, "10.0.0.1") {
			t.Errorf("%s: исходный адрес в запросе: %q", name, out)
		}
		got, _, _ := s.UnmaskJSON([]byte(`{"text":"` + f[1] + `"}`))
		if !strings.Contains(string(got), "[::ffff:10.0.0.1]:22") {
			t.Errorf("%s: обратная подстановка: %s", name, got)
		}
	}
}

func TestMappedТолькоВMappedЗаписи(t *testing.T) {
	for name, s := range sessionsWithAndWithoutKey(t, "") {
		out, _ := maskString(t, s, "ssh ::ffff:192.168.1.5")
		if !regexp.MustCompile(`^ssh ::ffff:192\.168\.\d+\.\d+$`).MatchString(out) || strings.HasSuffix(out, "168.1.5") {
			t.Errorf("%s: %q", name, out)
		}
	}
}

func TestMappedШестнадцатеричнаяЗапись(t *testing.T) {
	for name, s := range sessionsWithAndWithoutKey(t, "") {
		out, _ := maskString(t, s, "::ffff:c0a8:0105")
		m := regexp.MustCompile(`^::ffff:([0-9a-f]{4}):([0-9a-f]{4})$`).FindStringSubmatch(out)
		if m == nil || out == "::ffff:c0a8:0105" {
			t.Fatalf("%s: %q", name, out)
		}
		inner := netip.MustParseAddr(out).Unmap()
		if !netip.MustParsePrefix("192.168.0.0/16").Contains(inner) {
			t.Errorf("%s: вложенный %s вне 192.168/16", name, inner)
		}
		// Тот же IPv4 в обычной записи — тот же вложенный суррогат.
		plain, _ := maskString(t, s, "192.168.1.5")
		if plain != inner.String() {
			t.Errorf("%s: 192.168.1.5 → %s, а в mapped — %s", name, plain, inner)
		}
		got, _, _ := s.UnmaskJSON([]byte(`{"text":"` + out + `"}`))
		if !strings.Contains(string(got), "::ffff:c0a8:0105") {
			t.Errorf("%s: обратная подстановка: %s", name, got)
		}
	}
}

func TestMappedLoopbackИIPPrivate(t *testing.T) {
	for name, s := range sessionsWithAndWithoutKey(t, "ip private") {
		out, _ := maskString(t, s, "::ffff:127.0.0.1 ::ffff:8.8.8.8 ::ffff:192.168.1.5 ::ffff:7f00:1")
		f := strings.Fields(out)
		if f[0] != "::ffff:127.0.0.1" || f[1] != "::ffff:8.8.8.8" || f[3] != "::ffff:7f00:1" {
			t.Errorf("%s: loopback или публичный тронут: %q", name, out)
		}
		if f[2] == "::ffff:192.168.1.5" {
			t.Errorf("%s: приватный mapped не замаскирован: %q", name, out)
		}
	}
	// С ip all mapped loopback тоже не трогается.
	s := newSession(t, "")
	if out, _ := maskString(t, s, "::ffff:127.0.0.1"); out != "::ffff:127.0.0.1" {
		t.Errorf("mapped loopback замаскирован: %q", out)
	}
}

func TestNAT64ИCompatibleЦеликом(t *testing.T) {
	octets := regexp.MustCompile(`\d+\.\d+`)
	for name, s := range sessionsWithAndWithoutKey(t, "") {
		for _, in := range []string{"64:ff9b::10.0.0.1", "::10.0.0.1"} {
			out, st := maskString(t, s, in)
			a, err := netip.ParseAddr(out)
			if err != nil || !a.Is6() || a.Is4In6() || octets.MatchString(out) || st.Masked[categoryIP] != 1 {
				t.Errorf("%s: %q → %q %v", name, in, out, st.Masked)
			}
		}
	}
}
