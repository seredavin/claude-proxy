package mask

import (
	"strings"
	"testing"
)

func TestIPv6РазныеЗаписиОдинСуррогат(t *testing.T) {
	for name, s := range sessionsWithAndWithoutKey(t, "") {
		out, _ := maskString(t, s, "FD00::1 fd00::1 fd00:0::1 fd00:0000:0000:0000:0000:0000:0000:0001 2606:4700::1111 2606:4700:0::1111")
		f := strings.Fields(out)
		for i := 1; i < 4; i++ {
			if f[i] != f[0] {
				t.Errorf("%s: записи одного ULA — разные суррогаты: %q", name, out)
				break
			}
		}
		if f[4] != f[5] {
			t.Errorf("%s: записи одного публичного IPv6 — разные суррогаты: %q", name, out)
		}
		if s.Size() != 2 {
			t.Errorf("%s: записей в таблице %d, ожидалось 2", name, s.Size())
		}
		got, _, _ := s.UnmaskJSON([]byte(`{"text":"` + f[0] + `"}`))
		if !strings.Contains(string(got), `"FD00::1"`) {
			t.Errorf("%s: восстановлено не в записи первого появления: %s", name, got)
		}
	}
}

func TestMappedШестнадцатеричнаяЗаписьНеКанонизируется(t *testing.T) {
	for name, s := range sessionsWithAndWithoutKey(t, "") {
		out, _ := maskString(t, s, "::FFFF:C0A8:0105 ::ffff:c0a8:0105")
		f := strings.Fields(out)
		if !strings.HasPrefix(f[0], "::FFFF:") || !strings.HasPrefix(f[1], "::ffff:") || !strings.EqualFold(f[0], f[1]) {
			t.Errorf("%s: %q", name, out)
		}
	}
}

func TestIPv6ДругаяЗаписьНаХодуМодели(t *testing.T) {
	for name, s := range sessionsWithAndWithoutKey(t, "") {
		sur, _ := maskString(t, s, "fd00::1")
		// Модель или пользователь пишут тот же адрес иначе на ходе assistant:
		// перемаскирование идёт только по таблице и должно его узнать.
		body := `{"messages":[{"role":"assistant","content":"ping FD00:0::1"}]}`
		out, _, err := s.MaskRequest([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), "ping "+sur) {
			t.Errorf("%s: out = %s, ожидался суррогат %s", name, out, sur)
		}
	}
}
