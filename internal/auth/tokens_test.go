package auth

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    []Token
		wantErr bool
	}{
		{name: "пусто", spec: "", want: nil},
		{name: "только запятые", spec: " , ,", want: nil},
		{
			name: "голое значение получает метку default",
			spec: "deadbeef",
			want: []Token{{Label: DefaultLabel, Value: "deadbeef"}},
		},
		{
			name: "метки и пробелы вокруг них",
			spec: " team-a : aaa , team-b:bbb ",
			want: []Token{{Label: "team-a", Value: "aaa"}, {Label: "team-b", Value: "bbb"}},
		},
		{name: "двоеточие внутри значения", spec: "l:a:b", want: []Token{{Label: "l", Value: "a:b"}}},
		{name: "пустая метка", spec: ":aaa", wantErr: true},
		{name: "пустое значение", spec: "team-a:", wantErr: true},
		{name: "дубликат метки", spec: "a:1,a:2", wantErr: true},
		{name: "дубликат значения", spec: "a:1,b:1", wantErr: true},
		{name: "перевод строки внутри значения", spec: "a:val\rue", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Parse(%q) = %v, ожидалась ошибка", tc.spec, got.tokens)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.spec, err)
			}
			if len(got.tokens) != len(tc.want) {
				t.Fatalf("Parse(%q) дал %d токенов, ожидалось %d", tc.spec, len(got.tokens), len(tc.want))
			}
			for i, want := range tc.want {
				if got.tokens[i] != want {
					t.Errorf("токен %d: получено %+v, ожидалось %+v", i, got.tokens[i], want)
				}
			}
		})
	}
}

func TestLookup(t *testing.T) {
	s, err := Parse("team-a:aaa,team-b:bbb")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		candidate string
		wantLabel string
		wantOK    bool
	}{
		{"aaa", "team-a", true},
		{"bbb", "team-b", true},
		{"ccc", "", false},
		{"", "", false},
		{"aaaa", "", false},
		{"aa", "", false},
	}

	for _, tc := range tests {
		label, ok := s.Lookup(tc.candidate)
		if ok != tc.wantOK || label != tc.wantLabel {
			t.Errorf("Lookup(%q) = (%q, %v), ожидалось (%q, %v)",
				tc.candidate, label, ok, tc.wantLabel, tc.wantOK)
		}
	}
}

func TestLookupНаПустомНаборе(t *testing.T) {
	var s Set
	if !s.Empty() {
		t.Fatal("пустой Set не считает себя пустым")
	}
	// Пустой набор не должен пропускать даже пустое значение.
	if _, ok := s.Lookup(""); ok {
		t.Error("пустой Set пропустил пустой токен")
	}
}

func TestLabelsОтсортированы(t *testing.T) {
	s, err := Parse("zeta:1,alpha:2,mid:3")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alpha", "mid", "zeta"}
	got := s.Labels()
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Labels() = %v, ожидалось %v", got, want)
		}
	}
}

func TestGenerateДаётРазныеHexТокены(t *testing.T) {
	a, b := Generate(), Generate()
	if a == b {
		t.Fatal("два вызова Generate вернули одно значение")
	}
	if len(a) != 64 {
		t.Fatalf("длина токена %d, ожидалось 64 hex-символа", len(a))
	}
	for _, r := range a {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Fatalf("недопустимый символ %q в токене", r)
		}
	}
}
