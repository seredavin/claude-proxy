package mask

import (
	"encoding/json"
	"io"
	"log/slog"
	"reflect"
	"testing"
)

func maskBody(t *testing.T, s *Session, body string) map[string]any {
	t.Helper()
	out, _, err := s.MaskRequest([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestИнструкцияОМетках(t *testing.T) {
	s := newTagSession(t, "", testKey(t))
	hint := map[string]any{"type": "text", "text": tagsHint}
	cases := []struct {
		name, body string
		want       any
	}{
		{"массив", `{"system":[{"type":"text","text":"a"},{"type":"text","text":"b","cache_control":{"type":"ephemeral"}}],"messages":[]}`,
			[]any{
				map[string]any{"type": "text", "text": "a"},
				map[string]any{"type": "text", "text": "b", "cache_control": map[string]any{"type": "ephemeral"}},
				hint,
			}},
		{"строка", `{"system":"a","messages":[]}`, "a\n\n" + tagsHint},
		{"без system", `{"messages":[]}`, []any{hint}},
	}
	for _, c := range cases {
		got := maskBody(t, s, c.body)["system"]
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: system = %#v", c.name, got)
		}
		// Второе звено цепочки не добавляет инструкцию повторно.
		again, _ := json.Marshal(map[string]any{"system": got, "messages": []any{}})
		if second := maskBody(t, s, string(again))["system"]; !reflect.DeepEqual(second, c.want) {
			t.Errorf("%s: повторный проход: system = %#v", c.name, second)
		}
	}
	// Тело без messages (не Messages API) не меняется.
	if v := maskBody(t, s, `{"x":1}`); v["system"] != nil {
		t.Errorf("инструкция в теле без messages: %v", v)
	}
}

func TestИнструкцияТолькоВРежимеМеток(t *testing.T) {
	for _, s := range []*Session{
		newKeyedSession(t, ""),
		NewRegistry(mustRules(t, ""), Options{Tags: true, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Session("x"),
	} {
		if v := maskBody(t, s, `{"system":"a","messages":[]}`); v["system"] != "a" {
			t.Errorf("system изменён вне режима меток: %v", v["system"])
		}
	}
}
