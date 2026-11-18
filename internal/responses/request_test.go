package responses

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/seredavin/claude-proxy/internal/config"
)

func TestConvertToolSearchResult(t *testing.T) {
	body := `{
		"model":"gpt-test",
		"tools":[
			{"name":"ToolSearch","input_schema":{"type":"object"}},
			{"name":"First","input_schema":{"type":"object"},"defer_loading":true},
			{"name":"Second","input_schema":{"type":"object"},"defer_loading":true}
		],
		"messages":[
			{"role":"assistant","content":[{"type":"tool_use","id":"toolu_search","name":"ToolSearch","input":{"query":"tools"}}]},
			{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_search","content":[
				{"type":"tool_reference","tool_name":"First"},
				{"type":"text","text":"Another match:"},
				{"type":"tool_reference","tool_name":"Second"}
			]}]}
		]
	}`
	_, payload, err := convertRequest([]byte(body), &config.OpenAITarget{Models: []config.OpenAIModel{{Alias: "gpt-test", Model: "gpt-test"}}})
	if err != nil {
		t.Fatal(err)
	}
	var converted struct {
		Input []struct {
			Type   string
			CallID string `json:"call_id"`
			Output string
			Tools  []struct{ Name string }
		}
	}
	if err := json.Unmarshal(payload, &converted); err != nil {
		t.Fatal(err)
	}
	if len(converted.Input) != 3 {
		t.Fatalf("unexpected input: %s", payload)
	}
	var names []string
	for _, tool := range converted.Input[0].Tools {
		names = append(names, tool.Name)
	}
	if converted.Input[0].Type != "additional_tools" || !reflect.DeepEqual(names, []string{"ToolSearch", "First", "Second"}) {
		t.Fatalf("unexpected tool definitions: %+v", converted.Input[0])
	}
	if result := converted.Input[2]; result.Type != "function_call_output" || result.CallID != "toolu_search" || result.Output != "Found tool: \"First\"\nAnother match:\nFound tool: \"Second\"" {
		t.Fatalf("unexpected ToolSearch result: %+v", result)
	}
}

func TestBlockTextRejectsUnsupportedBlocks(t *testing.T) {
	for _, tc := range []struct {
		name, content, wantError string
		allowToolReferences      bool
	}{
		{"system reference", `[{"type":"tool_reference","tool_name":"First"}]`, "только текстовые", false},
		{"image result", `[{"type":"image"}]`, "только текстовые", true},
		{"reference without name", `[{"type":"tool_reference"}]`, "tool_name", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := blockText(json.RawMessage(tc.content), tc.allowToolReferences); err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("expected error containing %q, got %v", tc.wantError, err)
			}
		})
	}
}
