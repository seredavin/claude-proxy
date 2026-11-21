package responses

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/seredavin/claude-proxy/internal/config"
)

const Path = "/v1/responses"

func nativeError(req *http.Request, status int, kind, message string) *http.Response {
	return jsonResponse(req, status, object{"error": object{"type": kind, "message": message}})
}

func nativeRequest(body []byte, target *config.OpenAITarget) ([]byte, error) {
	var request map[string]json.RawMessage
	if err := json.Unmarshal(body, &request); err != nil || request == nil {
		return nil, fmt.Errorf("ожидается объект Responses API")
	}
	var alias string
	if err := json.Unmarshal(request["model"], &alias); err != nil || alias == "" {
		return nil, fmt.Errorf("укажите модель")
	}
	model, ok := target.ResolveModel(alias)
	if !ok {
		return nil, fmt.Errorf("модель не разрешена для этого маршрута")
	}
	if string(request["stream"]) != "true" {
		return nil, fmt.Errorf("Responses по подписке ChatGPT требует stream: true")
	}
	for _, field := range []string{"previous_response_id", "conversation", "prompt"} {
		if value := request[field]; len(value) != 0 && string(value) != "null" {
			return nil, fmt.Errorf("%s недоступен, передайте полную историю в input", field)
		}
		delete(request, field)
	}

	var input []map[string]json.RawMessage
	if err := json.Unmarshal(request["input"], &input); err != nil || len(input) == 0 {
		var text string
		if err := json.Unmarshal(request["input"], &text); err != nil || text == "" {
			return nil, fmt.Errorf("передайте историю сообщений в input")
		}
		value, _ := json.Marshal(text)
		input = []map[string]json.RawMessage{{"role": json.RawMessage(`"user"`), "content": value}}
	}
	for _, item := range input {
		if item == nil {
			return nil, fmt.Errorf("элементы input должны быть объектами")
		}
		if string(item["role"]) == `"system"` {
			item["role"] = json.RawMessage(`"developer"`)
		}
	}
	var tools []map[string]json.RawMessage
	if value := request["tools"]; len(value) != 0 {
		if err := json.Unmarshal(value, &tools); err != nil {
			return nil, fmt.Errorf("tools должен быть массивом")
		}
	}
	var local, hosted []map[string]json.RawMessage
	for _, tool := range tools {
		switch string(tool["type"]) {
		case `"function"`, `"custom"`:
			local = append(local, tool)
		default:
			hosted = append(hosted, tool)
		}
	}
	if len(local) != 0 {
		encoded, _ := json.Marshal(local)
		input = append([]map[string]json.RawMessage{{
			"type": json.RawMessage(`"additional_tools"`), "role": json.RawMessage(`"developer"`), "tools": encoded,
		}}, input...)
	}
	delete(request, "tools")
	if len(hosted) != 0 {
		request["tools"], _ = json.Marshal(hosted)
	}
	for _, field := range []string{
		"background", "max_output_tokens", "max_tool_calls", "metadata", "moderation",
		"multi_agent", "prompt_cache_retention", "safety_identifier", "temperature",
		"top_logprobs", "top_p", "truncation", "user",
	} {
		delete(request, field)
	}
	request["model"], _ = json.Marshal(model)
	request["input"], _ = json.Marshal(input)
	request["store"] = json.RawMessage("false")
	return json.Marshal(request)
}
