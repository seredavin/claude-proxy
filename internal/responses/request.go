// Package responses адаптирует Anthropic Messages для OpenAI Responses API.
package responses

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/seredavin/claude-proxy/internal/config"
)

type messageRequest struct {
	Model    string          `json:"model"`
	Stream   bool            `json:"stream"`
	System   json.RawMessage `json:"system"`
	Messages []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	} `json:"messages"`
	Tools []struct {
		Type        string          `json:"type"`
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Schema      json.RawMessage `json:"input_schema"`
	} `json:"tools"`
	ToolChoice struct {
		Type            string `json:"type"`
		Name            string `json:"name"`
		DisableParallel bool   `json:"disable_parallel_tool_use"`
	} `json:"tool_choice"`
}

type block struct {
	Type      string          `json:"type"`
	Text      string          `json:"text"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
	ToolName  string          `json:"tool_name"`
	Content   json.RawMessage `json:"content"`
	IsError   bool            `json:"is_error"`
}

type object = map[string]any

func contentBlocks(raw json.RawMessage) ([]block, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return []block{{Type: "text", Text: text}}, nil
	}
	var blocks []block
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return nil, fmt.Errorf("ожидается текст или список блоков")
	}
	return blocks, nil
}

func blockText(raw json.RawMessage, allowToolReferences bool) (string, error) {
	blocks, err := contentBlocks(raw)
	if err != nil {
		return "", err
	}
	var lines []string
	for _, b := range blocks {
		switch {
		case b.Type == "text":
			lines = append(lines, b.Text)
		case allowToolReferences && b.Type == "tool_reference":
			if strings.TrimSpace(b.ToolName) == "" {
				return "", fmt.Errorf("в блоке tool_reference отсутствует tool_name")
			}
			// Схемы найденных инструментов передаются отдельно из tools.
			lines = append(lines, fmt.Sprintf("Found tool: %q", b.ToolName))
		default:
			return "", fmt.Errorf("поддерживаются только текстовые блоки")
		}
	}
	return strings.Join(lines, "\n"), nil
}

func convertRequest(body []byte, target *config.OpenAITarget) (messageRequest, []byte, error) {
	var client messageRequest
	if err := json.Unmarshal(body, &client); err != nil || len(client.Messages) == 0 || client.Model == "" {
		return client, nil, fmt.Errorf("ожидается запрос Anthropic Messages с моделью и сообщениями")
	}
	model, ok := target.ResolveModel(client.Model)
	if !ok {
		return client, nil, fmt.Errorf("модель не разрешена для этого маршрута, используйте /v1/models")
	}
	instructions, err := blockText(client.System, false)
	if err != nil {
		return client, nil, err
	}
	items := make([]object, 0, len(client.Messages))
	for _, msg := range client.Messages {
		// Claude Code может добавлять системные инструкции в историю.
		if msg.Role == "system" {
			text, err := blockText(msg.Content, false)
			if err != nil {
				return client, nil, err
			}
			items = append(items, object{"type": "message", "role": "developer", "content": text})
			continue
		}
		if msg.Role != "user" && msg.Role != "assistant" {
			return client, nil, fmt.Errorf("неподдерживаемая роль в истории сообщений")
		}
		blocks, err := contentBlocks(msg.Content)
		if err != nil {
			return client, nil, err
		}
		var texts []object
		flush := func() {
			if len(texts) != 0 {
				items = append(items, object{"type": "message", "role": msg.Role, "content": texts})
				texts = nil
			}
		}
		for _, b := range blocks {
			switch b.Type {
			case "text":
				typ := "input_text"
				if msg.Role == "assistant" {
					typ = "output_text"
				}
				item := object{"type": typ, "text": b.Text}
				if typ == "output_text" {
					item["annotations"] = []any{}
				}
				texts = append(texts, item)
			case "tool_use":
				if msg.Role != "assistant" || b.ID == "" || b.Name == "" || len(b.Input) == 0 || b.Input[0] != '{' {
					return client, nil, fmt.Errorf("некорректный блок tool_use")
				}
				flush()
				items = append(items, object{"type": "function_call", "call_id": b.ID, "name": b.Name, "arguments": string(b.Input)})
			case "tool_result":
				if msg.Role != "user" || b.ToolUseID == "" {
					return client, nil, fmt.Errorf("некорректный блок tool_result")
				}
				output, err := blockText(b.Content, true)
				if err != nil {
					return client, nil, err
				}
				if b.IsError {
					output = "Tool execution failed:\n" + output
				}
				flush()
				items = append(items, object{"type": "function_call_output", "call_id": b.ToolUseID, "output": output})
			default:
				return client, nil, fmt.Errorf("неподдерживаемый блок Anthropic Messages")
			}
		}
		flush()
	}
	if len(items) == 0 {
		return client, nil, fmt.Errorf("история сообщений пуста")
	}

	request := object{"model": model, "input": items, "instructions": instructions, "stream": true, "store": false}
	if len(client.Tools) != 0 {
		tools := make([]object, 0, len(client.Tools))
		for _, tool := range client.Tools {
			if (tool.Type != "" && tool.Type != "custom") || tool.Name == "" || len(tool.Schema) == 0 || tool.Schema[0] != '{' {
				return client, nil, fmt.Errorf("поддерживаются только локальные инструменты с JSON-схемой")
			}
			tools = append(tools, object{"type": "function", "name": tool.Name, "description": tool.Description, "parameters": tool.Schema, "strict": false})
		}
		request["input"] = append([]object{{"type": "additional_tools", "role": "developer", "tools": tools}}, items...)
	}
	switch client.ToolChoice.Type {
	case "", "auto":
	case "any":
		request["tool_choice"] = "required"
	case "none":
		request["tool_choice"] = "none"
	case "tool":
		request["tool_choice"] = object{"type": "function", "name": client.ToolChoice.Name}
	default:
		return client, nil, fmt.Errorf("неподдерживаемый режим выбора инструмента")
	}
	if client.ToolChoice.DisableParallel {
		request["parallel_tool_calls"] = false
	}
	payload, err := json.Marshal(request)
	return client, payload, err
}
