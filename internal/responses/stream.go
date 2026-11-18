package responses

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

type outputItem struct {
	Type      string       `json:"type"`
	CallID    string       `json:"call_id"`
	Name      string       `json:"name"`
	Arguments string       `json:"arguments"`
	Content   []outputPart `json:"content"`
}

type outputPart struct {
	Type    string `json:"type"`
	Text    string `json:"text"`
	Refusal string `json:"refusal"`
}

type apiError struct {
	Code string `json:"code"`
}

type responseData struct {
	ID     string       `json:"id"`
	Output []outputItem `json:"output"`
	Error  apiError     `json:"error"`
	Usage  struct {
		Input  int `json:"input_tokens"`
		Output int `json:"output_tokens"`
		Cached struct {
			Tokens int `json:"cached_tokens"`
		} `json:"input_tokens_details"`
	} `json:"usage"`
	Incomplete struct {
		Reason string `json:"reason"`
	} `json:"incomplete_details"`
}

type event struct {
	Type         string       `json:"type"`
	Delta        string       `json:"delta"`
	OutputIndex  int          `json:"output_index"`
	ContentIndex int          `json:"content_index"`
	Item         outputItem   `json:"item"`
	Part         outputPart   `json:"part"`
	Response     responseData `json:"response"`
	Code         string       `json:"code"`
}

func consumeEvents(r io.Reader, handle func(event) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 32<<10), 16<<20)
	var data bytes.Buffer
	for scanner.Scan() {
		line := scanner.Bytes()
		if value, ok := bytes.CutPrefix(line, []byte("data:")); ok {
			if data.Len()+len(value) > 16<<20 {
				return errors.New("слишком большое событие OpenAI")
			}
			data.Write(bytes.TrimPrefix(value, []byte(" ")))
			data.WriteByte('\n')
			continue
		}
		if len(line) != 0 || data.Len() == 0 {
			continue
		}
		var evt event
		if err := json.Unmarshal(data.Bytes(), &evt); err != nil {
			return errors.New("некорректное событие OpenAI")
		}
		data.Reset()
		if err := handle(evt); err != nil {
			return err
		}
		if evt.Type == "response.completed" || evt.Type == "response.incomplete" {
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return io.ErrUnexpectedEOF
}

func (r responseData) usage() object {
	return object{
		"input_tokens":            max(r.Usage.Input-r.Usage.Cached.Tokens, 0),
		"cache_read_input_tokens": r.Usage.Cached.Tokens,
		"output_tokens":           r.Usage.Output,
	}
}

func (r responseData) stopReason() string {
	for _, item := range r.Output {
		if item.Type == "function_call" {
			return "tool_use"
		}
	}
	if r.Incomplete.Reason == "max_output_tokens" {
		return "max_tokens"
	}
	if r.Incomplete.Reason == "content_filter" {
		return "refusal"
	}
	return "end_turn"
}

func message(r responseData, model string, content []object, reason any) object {
	return object{"id": r.ID, "type": "message", "role": "assistant", "model": model,
		"content": content, "stop_reason": reason, "stop_sequence": nil, "usage": r.usage()}
}

func finalMessage(r responseData, model string) (object, error) {
	content := make([]object, 0)
	for _, item := range r.Output {
		switch item.Type {
		case "message":
			for _, p := range item.Content {
				switch p.Type {
				case "output_text":
					content = append(content, object{"type": "text", "text": p.Text})
				case "refusal":
					content = append(content, object{"type": "text", "text": p.Refusal})
				}
			}
		case "function_call":
			var args map[string]any
			if json.Unmarshal([]byte(item.Arguments), &args) != nil || args == nil {
				return nil, errors.New("OpenAI вернул некорректные аргументы инструмента")
			}
			content = append(content, object{"type": "tool_use", "id": item.CallID, "name": item.Name, "input": json.RawMessage(item.Arguments)})
		}
	}
	return message(r, model, content, r.stopReason()), nil
}

type streamKey struct{ output, content int }

type messageStream struct {
	w       io.Writer
	model   string
	indices map[streamKey]int
	next    int
	started bool
}

func (s *messageStream) send(kind string, fields object) error {
	fields["type"] = kind
	payload, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(s.w, "event: %s\ndata: %s\n\n", kind, payload)
	return err
}

func (s *messageStream) block(kind string, key streamKey, data object) error {
	index, exists := s.indices[key]
	if kind == "content_block_start" {
		if exists {
			return nil
		}
		index = s.next
		s.next++
		s.indices[key] = index
	} else if !exists {
		return nil
	}
	if kind == "content_block_stop" {
		delete(s.indices, key)
	}
	data["index"] = index
	return s.send(kind, data)
}

func (s *messageStream) handle(e event) error {
	key := streamKey{e.OutputIndex, e.ContentIndex}
	call := streamKey{e.OutputIndex, -1}
	switch e.Type {
	case "response.created":
		if !s.started {
			s.started = true
			return s.send("message_start", object{"message": message(e.Response, s.model, []object{}, nil)})
		}
	case "response.content_part.added":
		if e.Part.Type == "output_text" || e.Part.Type == "refusal" {
			return s.block("content_block_start", key, object{"content_block": object{"type": "text", "text": ""}})
		}
	case "response.output_text.delta", "response.refusal.delta":
		return s.block("content_block_delta", key, object{"delta": object{"type": "text_delta", "text": e.Delta}})
	case "response.content_part.done":
		return s.block("content_block_stop", key, object{})
	case "response.output_item.added":
		if e.Item.Type == "function_call" {
			return s.block("content_block_start", call, object{"content_block": object{"type": "tool_use", "id": e.Item.CallID, "name": e.Item.Name, "input": object{}}})
		}
	case "response.function_call_arguments.delta":
		return s.block("content_block_delta", call, object{"delta": object{"type": "input_json_delta", "partial_json": e.Delta}})
	case "response.output_item.done":
		if e.Item.Type == "function_call" {
			return s.block("content_block_stop", call, object{})
		}
	case "response.completed", "response.incomplete":
		if !s.started || len(s.indices) != 0 {
			return errors.New("неполное сообщение OpenAI")
		}
		if err := s.send("message_delta", object{"delta": object{"stop_reason": e.Response.stopReason(), "stop_sequence": nil}, "usage": e.Response.usage()}); err != nil {
			return err
		}
		return s.send("message_stop", object{})
	case "response.failed", "error":
		return failure(e)
	}
	return nil
}
