package mask

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"sync"
)

// deltaFields — текстовое поле дельты по её типу. Прочие дельты
// (signature_delta, citations_delta) идут через общий обходчик.
var deltaFields = map[string]string{
	"text_delta":       "text",
	"thinking_delta":   "thinking",
	"input_json_delta": "partial_json",
}

// heldBlock — удержанный хвост одного блока контента.
type heldBlock struct {
	tail      string
	deltaType string
	field     string
}

// Stream демаскирует SSE-ответ на лету.
//
// События разбираются по одному; в дельтах text/thinking/partial_json
// суррогаты заменяются исходными значениями. Суффикс дельты, который может
// быть началом суррогата, удерживается до следующей дельты того же блока —
// и никогда не теряется: он отдаётся синтетической дельтой на
// content_block_stop, message_stop, error, конце потока или ошибке чтения.
type Stream struct {
	s   *Session
	src io.ReadCloser
	br  *bufio.Reader
	log *slog.Logger

	out           bytes.Buffer
	held          map[int64]*heldBlock
	responsesHeld map[responseDeltaKey]map[string]any
	// done — источник исчерпан (err — чем именно; io.EOF при штатном конце).
	done bool
	err  error

	mu sync.Mutex
	st Stats
}

// UnmaskStream оборачивает тело SSE-ответа.
func (s *Session) UnmaskStream(src io.ReadCloser) *Stream {
	return &Stream{
		s:    s,
		src:  src,
		br:   bufio.NewReaderSize(src, 64*1024),
		log:  s.log,
		held: map[int64]*heldBlock{},
	}
}

// Stats — счётчики после завершения потока.
func (st *Stream) Stats() Stats {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.st
}

func (st *Stream) Close() error { return st.src.Close() }

// Read отдаёт по одному обработанному событию за вызов: ReverseProxy с
// FlushInterval -1 сбрасывает буфер после каждого Read, так что клиент
// видит события по мере поступления.
func (st *Stream) Read(p []byte) (int, error) {
	for st.out.Len() == 0 {
		if st.done {
			return 0, st.err
		}
		st.nextEvent()
	}
	return st.out.Read(p)
}

// nextEvent читает одно событие (до пустой строки) и кладёт результат в out.
func (st *Stream) nextEvent() {
	var lines []string
	for {
		raw, err := st.br.ReadString('\n')
		if len(raw) > 0 {
			line := strings.TrimRight(raw, "\r\n")
			if line == "" && err == nil {
				if len(lines) == 0 {
					continue // подряд идущие пустые строки — не событие
				}
				break
			}
			if line != "" {
				lines = append(lines, line)
			}
		}
		if err != nil {
			// Конец или обрыв: обрабатываем то, что успело прийти, и
			// сбрасываем все хвосты — обрезанный tool_use хуже лишней дельты.
			if len(lines) > 0 {
				st.processEvent(lines)
			}
			st.flushAll()
			st.flushResponseDeltas()
			st.done = true
			st.err = err
			return
		}
	}
	st.processEvent(lines)
}

// processEvent переписывает событие и пишет его в out.
func (st *Stream) processEvent(lines []string) {
	var data []string
	firstData := -1
	for i, line := range lines {
		if value, ok := strings.CutPrefix(line, "data:"); ok {
			if firstData < 0 {
				firstData = i
			}
			data = append(data, strings.TrimPrefix(value, " "))
		}
	}
	if firstData < 0 {
		st.writeLines(lines)
		return
	}

	payload := strings.Join(data, "\n")
	node, err := decode([]byte(payload))
	if err != nil {
		st.fail("событие SSE не разобралось, передано как есть", err)
		st.writeLines(lines)
		return
	}
	obj, ok := node.(map[string]any)
	if !ok {
		st.writeLines(lines)
		return
	}

	kind, _ := obj["type"].(string)
	switch kind {
	case "content_block_delta":
		st.rewriteDelta(obj)
	case "content_block_stop":
		if idx, ok := blockIndex(obj); ok {
			st.flushBlock(idx)
		}
	case "response.output_text.delta", "response.refusal.delta", "response.reasoning_text.delta",
		"response.reasoning_summary_text.delta", "response.function_call_arguments.delta", "response.custom_tool_call_input.delta":
		st.rewriteResponseDelta(kind, obj)
	case "response.output_text.done", "response.refusal.done", "response.reasoning_text.done",
		"response.reasoning_summary_text.done", "response.function_call_arguments.done", "response.custom_tool_call_input.done":
		st.flushResponseDelta(responseKey(strings.TrimSuffix(kind, ".done")+".delta", obj))
		st.unmaskEvent(obj)
	case "response.completed", "response.incomplete", "response.failed":
		st.flushResponseDeltas()
		st.unmaskEvent(obj)
	case "message_stop", "error":
		st.flushAll()
		st.flushResponseDeltas()
		st.unmaskEvent(obj)
	default:
		st.unmaskEvent(obj)
	}

	encoded, err := encode(obj)
	if err != nil {
		st.fail("событие SSE не сериализовалось, передано как есть", err)
		st.writeLines(lines)
		return
	}
	var out []string
	for i, line := range lines {
		switch {
		case i == firstData:
			out = append(out, "data: "+string(encoded))
		case strings.HasPrefix(line, "data:"):
		default:
			out = append(out, line)
		}
	}
	st.writeLines(out)
}

// rewriteDelta демаскирует текстовую дельту с учётом удержанного хвоста.
func (st *Stream) rewriteDelta(obj map[string]any) {
	idx, ok := blockIndex(obj)
	delta, isMap := obj["delta"].(map[string]any)
	if !ok || !isMap {
		return
	}
	deltaType, _ := delta["type"].(string)
	field, textual := deltaFields[deltaType]
	if !textual {
		var s Stats
		if err := st.s.walk(delta, modeReverse, &s); err == nil {
			st.count(s.Unmasked)
		}
		return
	}
	text, _ := delta[field].(string)

	// Блоки идут последовательно: дельта другого индекса означает, что
	// прежний блок закончился, даже если stop по нему ещё не пришёл.
	for other := range st.held {
		if other != idx {
			st.flushBlock(other)
		}
	}
	if h := st.held[idx]; h != nil {
		text = h.tail + text
		delete(st.held, idx)
	}

	tail := st.s.heldTail(text)
	emit := text[:len(text)-len(tail)]
	if tail != "" {
		st.held[idx] = &heldBlock{tail: tail, deltaType: deltaType, field: field}
	}
	out, n := st.s.unmaskText(emit, escapeFor(field))
	st.count(n)
	delta[field] = out
}

// flushBlock отдаёт удержанный хвост блока синтетической дельтой.
func (st *Stream) flushBlock(idx int64) {
	h := st.held[idx]
	if h == nil {
		return
	}
	delete(st.held, idx)
	out, n := st.s.unmaskText(h.tail, escapeFor(h.field))
	st.count(n)
	event := map[string]any{
		"type":  "content_block_delta",
		"index": idx,
		"delta": map[string]any{"type": h.deltaType, h.field: out},
	}
	encoded, err := encode(event)
	if err != nil {
		return
	}
	st.writeLines([]string{"event: content_block_delta", "data: " + string(encoded)})
}

func (st *Stream) flushAll() {
	for idx := range st.held {
		st.flushBlock(idx)
	}
}

func (st *Stream) writeLines(lines []string) {
	for _, line := range lines {
		st.out.WriteString(line)
		st.out.WriteByte('\n')
	}
	st.out.WriteByte('\n')
}

func (st *Stream) count(n int) {
	st.mu.Lock()
	st.st.Unmasked += n
	st.mu.Unlock()
}

func (st *Stream) fail(msg string, err error) {
	st.mu.Lock()
	st.st.Errors++
	st.mu.Unlock()
	st.log.Warn(msg, "token", st.s.label, "err", err)
}

// blockIndex — индекс блока контента из события.
func blockIndex(obj map[string]any) (int64, bool) {
	num, ok := obj["index"].(json.Number)
	if !ok {
		return 0, false
	}
	idx, err := num.Int64()
	return idx, err == nil
}

// escapeFor — как вставлять исходное значение в поле дельты. partial_json —
// фрагмент JSON, и значение стоит внутри строкового литерала: его надо
// экранировать. Текст и thinking — как есть.
func escapeFor(field string) func(string) string {
	if field != "partial_json" {
		return nil
	}
	return jsonEscape
}

// jsonEscape — содержимое JSON-строки без кавычек.
func jsonEscape(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	b := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	return string(b[1 : len(b)-1])
}

func (st *Stream) unmaskEvent(obj map[string]any) {
	var stats Stats
	if err := st.s.walk(obj, modeReverse, &stats); err != nil {
		st.fail("событие SSE не переписалось", err)
	}
	st.count(stats.Unmasked)
}

type responseDeltaKey struct {
	kind, item    string
	index, output json.Number
}

func responseKey(kind string, obj map[string]any) responseDeltaKey {
	item, _ := obj["item_id"].(string)
	index, ok := obj["content_index"].(json.Number)
	if !ok {
		index, _ = obj["summary_index"].(json.Number)
	}
	output, _ := obj["output_index"].(json.Number)
	return responseDeltaKey{kind, item, index, output}
}

func (st *Stream) rewriteResponseDelta(kind string, obj map[string]any) {
	text, ok := obj["delta"].(string)
	if !ok {
		return
	}
	key := responseKey(kind, obj)
	if previous := st.responsesHeld[key]; previous != nil {
		text = previous["delta"].(string) + text
		delete(st.responsesHeld, key)
	}
	tail := st.s.heldTail(text)
	var escape func(string) string
	if kind == "response.function_call_arguments.delta" {
		escape = jsonEscape
	}
	out, n := st.s.unmaskText(text[:len(text)-len(tail)], escape)
	st.count(n)
	if tail != "" {
		if st.responsesHeld == nil {
			st.responsesHeld = make(map[responseDeltaKey]map[string]any)
		}
		event := make(map[string]any, len(obj))
		for k, value := range obj {
			event[k] = value
		}
		event["delta"] = tail
		st.responsesHeld[key] = event
	}
	obj["delta"] = out
}

func (st *Stream) flushResponseDelta(key responseDeltaKey) {
	if event := st.responsesHeld[key]; event != nil {
		delete(st.responsesHeld, key)
		if encoded, err := encode(event); err == nil {
			st.writeLines([]string{"event: " + key.kind, "data: " + string(encoded)})
		}
	}
}

func (st *Stream) flushResponseDeltas() {
	for key := range st.responsesHeld {
		st.flushResponseDelta(key)
	}
}
