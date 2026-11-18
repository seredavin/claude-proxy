package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seredavin/claude-proxy/internal/auth"
	"github.com/seredavin/claude-proxy/internal/config"
	"github.com/seredavin/claude-proxy/internal/mask"
	"github.com/seredavin/claude-proxy/internal/trace"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOpenAIStreamAndToolContinuation(t *testing.T) {
	set, err := auth.Parse("openai:AA,legacy:BB")
	if err != nil {
		t.Fatal(err)
	}
	openaiURL, _ := url.Parse(config.OpenAIResponsesURL)
	legacyURL, _ := url.Parse("https://edge.example")
	transportCalls := 0
	gw := New(Options{
		Mode: config.ModeOAuth, Tokens: set, Upstream: legacyURL, UpstreamKey: "edge-secret",
		Routes: []config.Route{{Label: "openai", Upstream: openaiURL, OpenAI: &config.OpenAITarget{Profile: "personal", Model: "gpt-test"}}},
		ChatGPTToken: func(_ context.Context, profile string) (string, error) {
			if profile != "personal" {
				t.Errorf("неожиданный профиль %q", profile)
			}
			return "openai-secret", nil
		},
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			defer req.Body.Close()
			transportCalls++
			if req.URL.Host == legacyURL.Host {
				if req.Header.Get("X-Gateway-Key") != "edge-secret" || req.Header.Get("Authorization") != "Bearer legacy-token" {
					t.Error("пропуска цепочки изменились")
				}
				return &http.Response{Request: req, StatusCode: 200, Body: io.NopCloser(strings.NewReader("legacy"))}, nil
			}
			if req.URL.String() != config.OpenAIResponsesURL || req.Header.Get("Authorization") != "Bearer openai-secret" ||
				req.Header.Get("X-Gateway-Key") != "" || req.Header.Get("Cookie") != "" {
				t.Error("неожиданный URL или заголовки OpenAI")
			}
			var payload struct {
				Model  string
				Input  []map[string]json.RawMessage
				Store  bool
				Stream bool
			}
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
				return nil, err
			}
			if payload.Model != "gpt-test" || payload.Store || !payload.Stream {
				t.Error("неверные поля Responses API")
			}
			events := []string{
				`{"type":"response.created","response":{"id":"resp_test"}}`,
				`{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","call_id":"call_test","name":"Read"}}`,
				`{"type":"response.function_call_arguments.delta","output_index":0,"delta":"{\"path\":"}`,
				`{"type":"response.function_call_arguments.delta","output_index":0,"delta":"\"file\"}"}`,
				`{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call"}}`,
				`{"type":"response.completed","response":{"id":"resp_test","output":[{"type":"function_call","call_id":"call_test","name":"Read","arguments":"{\"path\":\"file\"}"}],"usage":{"input_tokens":12,"output_tokens":7}}}`,
			}
			if transportCalls == 1 && (len(payload.Input) != 3 || string(payload.Input[0]["type"]) != `"additional_tools"` || string(payload.Input[2]["role"]) != `"developer"`) {
				t.Error("ожидались additional_tools и преобразованное системное сообщение")
			}
			if transportCalls == 2 {
				if len(payload.Input) != 3 || string(payload.Input[2]["call_id"]) != `"call_test"` || string(payload.Input[2]["output"]) != `"file content"` {
					t.Error("результат инструмента потерял идентификатор или содержимое")
				}
				events = []string{`{"type":"response.completed","response":{"id":"resp_next","output":[{"type":"message","content":[{"type":"output_text","text":"done"}]}]}}`}
			}
			wire := "data: " + strings.Join(events, "\n\ndata: ") + "\n\n"
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(wire))}, nil
		}),
	})

	request := func(path, token, payload string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(payload))
		req.Header.Set("X-Gateway-Key", token)
		req.Header.Set("Cookie", "never-forward-this")
		if token == "BB" {
			req.Header.Set("Authorization", "Bearer legacy-token")
		}
		w := httptest.NewRecorder()
		gw.ServeHTTP(w, req)
		return w
	}
	w := request("/v1/messages", "AA", `{"model":"claude-test","stream":true,"messages":[{"role":"user","content":"read"},{"role":"system","content":"Use the local tool"}],"tools":[{"name":"Read","input_schema":{"type":"object"}}]}`)
	for _, part := range []string{`"id":"call_test"`, `"partial_json":"{\"path\`, `"stop_reason":"tool_use"`, "event: message_stop"} {
		if w.Code != 200 || !strings.Contains(w.Body.String(), part) {
			t.Fatalf("неполный Anthropic SSE (%d): %s", w.Code, w.Body)
		}
	}
	w = request("/v1/messages", "AA", `{"model":"claude-test","messages":[{"role":"user","content":"read"},{"role":"assistant","content":[{"type":"tool_use","id":"call_test","name":"Read","input":{"path":"file"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"call_test","content":"file content"}]}]}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"text":"done"`) {
		t.Fatalf("неполный Anthropic JSON (%d): %s", w.Code, w.Body)
	}
	w = request("/v1/messages/count_tokens", "AA", `{"model":"claude-test","messages":[{"role":"user","content":"count"}]}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"input_tokens":`) || transportCalls != 2 {
		t.Fatalf("неожиданный результат count_tokens (%d): %s", w.Code, w.Body)
	}
	w = request("/v1/messages", "BB", `{}`)
	if w.Code != 200 || w.Body.String() != "legacy" {
		t.Fatalf("общий маршрут изменился (%d): %s", w.Code, w.Body)
	}
}

func TestDefaultOpenAIMasksAndTraces(t *testing.T) {
	tokens, err := auth.Parse("client:local-secret")
	if err != nil {
		t.Fatal(err)
	}
	url, _ := url.Parse(config.OpenAIResponsesURL)
	dir := t.TempDir()
	tracer, err := trace.New(dir, trace.Options{})
	if err != nil {
		t.Fatal(err)
	}
	rules, err := mask.ParseRules(strings.NewReader("ip private\n"), "rules")
	if err != nil {
		t.Fatal(err)
	}
	gw := New(Options{
		Mode: config.ModeOAuth, Tokens: tokens, Upstream: url,
		OpenAI:       &config.OpenAITarget{Profile: "test", Model: "gpt-test"},
		ChatGPTToken: func(context.Context, string) (string, error) { return "openai-secret", nil },
		Masker:       mask.NewRegistry(rules, mask.Options{}), MaskOnError: config.MaskClosed, Tracer: tracer,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			defer req.Body.Close()
			var request struct {
				Input []struct{ Content []struct{ Text string } }
			}
			if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
				return nil, err
			}
			text := request.Input[0].Content[0].Text
			if strings.Contains(text, "10.0.0.5") {
				t.Error("OpenAI получил исходный IP")
			}
			data, err := json.Marshal(map[string]any{"type": "response.completed", "response": map[string]any{
				"id": "test", "output": []any{map[string]any{"type": "message", "content": []any{map[string]any{"type": "output_text", "text": text}}}},
			}})
			if err != nil {
				return nil, err
			}
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader("data: " + string(data) + "\n\n"))}, nil
		}),
	})
	r := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(`{"model":"claude-test","messages":[{"role":"user","content":"host 10.0.0.5"}]}`))
	r.Header.Set("X-Gateway-Key", "local-secret")
	w := httptest.NewRecorder()
	gw.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "host 10.0.0.5") {
		t.Fatalf("ответ не демаскирован: %d %s", w.Code, w.Body)
	}
	for _, suffix := range []string{"upstream.request", "upstream.response", "meta.json"} {
		paths, err := filepath.Glob(filepath.Join(dir, "*."+suffix))
		if err != nil || len(paths) != 1 {
			t.Fatalf("ожидался один файл %s, получено %v (%v)", suffix, paths, err)
		}
		data, err := os.ReadFile(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"openai-secret", "local-secret", "10.0.0.5"} {
			if strings.Contains(string(data), secret) {
				t.Errorf("%s содержит исходные данные", suffix)
			}
		}
		if suffix == "meta.json" && (!strings.Contains(string(data), "<redacted>") || !strings.Contains(string(data), "api.openai.com")) {
			t.Error("в метаданных нет хоста или скрытого Authorization")
		}
	}
}

func TestLocalChainUsesOnlyRemoteOpenAIRouteKey(t *testing.T) {
	localTokens, _ := auth.Parse("local:local-key")
	remoteTokens, _ := auth.Parse("openai:remote-openai,other:remote-other")
	openAIURL, _ := url.Parse(config.OpenAIResponsesURL)
	anthropic, _ := url.Parse("https://api.anthropic.com")
	edge, _ := url.Parse("https://edge.example")
	var called []string
	remoteGateway := New(Options{
		Mode: config.ModeOAuth, Tokens: remoteTokens, Upstream: anthropic,
		Routes: []config.Route{
			{Label: "openai", Upstream: openAIURL, OpenAI: &config.OpenAITarget{Profile: "test", Models: []config.OpenAIModel{
				{Alias: "gpt-fast", Model: "fast-upstream"},
				{Alias: "gpt-strong", Model: "strong-upstream"},
			}}},
			{Label: "other", Upstream: openAIURL, OpenAI: &config.OpenAITarget{Profile: "other", Models: []config.OpenAIModel{
				{Alias: "gpt-other", Model: "other-upstream"},
			}}},
		},
		ChatGPTToken: func(context.Context, string) (string, error) { return "openai-session", nil },
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			defer req.Body.Close()
			if req.URL.Host != openAIURL.Host || req.Header.Get("Authorization") != "Bearer openai-session" ||
				req.Header.Get("X-Gateway-Key") != "" {
				t.Error("запрос не изолирован от пропуска шлюза")
			}
			var payload struct{ Model string }
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
				return nil, err
			}
			called = append(called, payload.Model)
			return &http.Response{StatusCode: 200,
				Body: io.NopCloser(strings.NewReader("data: " + `{"type":"response.completed","response":{"id":"test","output":[{"type":"message","content":[{"type":"output_text","text":"OpenAI"}]}]}}` + "\n\n"))}, nil
		}),
	})
	localGateway := New(Options{
		Mode: config.ModeOAuth, Tokens: localTokens, Upstream: edge, UpstreamKey: "remote-openai", ChatGPTChainLabel: "local",
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("X-Gateway-Key") != "remote-openai" || req.Header.Get("Authorization") != "" ||
				req.Header.Get("X-Api-Key") != "" {
				t.Error("удалённому шлюзу нужен только его пропуск")
			}
			rec := httptest.NewRecorder()
			remoteGateway.ServeHTTP(rec, req)
			resp := rec.Result()
			resp.Request = req
			return resp, nil
		}),
	})
	request := func(method, path, model string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"model": model, "messages": []any{map[string]string{"role": "user", "content": "hello"}}})
		reader := strings.NewReader("")
		if method == http.MethodPost {
			reader = strings.NewReader(string(body))
		}
		req := httptest.NewRequest(method, path, reader)
		req.Header.Set("X-Gateway-Key", "local-key")
		req.Header.Set("Authorization", "Bearer local-only")
		rec := httptest.NewRecorder()
		localGateway.ServeHTTP(rec, req)
		return rec
	}
	catalog := request(http.MethodGet, "/v1/models", "")
	var models struct {
		Data    []struct{ ID string }
		HasMore bool `json:"has_more"`
	}
	if err := json.Unmarshal(catalog.Body.Bytes(), &models); err != nil || catalog.Code != 200 ||
		len(models.Data) != 2 || models.Data[0].ID != "claude-gpt-fast" || models.Data[1].ID != "claude-gpt-strong" || models.HasMore {
		t.Fatalf("ожидались только модели выбранного маршрута: %d %s", catalog.Code, catalog.Body)
	}
	if len(called) != 0 {
		t.Fatal("каталог не должен обращаться в OpenAI")
	}
	for _, alias := range []string{"gpt-fast", "claude-gpt-strong"} {
		resp := request(http.MethodPost, "/v1/messages", alias)
		if resp.Code != 200 || !strings.Contains(resp.Body.String(), `"model":"`+alias+`"`) {
			t.Fatalf("модель %s: %d %s", alias, resp.Code, resp.Body)
		}
	}
	for _, path := range []string{"/v1/messages", "/v1/messages/count_tokens"} {
		if resp := request(http.MethodPost, path, "gpt-other"); resp.Code != 400 {
			t.Fatalf("модель чужого маршрута принята для %s: %d %s", path, resp.Code, resp.Body)
		}
	}
	if resp := request(http.MethodPost, "/v1/messages/count_tokens", "gpt-fast"); resp.Code != 200 {
		t.Fatalf("разрешённый псевдоним не принят для count_tokens: %d %s", resp.Code, resp.Body)
	}
	if strings.Join(called, ",") != "fast-upstream,strong-upstream" {
		t.Fatalf("неожиданные обращения в OpenAI: %v", called)
	}
}
