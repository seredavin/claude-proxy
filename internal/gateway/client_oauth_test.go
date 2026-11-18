package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/seredavin/claude-proxy/internal/auth"
	"github.com/seredavin/claude-proxy/internal/config"
	"github.com/seredavin/claude-proxy/internal/trace"
)

func TestClientOAuthRelayAndInference(t *testing.T) {
	set, _ := auth.Parse("gpt:gateway,legacy:legacy-key")
	target, _ := url.Parse(config.OpenAIResponsesURL)
	dir := t.TempDir()
	var log bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&log, nil))
	tracer, err := trace.New(dir, trace.Options{Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	upstreamCalls := 0
	gw := New(Options{
		Mode: config.ModeOAuth, Tokens: set, Upstream: target, Logger: logger, Tracer: tracer,
		Routes: []config.Route{{Label: "gpt", Upstream: target, OpenAI: &config.OpenAITarget{ClientOAuth: true, Model: "test"}}},
		ChatGPTToken: func(context.Context, string) (string, error) {
			t.Fatal("не должно быть обращения к серверному профилю")
			return "", nil
		},
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			defer r.Body.Close()
			upstreamCalls++
			switch r.URL.Host {
			case "auth.openai.com":
				if r.Header.Get("X-Gateway-Key") != "" || r.ParseForm() != nil || r.Form.Get("refresh_token") != "old-secret" {
					t.Error("неверный OAuth запрос")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"access_token":"next-access","refresh_token":"next-secret","id_token":"extra-secret","token_type":"Bearer","expires_in":3600}`))}, nil
			case "api.openai.com":
				if r.Header.Get("Authorization") != "Bearer next-access" || r.Header.Get("X-Gateway-Key") != "" {
					t.Error("неверные credentials инференса")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("data: " + `{"type":"response.completed","response":{"id":"test"}}` + "\n\n"))}, nil
			default:
				t.Fatal("неожиданный апстрим")
				return nil, nil
			}
		}),
	})
	do := func(method, path, key, bearer, body string, secure bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("X-Gateway-Key", key)
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if secure {
			r.TLS = &tls.ConnectionState{}
		}
		w := httptest.NewRecorder()
		gw.ServeHTTP(w, r)
		return w
	}
	form := "client_id=oaiapp_test&refresh_token=old-secret"
	for _, tc := range []struct {
		key, body string
		secure    bool
		status    int
	}{
		{"wrong", form, true, 401},
		{"legacy-key", form, true, 403},
		{"gateway", form, false, 403},
		{"gateway", form + "&resource=https://bad.example", true, 400},
		{"gateway", strings.Repeat("x", 33<<10), true, 413},
		{"gateway", form, true, 200},
	} {
		w := do("POST", config.ChatGPTRefreshPath, tc.key, "", tc.body, tc.secure)
		if w.Code != tc.status || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("refresh: %d, ожидали %d", w.Code, tc.status)
		}
		if w.Code == 200 && (!strings.Contains(w.Body.String(), "next-secret") || strings.Contains(w.Body.String(), "extra-secret")) {
			t.Error("неверный ответ ротации")
		}
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 0 || upstreamCalls != 1 {
		t.Fatal("обмен попал в трассу или ушёл в OAuth без разрешения")
	}
	msg := `{"model":"alias","messages":[{"role":"user","content":"hello"}]}`
	if w := do("POST", "/v1/messages", "gateway", "", msg, true); w.Code != 401 {
		t.Fatalf("инференс без Bearer: %d", w.Code)
	}
	if w := do("GET", "/v1/models", "gateway", "", "", true); w.Code != 200 {
		t.Fatalf("каталог без Bearer: %d", w.Code)
	}
	if w := do("POST", "/v1/messages/count_tokens", "gateway", "", msg, true); w.Code != 200 {
		t.Fatalf("подсчёт без Bearer: %d", w.Code)
	}
	if w := do("POST", "/v1/messages", "gateway", "next-access", msg, true); w.Code != 200 || upstreamCalls != 2 {
		t.Fatalf("инференс с Bearer: %d", w.Code)
	}
	localTokens, _ := auth.Parse("local:launch-key")
	edge, _ := url.Parse("https://edge.example")
	local := New(Options{
		Mode: config.ModeOAuth, Tokens: localTokens, Upstream: edge, UpstreamKey: "gateway",
		ChatGPTChainLabel: "local", ChatGPTChainProfile: "personal",
		ChatGPTToken: func(ctx context.Context, name string) (string, error) {
			if name != "personal" {
				t.Fatal("неверный профиль")
			}
			res := do("POST", config.ChatGPTRefreshPath, "gateway", "", form, true)
			var out struct {
				AccessToken string `json:"access_token"`
			}
			if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
				return "", err
			}
			return out.AccessToken, nil
		},
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			req.TLS = &tls.ConnectionState{}
			resp := httptest.NewRecorder()
			gw.ServeHTTP(resp, req)
			out := resp.Result()
			out.Request = req
			return out, nil
		}),
	})
	request := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(msg))
	request.Header.Set("X-Gateway-Key", "launch-key")
	request.Header.Set("Authorization", "Bearer claude-placeholder")
	reply := httptest.NewRecorder()
	local.ServeHTTP(reply, request)
	if reply.Code != 200 || upstreamCalls != 4 {
		t.Fatalf("два звена с обновлением: %d, запросов %d", reply.Code, upstreamCalls)
	}

	files, _ = os.ReadDir(dir)
	for _, f := range files {
		data, err := os.ReadFile(dir + "/" + f.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"old-secret", "next-secret", "next-access"} {
			if strings.Contains(string(data), secret) || strings.Contains(log.String(), secret) {
				t.Error("credential попал в трассу или лог")
			}
		}
	}
}
