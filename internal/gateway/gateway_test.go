package gateway

import (
	"bufio"
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seredavin/claude-proxy/internal/auth"
	"github.com/seredavin/claude-proxy/internal/config"
)

// syncBuffer — логи, в которые пишет горутина сервера, а читает тест.
// Без мьютекса это гонка, без ожидания — флак: access-лог пишется уже
// после того, как клиент получил ответ.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

// waitFor ждёт появления подстроки в логе.
func (b *syncBuffer) waitFor(substr string) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(b.String(), substr) {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// upstreamEcho — заглушка Anthropic: возвращает заголовки, которые получила.
type upstreamEcho struct {
	gotHeader http.Header
	gotHost   string
	gotURI    string
}

func newTestGateway(t *testing.T, mode config.Mode, tokens string, handler http.HandlerFunc) (*httptest.Server, *upstreamEcho, *syncBuffer) {
	t.Helper()

	echo := &upstreamEcho{}
	if handler == nil {
		handler = func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "upstream ok")
		}
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		echo.gotHeader = r.Header.Clone()
		echo.gotHost = r.Host
		echo.gotURI = r.URL.RequestURI()
		handler(w, r)
	}))
	t.Cleanup(upstream.Close)

	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	set, err := auth.Parse(tokens)
	if err != nil {
		t.Fatal(err)
	}

	logs := &syncBuffer{}
	apiKey := ""
	if mode == config.ModeAPIKey {
		apiKey = "sk-ant-api03-secret"
	}

	gw := New(Options{
		Mode:         mode,
		Tokens:       set,
		APIKey:       apiKey,
		Upstream:     target,
		MaxBodyBytes: 1 << 20,
		Logger:       slog.New(slog.NewTextHandler(logs, nil)),
	})

	front := httptest.NewServer(gw)
	t.Cleanup(front.Close)
	return front, echo, logs
}

func do(t *testing.T, srv *httptest.Server, method, path string, header http.Header, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func bodyOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestСлужебныеПутиБезАвторизации(t *testing.T) {
	for _, mode := range []config.Mode{config.ModeOAuth, config.ModeAPIKey} {
		for _, path := range []string{"/healthz", "/"} {
			srv, echo, _ := newTestGateway(t, mode, "default:secret", nil)
			resp := do(t, srv, http.MethodGet, path, nil, "")
			if resp.StatusCode != http.StatusOK {
				t.Errorf("%s %s: статус %d, ожидалось 200", mode, path, resp.StatusCode)
			}
			if got := bodyOf(t, resp); got != "ok\n" {
				t.Errorf("%s %s: тело %q", mode, path, got)
			}
			if echo.gotHeader != nil {
				t.Errorf("%s %s: запрос ушёл наверх, а не должен был", mode, path)
			}
		}
	}
}

func TestOAuthВеткиАвторизации(t *testing.T) {
	tests := []struct {
		name       string
		header     http.Header
		wantStatus int
		wantBody   string
	}{
		{
			name:       "без ключа шлюза",
			header:     http.Header{"Authorization": {"Bearer sk-ant-oat01-x"}},
			wantStatus: http.StatusUnauthorized,
			wantBody:   "invalid gateway key",
		},
		{
			name:       "неверный ключ шлюза",
			header:     http.Header{"X-Gateway-Key": {"wrong"}, "Authorization": {"Bearer sk-ant-oat01-x"}},
			wantStatus: http.StatusUnauthorized,
			wantBody:   "invalid gateway key",
		},
		{
			name:       "ключ есть, токена подписки нет",
			header:     http.Header{"X-Gateway-Key": {"secret"}},
			wantStatus: http.StatusUnauthorized,
			wantBody:   "missing oauth token",
		},
		{
			name:       "всё на месте",
			header:     http.Header{"X-Gateway-Key": {"secret"}, "Authorization": {"Bearer sk-ant-oat01-x"}},
			wantStatus: http.StatusOK,
			wantBody:   "upstream ok",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, _ := newTestGateway(t, config.ModeOAuth, "default:secret", nil)
			resp := do(t, srv, http.MethodPost, "/v1/messages", tc.header, "{}")
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("статус %d, ожидалось %d", resp.StatusCode, tc.wantStatus)
			}
			if got := bodyOf(t, resp); !strings.Contains(got, tc.wantBody) {
				t.Errorf("тело %q не содержит %q", got, tc.wantBody)
			}
		})
	}
}

func TestOAuthЗаголовкиНаверх(t *testing.T) {
	srv, echo, _ := newTestGateway(t, config.ModeOAuth, "default:secret", nil)
	header := http.Header{
		"X-Gateway-Key":   {"secret"},
		"Authorization":   {"Bearer sk-ant-oat01-x"},
		"X-Forwarded-For": {"10.1.2.3"},
		"Anthropic-Beta":  {"oauth-2025-04-20"},
	}
	do(t, srv, http.MethodPost, "/v1/messages?beta=true", header, "{}")

	if got := echo.gotHeader.Get("Authorization"); got != "Bearer sk-ant-oat01-x" {
		t.Errorf("Authorization наверх = %q — токен подписки должен идти как есть", got)
	}
	if got := echo.gotHeader.Get("X-Gateway-Key"); got != "" {
		t.Errorf("X-Gateway-Key утёк наверх: %q", got)
	}
	if got := echo.gotHeader.Get("X-Forwarded-For"); got != "" {
		t.Errorf("X-Forwarded-For утёк наверх: %q", got)
	}
	if got := echo.gotHeader.Get("Anthropic-Beta"); got != "oauth-2025-04-20" {
		t.Errorf("прикладной заголовок потерян: %q", got)
	}
	if echo.gotURI != "/v1/messages?beta=true" {
		t.Errorf("URI наверх = %q", echo.gotURI)
	}
}

func TestOAuthПодставляетHostАпстрима(t *testing.T) {
	srv, echo, _ := newTestGateway(t, config.ModeOAuth, "default:secret", nil)
	header := http.Header{"X-Gateway-Key": {"secret"}, "Authorization": {"Bearer x"}}
	do(t, srv, http.MethodPost, "/v1/messages", header, "{}")

	if strings.Contains(echo.gotHost, "127.0.0.1") && !strings.HasPrefix(srv.URL, "http://127.0.0.1") {
		t.Fatalf("неожиданный Host: %q", echo.gotHost)
	}
	// Host должен быть хостом апстрима, а не тем, что прислал клиент.
	if echo.gotHost == srv.Listener.Addr().String() {
		t.Errorf("наверх ушёл Host клиента %q", echo.gotHost)
	}
}

func TestAPIKeyВеткиАвторизации(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{name: "без заголовка", authHeader: "", wantStatus: http.StatusUnauthorized},
		{name: "чужой токен", authHeader: "Bearer wrong", wantStatus: http.StatusUnauthorized},
		{name: "без схемы Bearer", authHeader: "secret", wantStatus: http.StatusUnauthorized},
		{name: "другая схема", authHeader: "Basic secret", wantStatus: http.StatusUnauthorized},
		{name: "правильный токен", authHeader: "Bearer secret", wantStatus: http.StatusOK},
		{name: "схема в другом регистре", authHeader: "bearer secret", wantStatus: http.StatusOK},
		{name: "несколько пробелов", authHeader: "Bearer   secret", wantStatus: http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, _ := newTestGateway(t, config.ModeAPIKey, "default:secret", nil)
			header := http.Header{}
			if tc.authHeader != "" {
				header.Set("Authorization", tc.authHeader)
			}
			resp := do(t, srv, http.MethodPost, "/v1/messages", header, "{}")
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("статус %d, ожидалось %d", resp.StatusCode, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusUnauthorized {
				if got := bodyOf(t, resp); !strings.Contains(got, "invalid gateway token") {
					t.Errorf("тело %q", got)
				}
			}
		})
	}
}

func TestAPIKeyПодменяетCredential(t *testing.T) {
	srv, echo, _ := newTestGateway(t, config.ModeAPIKey, "default:secret", nil)
	do(t, srv, http.MethodPost, "/v1/messages",
		http.Header{"Authorization": {"Bearer secret"}}, "{}")

	if got := echo.gotHeader.Get("Authorization"); got != "" {
		t.Errorf("пропуск на шлюз утёк наверх в Authorization: %q", got)
	}
	if got := echo.gotHeader.Get("X-Api-Key"); got != "sk-ant-api03-secret" {
		t.Errorf("x-api-key наверх = %q", got)
	}
}

func TestНесколькоТокеновИМеткаВЛоге(t *testing.T) {
	srv, _, logs := newTestGateway(t, config.ModeOAuth, "team-a:aaa,team-b:bbb", nil)

	for _, tc := range []struct{ token, label string }{{"aaa", "team-a"}, {"bbb", "team-b"}} {
		logs.Reset()
		header := http.Header{"X-Gateway-Key": {tc.token}, "Authorization": {"Bearer x"}}
		resp := do(t, srv, http.MethodPost, "/v1/messages", header, "{}")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("токен %s: статус %d", tc.label, resp.StatusCode)
		}
		if !logs.waitFor("token=" + tc.label) {
			t.Errorf("в логе нет метки %q: %s", tc.label, logs.String())
		}
		if strings.Contains(logs.String(), tc.token) {
			t.Errorf("значение токена попало в лог: %s", logs.String())
		}
	}
}

func TestОтозванныйТокенНеПроходит(t *testing.T) {
	srv, _, _ := newTestGateway(t, config.ModeOAuth, "team-a:aaa", nil)
	header := http.Header{"X-Gateway-Key": {"bbb"}, "Authorization": {"Bearer x"}}
	resp := do(t, srv, http.MethodPost, "/v1/messages", header, "{}")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("статус %d, ожидалось 401", resp.StatusCode)
	}
}

func TestПревышениеРазмераТела(t *testing.T) {
	srv, echo, _ := newTestGateway(t, config.ModeOAuth, "default:secret", nil)
	header := http.Header{"X-Gateway-Key": {"secret"}, "Authorization": {"Bearer x"}}
	resp := do(t, srv, http.MethodPost, "/v1/messages", header, strings.Repeat("x", (1<<20)+1))

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("статус %d, ожидалось 413", resp.StatusCode)
	}
	if !strings.Contains(bodyOf(t, resp), "request_too_large") {
		t.Error("тело не в формате ошибки Anthropic")
	}
	if echo.gotHeader != nil {
		t.Error("слишком большой запрос ушёл наверх")
	}
}

func TestSSEПрилетаетДоЗавершенияОтвета(t *testing.T) {
	release := make(chan struct{})
	srv, _, _ := newTestGateway(t, config.ModeOAuth, "default:secret",
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "event: message_start\ndata: {}\n\n")
			w.(http.Flusher).Flush()
			<-release // ответ ещё не завершён
			_, _ = io.WriteString(w, "event: message_stop\ndata: {}\n\n")
		})

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/messages", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Gateway-Key", "secret")
	req.Header.Set("Authorization", "Bearer x")

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	type readResult struct {
		line string
		err  error
	}
	got := make(chan readResult, 1)
	go func() {
		line, err := bufio.NewReader(resp.Body).ReadString('\n')
		got <- readResult{line, err}
	}()

	select {
	case res := <-got:
		if res.err != nil {
			t.Fatalf("чтение первого события: %v", res.err)
		}
		if !strings.Contains(res.line, "message_start") {
			t.Fatalf("первое событие = %q", res.line)
		}
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("первое событие не дошло до клиента — буферизация не отключена")
	}
	close(release)
}

func TestАпстримНедоступен(t *testing.T) {
	set, err := auth.Parse("default:secret")
	if err != nil {
		t.Fatal(err)
	}
	// Порт, на котором заведомо никто не слушает.
	dead, err := url.Parse("http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	gw := New(Options{
		Mode:         config.ModeOAuth,
		Tokens:       set,
		Upstream:     dead,
		MaxBodyBytes: 1 << 20,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	srv := httptest.NewServer(gw)
	defer srv.Close()

	header := http.Header{"X-Gateway-Key": {"secret"}, "Authorization": {"Bearer x"}}
	resp := do(t, srv, http.MethodPost, "/v1/messages", header, "{}")
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("статус %d, ожидалось 502", resp.StatusCode)
	}
	if !strings.Contains(bodyOf(t, resp), "api_error") {
		t.Error("тело не в формате ошибки Anthropic")
	}
}

func TestBearerToken(t *testing.T) {
	tests := map[string]string{
		"Bearer abc":     "abc",
		"bearer abc":     "abc",
		"BEARER\tabc":    "abc",
		"Bearer   abc":   "abc",
		"Bearerabc":      "",
		"Bearer":         "",
		"Bearer ":        "",
		"Basic abc":      "",
		"":               "",
		"abc":            "",
		"Bearer a b":     "a b",
		"Bearer abc def": "abc def",
	}
	for in, want := range tests {
		if got := bearerToken(in); got != want {
			t.Errorf("bearerToken(%q) = %q, ожидалось %q", in, got, want)
		}
	}
}
