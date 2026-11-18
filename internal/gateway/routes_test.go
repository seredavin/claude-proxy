package gateway

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/seredavin/claude-proxy/internal/auth"
	"github.com/seredavin/claude-proxy/internal/config"
	"github.com/seredavin/claude-proxy/internal/trace"
)

// routeUpstream — апстрим-заглушка, запоминающий заголовки и Host.
func routeUpstream(t *testing.T, echo *upstreamEcho) *url.URL {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
		if r.Host != addr.String() {
			t.Errorf("Host = %q, ожидался адрес апстрима %q", r.Host, addr)
		}
		echo.gotHeader = r.Header.Clone()
		echo.gotHost = r.Host
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "upstream ok")
	}))
	t.Cleanup(srv.Close)
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

// newRoutedGateway поднимает общий апстрим и апстрим маршрута метки routed;
// возвращает фронт шлюза и обе заглушки.
func newRoutedGateway(t *testing.T, mode config.Mode, route config.Route) (*httptest.Server, *upstreamEcho, *upstreamEcho, *syncBuffer) {
	t.Helper()

	defEcho, rtEcho := &upstreamEcho{}, &upstreamEcho{}
	defURL, rtURL := routeUpstream(t, defEcho), routeUpstream(t, rtEcho)
	route.Upstream = rtURL

	set, err := auth.Parse("plain:AAA,routed:BBB")
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
		Upstream:     defURL,
		UpstreamKey:  "DEFAULT-KEY",
		Routes:       []config.Route{route},
		MaxBodyBytes: 1 << 20,
		Logger:       slog.New(slog.NewTextHandler(logs, nil)),
	})
	front := httptest.NewServer(gw)
	t.Cleanup(front.Close)
	return front, defEcho, rtEcho, logs
}

// routedHeader — пропуск на шлюз тем способом, который ждёт режим.
func routedHeader(mode config.Mode, value string) http.Header {
	h := http.Header{}
	if mode == config.ModeAPIKey {
		h.Set("Authorization", "Bearer "+value)
		return h
	}
	h.Set("X-Gateway-Key", value)
	h.Set("Authorization", "Bearer sk-ant-oat01-sub")
	return h
}

func TestМаршрутУводитЗапросМеткинаСвойАпстрим(t *testing.T) {
	for _, mode := range []config.Mode{config.ModeOAuth, config.ModeAPIKey} {
		t.Run(string(mode), func(t *testing.T) {
			front, defEcho, rtEcho, logs := newRoutedGateway(t, mode, config.Route{Label: "routed", Key: "ROUTE-KEY"})

			resp := do(t, front, http.MethodPost, "/v1/messages", routedHeader(mode, "BBB"), `{}`)
			if bodyOf(t, resp) != "upstream ok" {
				t.Fatal("запрос не дошёл до апстрима маршрута")
			}
			if rtEcho.gotHost == "" {
				t.Fatal("апстрим маршрута не получил запрос")
			}
			if got := rtEcho.gotHeader.Get("X-Gateway-Key"); got != "ROUTE-KEY" {
				t.Errorf("X-Gateway-Key = %q, ожидался ключ маршрута", got)
			}
			if mode == config.ModeAPIKey {
				if got := rtEcho.gotHeader.Get("X-Api-Key"); got != "sk-ant-api03-secret" {
					t.Errorf("X-Api-Key = %q, credential должен уходить как обычно", got)
				}
			} else if got := rtEcho.gotHeader.Get("Authorization"); got != "Bearer sk-ant-oat01-sub" {
				t.Errorf("Authorization = %q, токен подписки должен доходить через маршрут", got)
			}
			if defEcho.gotHost != "" {
				t.Error("запрос метки с маршрутом ушёл на общий апстрим")
			}
			if !logs.waitFor("upstream=" + rtEcho.gotHost) {
				t.Errorf("в access-логе нет хоста апстрима маршрута:\n%s", logs)
			}

			// Токен без маршрута — общий апстрим с общим пропуском.
			resp = do(t, front, http.MethodPost, "/v1/messages", routedHeader(mode, "AAA"), `{}`)
			_ = bodyOf(t, resp)
			if defEcho.gotHost == "" {
				t.Fatal("запрос метки без маршрута не дошёл до общего апстрима")
			}
			if got := defEcho.gotHeader.Get("X-Gateway-Key"); got != "DEFAULT-KEY" {
				t.Errorf("X-Gateway-Key = %q, ожидался общий ключ", got)
			}
		})
	}
}

func TestМаршрутБезКлючаНеНаследуетОбщий(t *testing.T) {
	front, _, rtEcho, _ := newRoutedGateway(t, config.ModeOAuth, config.Route{Label: "routed"})

	resp := do(t, front, http.MethodPost, "/v1/messages", routedHeader(config.ModeOAuth, "BBB"), `{}`)
	_ = bodyOf(t, resp)
	if got := rtEcho.gotHeader.Get("X-Gateway-Key"); got != "" {
		t.Errorf("X-Gateway-Key = %q, у маршрута без ключа заголовка быть не должно", got)
	}
}

func TestНедостижимыйМаршрутНазываетСвойХост(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL, err := url.Parse(dead.URL)
	if err != nil {
		t.Fatal(err)
	}
	dead.Close()

	set, _ := auth.Parse("routed:BBB")
	logs := &syncBuffer{}
	gw := New(Options{
		Mode: config.ModeOAuth, Tokens: set, Upstream: deadURL,
		UpstreamKey:  "DEFAULT-KEY",
		Routes:       []config.Route{{Label: "routed", Upstream: deadURL, Key: "ROUTE-KEY"}},
		MaxBodyBytes: 1 << 20,
		Logger:       slog.New(slog.NewTextHandler(logs, nil)),
	})
	front := httptest.NewServer(gw)
	t.Cleanup(front.Close)

	resp := do(t, front, http.MethodPost, "/v1/messages", routedHeader(config.ModeOAuth, "BBB"), `{}`)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("статус = %d, ожидался 502", resp.StatusCode)
	}
	if !logs.waitFor("upstream=" + deadURL.Host) {
		t.Errorf("ошибка не назвала хост маршрута:\n%s", logs)
	}
}

func TestМаршрутПишетХостАпстримаВТрассу(t *testing.T) {
	dir := t.TempDir()
	defEcho, rtEcho := &upstreamEcho{}, &upstreamEcho{}
	defURL, rtURL := routeUpstream(t, defEcho), routeUpstream(t, rtEcho)

	set, _ := auth.Parse("plain:AAA,routed:BBB")
	logs := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	tracer, err := trace.New(dir, trace.Options{Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	gw := New(Options{
		Mode: config.ModeOAuth, Tokens: set, Upstream: defURL, UpstreamKey: "DEFAULT-KEY",
		Routes:       []config.Route{{Label: "routed", Upstream: rtURL, Key: "ROUTE-KEY"}},
		MaxBodyBytes: 1 << 20, Logger: logger, Tracer: tracer,
	})
	front := httptest.NewServer(gw)
	t.Cleanup(front.Close)

	do(t, front, http.MethodPost, "/v1/messages", routedHeader(config.ModeOAuth, "BBB"), `{}`)
	do(t, front, http.MethodPost, "/v1/messages", routedHeader(config.ModeOAuth, "AAA"), `{}`)

	// Close дожидается обработчиков, которые записывают трассу после ответа.
	front.Close()
	paths, err := filepath.Glob(filepath.Join(dir, "*.meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Fatalf("в каталоге %d meta.json вместо 2", len(paths))
	}
	wantHost := map[string]string{"routed": rtURL.Host, "plain": defURL.Host}
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var meta trace.Meta
		if err := json.Unmarshal(content, &meta); err != nil {
			t.Fatal(err)
		}
		if host, ok := wantHost[meta.Token]; !ok || meta.Upstream != host {
			t.Errorf("неожиданные метка %q и апстрим %q в трассе", meta.Token, meta.Upstream)
		}
		delete(wantHost, meta.Token)
		if got := meta.RequestHeaders["X-Gateway-Key"]; got != "<redacted>" {
			t.Errorf("X-Gateway-Key в трассе: %q", got)
		}
	}
}
