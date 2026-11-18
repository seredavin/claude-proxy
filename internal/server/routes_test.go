package server

import (
	"bytes"
	"context"
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

// syncBuffer — логгер-приёмник, который тест читает после старта сервера.
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

func TestRunПеречисляетМаршрутыВСтартовомЛоге(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := auth.Parse("a:AAA,b:BBB")
	if err != nil {
		t.Fatal(err)
	}

	edge, err := url.Parse("https://edge.example.com:9443")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Mode:     config.ModeOAuth,
		Listen:   freePort(t),
		Domain:   "localhost",
		Tokens:   tokens,
		Upstream: target,
		Routes: []config.Route{
			{Label: "a", Upstream: edge, Key: "KEY-A"},
			{Label: "b", Upstream: target},
		},
		TLS:          config.TLSSelf,
		StateDir:     t.TempDir(),
		MaxBodyBytes: 1 << 20,
		LogFormat:    "text",
	}

	logs := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Run(ctx, cfg, slog.New(slog.NewTextHandler(logs, nil))) }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s := logs.String(); strings.Contains(s, "a=edge.example.com:9443") && strings.Contains(s, "b=127.0.0.1") {
			if strings.Contains(s, "KEY-A") {
				t.Error("стартовый лог не должен содержать пропусков маршрутов")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("маршруты не попали в стартовый лог:\n%s", logs)
}
