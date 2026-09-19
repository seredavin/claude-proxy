package server

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/seredavin/claude-proxy/internal/auth"
	"github.com/seredavin/claude-proxy/internal/config"
)

// freePort занимает порт и сразу отпускает его. Гонка теоретически возможна,
// но в тестовом окружении достаточно надёжно.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func insecureClient() *http.Client {
	return &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
}

func TestRunПоднимаетTLSИГаснетПоКонтексту(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "upstream ok")
	}))
	defer upstream.Close()

	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := auth.Parse("default:secret")
	if err != nil {
		t.Fatal(err)
	}

	addr := freePort(t)
	cfg := &config.Config{
		Mode:         config.ModeOAuth,
		Listen:       addr,
		Domain:       "localhost",
		Tokens:       tokens,
		Upstream:     target,
		TLS:          config.TLSSelf,
		StateDir:     t.TempDir(),
		MaxBodyBytes: 1 << 20,
		LogFormat:    "text",
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil))) }()

	client := insecureClient()
	var resp *http.Response
	for i := 0; i < 50; i++ {
		resp, err = client.Get("https://" + addr + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatalf("шлюз не поднялся: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "ok\n" {
		t.Errorf("/healthz вернул %q", body)
	}

	// Запрос через шлюз доходит до апстрима.
	req, err := http.NewRequest(http.MethodPost, "https://"+addr+"/v1/messages", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Gateway-Key", "secret")
	req.Header.Set("Authorization", "Bearer x")
	resp, err = client.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("запрос через шлюз: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "upstream ok" {
		t.Errorf("ответ апстрима = %q", body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run вернул ошибку при остановке: %v", err)
		}
	case <-time.After(shutdownTimeout + 5*time.Second):
		t.Fatal("Run не завершился по отмене контекста")
	}
}

func TestRunПадаетНаЗанятомПорту(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()

	tokens, err := auth.Parse("default:secret")
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse("https://api.anthropic.com")
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Mode:     config.ModeOAuth,
		Listen:   busy.Addr().String(),
		Domain:   "localhost",
		Tokens:   tokens,
		Upstream: target,
		TLS:      config.TLSSelf,
		StateDir: t.TempDir(),
	}

	err = Run(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("занятый порт не привёл к ошибке")
	}
	if !strings.Contains(err.Error(), "не удалось занять") {
		t.Errorf("невнятная ошибка: %v", err)
	}
}
