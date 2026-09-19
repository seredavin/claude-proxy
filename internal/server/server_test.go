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
	"github.com/seredavin/claude-proxy/internal/gateway"
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

// waitUp дожидается, пока шлюз ответит на /healthz по указанной схеме.
func waitUp(t *testing.T, client *http.Client, base string) {
	t.Helper()
	var err error
	for i := 0; i < 50; i++ {
		var resp *http.Response
		resp, err = client.Get(base + "/healthz")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("шлюз не поднялся: %v", err)
}

func TestRunБезTLSПроксируетПоHTTP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "upstream ok")
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	addr := freePort(t)
	cfg := &config.Config{
		Mode:         config.ModeOAuth,
		Listen:       addr,
		Tokens:       tokensOf(t, "default:secret"),
		Upstream:     target,
		TLS:          config.TLSNone,
		MaxBodyBytes: 1 << 20,
		LogFormat:    "text",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil))) }()

	client := &http.Client{Timeout: 3 * time.Second}
	waitUp(t, client, "http://"+addr)

	// С верным пропуском запрос доходит до апстрима.
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/v1/messages", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Gateway-Key", "secret")
	req.Header.Set("Authorization", "Bearer x")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("запрос через шлюз: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "upstream ok" {
		t.Errorf("ответ апстрима = %q", body)
	}

	// Без пропуска — отказ, как и за TLS.
	req, err = http.NewRequest(http.MethodPost, "http://"+addr+"/v1/messages", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("запрос без пропуска: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("без пропуска статус %d, ожидался 401", resp.StatusCode)
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

// Локальное звено без TLS перед следующим звеном: пропуск клиента
// остаётся на локальном звене, следующему уходит его собственный.
// Доверие к сертификату следующего звена здесь не проверяется — за него
// отвечают тесты цепочки в пакете gateway; на macOS SSL_CERT_FILE не
// работает, и второе звено поднято по http.
func TestRunБезTLSПередСледующимЗвеном(t *testing.T) {
	var seenKey, seenAuth string
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "anthropic ok")
	}))
	defer stub.Close()
	stubURL, err := url.Parse(stub.URL)
	if err != nil {
		t.Fatal(err)
	}

	nextGw := gateway.New(gateway.Options{
		Mode:         config.ModeOAuth,
		Tokens:       tokensOf(t, "edge:BBB"),
		Upstream:     stubURL,
		MaxBodyBytes: 1 << 20,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	// Заголовок, который увидело следующее звено, снимаем с его входа.
	next := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenKey = r.Header.Get("X-Gateway-Key")
		nextGw.ServeHTTP(w, r)
	}))
	defer next.Close()
	nextURL, err := url.Parse(next.URL)
	if err != nil {
		t.Fatal(err)
	}

	addr := freePort(t)
	cfg := &config.Config{
		Mode:         config.ModeOAuth,
		Listen:       addr,
		Tokens:       tokensOf(t, "client:AAA"),
		Upstream:     nextURL,
		UpstreamKey:  "BBB",
		TLS:          config.TLSNone,
		MaxBodyBytes: 1 << 20,
		LogFormat:    "text",
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil))) }()

	client := &http.Client{Timeout: 3 * time.Second}
	waitUp(t, client, "http://"+addr)

	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/v1/messages", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Gateway-Key", "AAA")
	req.Header.Set("Authorization", "Bearer sk-ant-oat01-x")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("запрос через цепочку: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "anthropic ok" {
		t.Fatalf("цепочка не прошла: статус %d, тело %q", resp.StatusCode, body)
	}
	if seenKey != "BBB" {
		t.Errorf("следующее звено получило X-Gateway-Key = %q, ожидался его пропуск BBB", seenKey)
	}
	if seenAuth != "Bearer sk-ant-oat01-x" {
		t.Errorf("до Anthropic дошёл Authorization = %q", seenAuth)
	}
}

func tokensOf(t *testing.T, spec string) auth.Set {
	t.Helper()
	set, err := auth.Parse(spec)
	if err != nil {
		t.Fatal(err)
	}
	return set
}
