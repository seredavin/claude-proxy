package service

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/seredavin/claude-proxy/internal/tlsconf"
)

// startSNIServer поднимает TLS-сервер, который, как autocert, отказывает
// в рукопожатии без имени сервера.
func startSNIServer(t *testing.T, expectName string) string {
	t.Helper()

	dir := t.TempDir()
	if err := tlsconf.GenerateSelfSigned(expectName, dir, 30); err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem"))
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})

	srv := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				// Ровно то, чем отвечает autocert на запрос без SNI.
				if hello.ServerName == "" {
					return nil, errors.New("acme/autocert: missing server name")
				}
				return &cert, nil
			},
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	return ln.Addr().String()
}

// TestWaitHealthyПередаётИмяСервера — регрессия на реальный отказ установки:
// проверка ходила на 127.0.0.1 и не отправляла SNI, поэтому в режиме auto
// рукопожатие рвалось с «missing server name», а install падал по таймауту
// при полностью исправном шлюзе.
func TestWaitHealthyПередаётИмяСервера(t *testing.T) {
	addr := startSNIServer(t, "proxy.example.com")

	if err := waitHealthy(addr, "proxy.example.com", 10*time.Second); err != nil {
		t.Fatalf("проверка не прошла, хотя шлюз отвечает: %v", err)
	}
}

// Имя может не резолвиться на самом хосте шлюза (split-horizon DNS,
// отсутствие записи во внутренней зоне) — соединение всё равно должно идти
// на петлю.
func TestWaitHealthyНеЗависитОтРазрешенияИмени(t *testing.T) {
	addr := startSNIServer(t, "nonexistent.invalid")

	if err := waitHealthy(addr, "nonexistent.invalid", 10*time.Second); err != nil {
		t.Fatalf("проверка пошла за DNS вместо петли: %v", err)
	}
}

func TestWaitHealthyСообщаетПричинуОтказа(t *testing.T) {
	// Порт, на котором никто не слушает.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	err = waitHealthy(addr, "proxy.example.com", 2*time.Second)
	if err == nil {
		t.Fatal("молчащий порт не привёл к ошибке")
	}
	if !strings.Contains(err.Error(), "/healthz") {
		t.Errorf("в ошибке нет проверяемого адреса: %v", err)
	}
	// Последняя сетевая ошибка должна быть видна: без неё непонятно,
	// шлюз не поднялся или рукопожатие не состоялось.
	if !strings.Contains(err.Error(), "connect") && !strings.Contains(err.Error(), "refused") {
		t.Errorf("в ошибке нет причины: %v", err)
	}
}
