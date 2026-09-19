package gateway

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/seredavin/claude-proxy/internal/auth"
	"github.com/seredavin/claude-proxy/internal/config"
)

// TestЗависшийАпстримОбрываетсяПоПаузе проверяет то, ради чего существует
// deadlineConn: соединение, замолчавшее посреди уже начатого ответа, должно
// быть разорвано, а не висеть вечно.
func TestЗависшийАпстримОбрываетсяПоПаузе(t *testing.T) {
	const stall = 200 * time.Millisecond

	released := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "event: first\n\n")
		w.(http.Flusher).Flush()

		// Заголовки уже ушли, дальше апстрим замолкает надолго.
		select {
		case <-released:
		case <-time.After(5 * time.Second):
		}
		_, _ = io.WriteString(w, "event: second\n\n")
	}))
	defer func() {
		close(released)
		upstream.Close()
	}()

	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := auth.Parse("default:secret")
	if err != nil {
		t.Fatal(err)
	}

	gw := New(Options{
		Mode:         config.ModeOAuth,
		Tokens:       tokens,
		Upstream:     target,
		MaxBodyBytes: 1 << 20,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Transport:    newTransport(stall, stall),
	})
	front := httptest.NewServer(gw)
	defer front.Close()

	req, err := http.NewRequest(http.MethodPost, front.URL+"/v1/messages", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Gateway-Key", "secret")
	req.Header.Set("Authorization", "Bearer x")

	start := time.Now()
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatalf("заголовки должны были дойти: %v", err)
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	elapsed := time.Since(start)

	if elapsed > 3*time.Second {
		t.Fatalf("чтение заняло %s — пауза в ответе не ограничена", elapsed)
	}
	if strings.Contains(string(body), "second") {
		t.Errorf("ответ дочитался целиком, обрыва не произошло: %q", body)
	}
	if readErr == nil && !strings.Contains(string(body), "first") {
		t.Errorf("первое событие потеряно: %q", body)
	}
}

// TestПростойСоединенияИстекаетРаньшеПаузы защищает рассуждение, на котором
// держится deadlineConn: соединение из пула закрывается по простою прежде,
// чем на нём сработает дедлайн чтения. Иначе каждое переиспользование пула
// натыкалось бы на таймаут и приводило к лишним переподключениям.
func TestПростойСоединенияИстекаетРаньшеПаузы(t *testing.T) {
	if upstreamIdleTimeout >= upstreamStallTimeout {
		t.Fatalf("IdleConnTimeout (%s) должен быть меньше паузы чтения (%s)",
			upstreamIdleTimeout, upstreamStallTimeout)
	}
}
