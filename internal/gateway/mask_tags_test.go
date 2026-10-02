package gateway

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/seredavin/claude-proxy/internal/auth"
	"github.com/seredavin/claude-proxy/internal/config"
	"github.com/seredavin/claude-proxy/internal/mask"
)

// Сквозная проверка режима меток: апстрим видит только метки, клиент
// получает исходные значения из SSE-эха.
func TestМаскированиеМеткамиRoundTrip(t *testing.T) {
	var gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "text/event-stream")
		echo, _ := json.Marshal(gotBody)
		_, _ = io.WriteString(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":"+string(echo)+"}}\n\n")
		_, _ = io.WriteString(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	}))
	t.Cleanup(upstream.Close)
	target, _ := url.Parse(upstream.URL)
	set, _ := auth.Parse("default:secret")
	rules, _ := mask.ParseRules(strings.NewReader("host *.corp.local"), "rules")
	key, err := mask.NewKey(make([]byte, mask.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	gw := New(Options{
		Mode: config.ModeOAuth, Tokens: set, Upstream: target, MaxBodyBytes: 1 << 20, Logger: logger,
		Masker:      mask.NewRegistry(rules, mask.Options{Logger: logger, Key: key, Tags: true}),
		MaskOnError: config.MaskClosed,
	})
	front := httptest.NewServer(gw)
	t.Cleanup(front.Close)

	ghp := "ghp_" + strings.Repeat("Ab12", 9)
	body := `{"model":"claude","messages":[{"role":"user","content":"ssh prod-db.corp.local with ` + ghp + `"}]}`
	resp := postMessages(t, front, "/v1/messages", "secret", body, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !regexp.MustCompile(`ssh <<m:host:[a-z2-7]+>> with <<m:secret:[a-z2-7]+>>`).MatchString(gotBody) {
		t.Errorf("апстрим получил не метки: %s", gotBody)
	}
	for _, leak := range []string{"prod-db", "corp.local", "ghp_"} {
		if strings.Contains(gotBody, leak) {
			t.Errorf("апстрим увидел %q: %s", leak, gotBody)
		}
	}
	got, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(got), "ssh prod-db.corp.local with "+ghp) {
		t.Errorf("клиент не получил исходные значения: %s", got)
	}
}
