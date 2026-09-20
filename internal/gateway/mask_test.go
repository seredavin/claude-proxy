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

// maskedUpstream — заглушка Anthropic, запоминающая тело и заголовки.
type maskedUpstream struct {
	gotBody   string
	gotHeader http.Header
}

// newMaskedGateway поднимает шлюз oauth с маскированием. rules — текст
// файла правил; handler отвечает за апстрим (nil — SSE-эхо тела в text_delta).
func newMaskedGateway(t *testing.T, tokens, rules string, policy config.MaskPolicy, upstreamKey string,
	handler http.HandlerFunc) (*httptest.Server, *maskedUpstream, *syncBuffer) {
	t.Helper()
	up := &maskedUpstream{}
	if handler == nil {
		handler = func(w http.ResponseWriter, r *http.Request) {
			// Модель «повторяет» текст запроса: то, что увидел апстрим,
			// уходит обратно в text_delta и в tool_use.
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			body, _ := json.Marshal(up.gotBody)
			_, _ = io.WriteString(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":"+string(body)+"}}\n\n")
			_, _ = io.WriteString(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		}
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		up.gotBody = string(b)
		up.gotHeader = r.Header.Clone()
		r.Body = io.NopCloser(strings.NewReader(up.gotBody)) // handler может прочитать снова
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
	logger := slog.New(slog.NewTextHandler(logs, nil))

	var masker *mask.Registry
	if rules != "-" {
		parsed, err := mask.ParseRules(strings.NewReader(rules), "rules")
		if err != nil {
			t.Fatal(err)
		}
		masker = mask.NewRegistry(parsed, mask.Options{Logger: logger})
	}

	gw := New(Options{
		Mode:         config.ModeOAuth,
		Tokens:       set,
		Upstream:     target,
		UpstreamKey:  upstreamKey,
		MaxBodyBytes: 1 << 20,
		Logger:       logger,
		Masker:       masker,
		MaskOnError:  policy,
	})
	front := httptest.NewServer(gw)
	t.Cleanup(front.Close)
	return front, up, logs
}

func postMessages(t *testing.T, srv *httptest.Server, path, key, body string, extra http.Header) *http.Response {
	t.Helper()
	h := http.Header{"X-Gateway-Key": {key}, "Authorization": {"Bearer sk-ant-oat01-token"}, "Content-Type": {"application/json"}}
	for k, v := range extra {
		h[k] = v
	}
	return do(t, srv, http.MethodPost, path, h, body)
}

const userBody = `{"model":"claude","messages":[{"role":"user","content":"ssh admin@10.0.0.5 via prod-db.corp.local"}]}`

func TestМаскированиеВыключеноТелоБайтВБайт(t *testing.T) {
	srv, up, _ := newMaskedGateway(t, "default:secret", "-", config.MaskClosed, "", nil)
	resp := postMessages(t, srv, "/v1/messages", "secret", userBody, nil)
	if resp.StatusCode != http.StatusOK || up.gotBody != userBody {
		t.Errorf("status = %d body = %s", resp.StatusCode, up.gotBody)
	}
}

func TestМаскированиеRoundTripЧерезSSE(t *testing.T) {
	srv, up, logs := newMaskedGateway(t, "default:secret", "host *.corp.local", config.MaskClosed, "", nil)
	resp := postMessages(t, srv, "/v1/messages", "secret", userBody, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if strings.Contains(up.gotBody, "10.0.0.5") || strings.Contains(up.gotBody, "prod-db.corp.local") {
		t.Errorf("апстрим увидел настоящие значения: %s", up.gotBody)
	}
	if !regexp.MustCompile(`ssh admin@10\.\d+\.\d+\.\d+ via host-\d+\.example`).MatchString(up.gotBody) {
		t.Errorf("суррогаты не той формы: %s", up.gotBody)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("чтение ответа: %v\nлог: %s", err, logs.String())
	}
	if !strings.Contains(string(got), `ssh admin@10.0.0.5 via prod-db.corp.local`) {
		t.Errorf("клиент не получил исходные значения: %s", got)
	}
	if !logs.waitFor("mask_ip=1") {
		t.Fatalf("нет счётчиков в логе: %s", logs.String())
	}
	line := logs.String()
	if !strings.Contains(line, "mask_host=1") || !strings.Contains(line, "unmasked=2") {
		t.Errorf("счётчики: %s", line)
	}
	if strings.Contains(line, "10.0.0.5") || strings.Contains(line, "prod-db") {
		t.Errorf("значения попали в лог: %s", line)
	}
}

func TestМаскированиеCountTokensИЗаголовки(t *testing.T) {
	srv, up, _ := newMaskedGateway(t, "default:secret", "", config.MaskClosed, "", nil)
	resp := postMessages(t, srv, "/v1/messages/count_tokens", "secret",
		`{"messages":[{"role":"user","content":"sk-ant-oat01-token lives at 10.0.0.5"}]}`,
		http.Header{"Accept-Encoding": {"gzip, br"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if strings.Contains(up.gotBody, "10.0.0.5") {
		t.Errorf("count_tokens не замаскирован: %s", up.gotBody)
	}
	if got := up.gotHeader.Get("Authorization"); got != "Bearer sk-ant-oat01-token" {
		t.Errorf("Authorization изменён: %q", got)
	}
	if got := up.gotHeader.Get("Accept-Encoding"); got != "" && got != "gzip" {
		// Пусто или «gzip» от транспорта — но не клиентский список с br.
		t.Errorf("Accept-Encoding клиента ушёл апстриму: %q", got)
	}
}

func TestМаскированиеПолитикаСбоя(t *testing.T) {
	closed, upClosed, _ := newMaskedGateway(t, "default:secret", "", config.MaskClosed, "", nil)
	resp := postMessages(t, closed, "/v1/messages", "secret", "not json", nil)
	if resp.StatusCode != http.StatusBadRequest || upClosed.gotHeader != nil {
		t.Errorf("closed: status = %d, ушёл наверх = %v", resp.StatusCode, upClosed.gotHeader != nil)
	}
	if got := bodyOf(t, resp); !strings.Contains(got, "invalid_request_error") || !strings.Contains(got, "could not mask") {
		t.Errorf("closed: тело = %s", got)
	}

	open, upOpen, logs := newMaskedGateway(t, "default:secret", "", config.MaskOpen, "", nil)
	resp = postMessages(t, open, "/v1/messages", "secret", "not json", nil)
	if resp.StatusCode != http.StatusOK || upOpen.gotBody != "not json" {
		t.Errorf("open: status = %d body = %q", resp.StatusCode, upOpen.gotBody)
	}
	if !logs.waitFor("отправлено как есть") {
		t.Errorf("open: нет предупреждения в логе")
	}
}

func TestМаскированиеНеразобранныйОтветПроходит(t *testing.T) {
	srv, _, logs := newMaskedGateway(t, "default:secret", "", config.MaskClosed, "",
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, "<html>bad gateway</html>")
		})
	resp := postMessages(t, srv, "/v1/messages", "secret", userBody, nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if got := bodyOf(t, resp); got != "<html>bad gateway</html>" {
		t.Errorf("тело изменено: %q", got)
	}
	if !logs.waitFor("unmask_errors=1") {
		t.Errorf("нет счётчика сбоя: %s", logs.String())
	}
}

func TestМаскированиеJSONОтветДемаскируется(t *testing.T) {
	srv, _, _ := newMaskedGateway(t, "default:secret", "host *.corp.local", config.MaskClosed, "",
		func(w http.ResponseWriter, r *http.Request) {
			// Не-SSE ответ: модель повторяет текст запроса целиком.
			b, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(append(append([]byte(`{"content":[{"type":"text","text":`), mustJSON(string(b))...), []byte(`}]}`)...))
		})
	resp := postMessages(t, srv, "/v1/messages", "secret", userBody, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	got := bodyOf(t, resp)
	if !strings.Contains(got, "ssh admin@10.0.0.5 via prod-db.corp.local") {
		t.Errorf("JSON-ответ не демаскирован: %s", got)
	}
	if resp.ContentLength != int64(len(got)) {
		t.Errorf("Content-Length %d != %d", resp.ContentLength, len(got))
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func TestМаскированиеИзоляцияМеток(t *testing.T) {
	srv, up, _ := newMaskedGateway(t, "dev:one,analytics:two", "host *.corp.local", config.MaskClosed, "", nil)
	resp := postMessages(t, srv, "/v1/messages", "one", userBody, nil)
	_ = bodyOf(t, resp)
	sur := regexp.MustCompile(`host-\d+\.example`).FindString(up.gotBody)
	if sur == "" {
		t.Fatalf("суррогата нет: %s", up.gotBody)
	}
	// Клиент другой метки присылает чужой суррогат — обратно он не
	// подставляется ни в запросе, ни в ответе.
	resp = postMessages(t, srv, "/v1/messages", "two",
		`{"messages":[{"role":"user","content":"see `+sur+`"}]}`, nil)
	if got := bodyOf(t, resp); !strings.Contains(got, sur) || strings.Contains(got, "prod-db") {
		t.Errorf("суррогат чужой метки раскрыт: %s", got)
	}
}

func TestМаскированиеЦепочкаИзДвухЗвеньев(t *testing.T) {
	outer, upOuter, _ := newMaskedGateway(t, "outer:key-outer", "host *.corp.local", config.MaskClosed, "", nil)
	outerURL, _ := url.Parse(outer.URL)

	// Внутреннее звено: апстрим — внешнее звено, оба маскируют.
	set, _ := auth.Parse("inner:key-inner")
	rules, _ := mask.ParseRules(strings.NewReader("host *.corp.local"), "rules")
	logs := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	inner := httptest.NewServer(New(Options{
		Mode: config.ModeOAuth, Tokens: set, Upstream: outerURL, UpstreamKey: "key-outer",
		MaxBodyBytes: 1 << 20, Logger: logger,
		Masker: mask.NewRegistry(rules, mask.Options{Logger: logger}), MaskOnError: config.MaskClosed,
	}))
	t.Cleanup(inner.Close)

	resp := postMessages(t, inner, "/v1/messages", "key-inner", userBody, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if strings.Contains(upOuter.gotBody, "10.0.0.5") || strings.Contains(upOuter.gotBody, "prod-db") {
		t.Errorf("конечный апстрим увидел настоящие значения: %s", upOuter.gotBody)
	}
	if got := bodyOf(t, resp); !strings.Contains(got, "ssh admin@10.0.0.5 via prod-db.corp.local") {
		t.Errorf("round-trip через два звена сломан: %s", got)
	}
}
