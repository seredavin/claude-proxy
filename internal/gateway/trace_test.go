package gateway

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/seredavin/claude-proxy/internal/auth"
	"github.com/seredavin/claude-proxy/internal/config"
	"github.com/seredavin/claude-proxy/internal/mask"
	"github.com/seredavin/claude-proxy/internal/trace"
)

// newTracedGateway поднимает шлюз oauth с трассировкой в каталог dir и,
// если rules != "-", с маскированием. handler nil — SSE-эхо тела.
func newTracedGateway(t *testing.T, dir, rules string, handler http.HandlerFunc) (*httptest.Server, *maskedUpstream, *syncBuffer) {
	t.Helper()
	up := &maskedUpstream{}
	if handler == nil {
		handler = func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			body, _ := json.Marshal(up.gotBody)
			_, _ = io.WriteString(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":"+string(body)+"}}\n\n")
		}
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		up.gotBody = string(b)
		up.gotHeader = r.Header.Clone()
		handler(w, r)
	}))
	t.Cleanup(upstream.Close)
	target, _ := url.Parse(upstream.URL)
	set, _ := auth.Parse("dev:secret")
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
	var tracer *trace.Tracer
	if dir != "" {
		var err error
		if tracer, err = trace.New(dir, trace.Options{Logger: logger}); err != nil {
			t.Fatal(err)
		}
	}
	gw := New(Options{
		Mode: config.ModeOAuth, Tokens: set, Upstream: target, MaxBodyBytes: 1 << 20, Logger: logger,
		Masker: masker, MaskOnError: config.MaskClosed, Tracer: tracer,
	})
	front := httptest.NewServer(gw)
	t.Cleanup(front.Close)
	return front, up, logs
}

// traceName — <ts>-<seq>.<file>; в ts есть точка, режем по номеру.
var traceName = regexp.MustCompile(`^(\d{8}T\d{6}\.\d{3}Z-\d{6})\.(.+)$`)

// traceFiles возвращает содержимое файлов трассы по суффиксу; ожидает ровно
// одну трассу в каталоге. meta.json пишется после того, как клиент дочитал
// ответ, поэтому его появления ждём.
func traceFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		files, ok := readTrace(t, dir)
		if ok || time.Now().After(deadline) {
			return files
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func readTrace(t *testing.T, dir string) (map[string]string, bool) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	prefix := ""
	for _, e := range entries {
		m := traceName.FindStringSubmatch(e.Name())
		if m == nil {
			t.Fatalf("неожиданное имя файла %s", e.Name())
		}
		if prefix == "" {
			prefix = m[1]
		} else if m[1] != prefix {
			t.Fatalf("в каталоге больше одной трассы: %s и %s", prefix, m[1])
		}
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		files[m[2]] = string(b)
	}
	_, done := files["meta.json"]
	return files, done
}

func metaOf(t *testing.T, files map[string]string) trace.Meta {
	t.Helper()
	var m trace.Meta
	if err := json.Unmarshal([]byte(files["meta.json"]), &m); err != nil {
		t.Fatalf("meta.json: %v\n%s", err, files["meta.json"])
	}
	return m
}

func TestТрассировкаВыключенаФайловНет(t *testing.T) {
	dir := t.TempDir()
	srv, up, _ := newTracedGateway(t, "", "-", nil)
	resp := postMessages(t, srv, "/v1/messages", "secret", userBody, nil)
	_ = bodyOf(t, resp)
	if up.gotBody != userBody {
		t.Errorf("тело изменено: %s", up.gotBody)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("появились файлы: %v", entries)
	}
}

func TestТрассировкаСМаскированиемДоИПосле(t *testing.T) {
	dir := t.TempDir()
	srv, _, _ := newTracedGateway(t, dir, "host *.corp.local", nil)
	resp := postMessages(t, srv, "/v1/messages?beta=true", "secret", userBody, nil)
	got := bodyOf(t, resp)
	if !strings.Contains(got, "10.0.0.5") {
		t.Fatalf("клиент не получил исходное значение: %s", got)
	}

	files := traceFiles(t, dir)
	if len(files) != 5 {
		t.Fatalf("файлов %d: %v", len(files), files)
	}
	if !strings.Contains(files["client.request"], "10.0.0.5") || !strings.Contains(files["client.request"], "prod-db.corp.local") {
		t.Errorf("client.request без исходных значений: %s", files["client.request"])
	}
	if strings.Contains(files["upstream.request"], "10.0.0.5") || !regexp.MustCompile(`host-\d+\.example`).MatchString(files["upstream.request"]) {
		t.Errorf("upstream.request не замаскирован: %s", files["upstream.request"])
	}
	if strings.Contains(files["upstream.response"], "10.0.0.5") || !strings.HasPrefix(files["upstream.response"], "event: content_block_delta") {
		t.Errorf("upstream.response должен быть SSE с суррогатами: %s", files["upstream.response"])
	}
	if !strings.Contains(files["client.response"], "10.0.0.5") {
		t.Errorf("client.response без исходных значений: %s", files["client.response"])
	}
	m := metaOf(t, files)
	if m.Status != 200 || m.Method != "POST" || m.Path != "/v1/messages" || m.Token != "dev" {
		t.Errorf("meta = %+v", m)
	}
	if m.RequestHeaders["Authorization"] != "<redacted>" || m.RequestHeaders["X-Gateway-Key"] != "" {
		t.Errorf("заголовки запроса: %v", m.RequestHeaders)
	}
	if m.RequestHeaders["Content-Type"] != "application/json" || m.UpstreamHeaders["Content-Type"] != "text/event-stream" {
		t.Errorf("заголовки: req=%v up=%v", m.RequestHeaders, m.UpstreamHeaders)
	}
	if m.Mask == nil || m.Mask.Masked["ip"] != 1 || m.Mask.Masked["host"] != 1 || m.Mask.Unmasked != 2 {
		t.Errorf("mask = %+v", m.Mask)
	}
	if strings.Contains(files["meta.json"], "sk-ant-oat01") || strings.Contains(files["meta.json"], "secret") {
		t.Errorf("credential в meta: %s", files["meta.json"])
	}
}

func TestТрассировкаБезМаскированияКопииСовпадают(t *testing.T) {
	dir := t.TempDir()
	srv, _, _ := newTracedGateway(t, dir, "-", nil)
	_ = bodyOf(t, postMessages(t, srv, "/v1/messages", "secret", userBody, nil))
	files := traceFiles(t, dir)
	if files["client.request"] != userBody || files["upstream.request"] != userBody {
		t.Errorf("копии запроса: %q / %q", files["client.request"], files["upstream.request"])
	}
	if !strings.Contains(files["upstream.response"], "10.0.0.5") || files["upstream.response"] != files["client.response"] {
		t.Errorf("копии ответа: %q / %q", files["upstream.response"], files["client.response"])
	}
	if m := metaOf(t, files); m.Mask != nil {
		t.Errorf("mask в meta без маскирования: %+v", m.Mask)
	}
}

func TestТрассировкаОтвергнутыйЗапрос(t *testing.T) {
	dir := t.TempDir()
	srv, up, _ := newTracedGateway(t, dir, "", nil)
	resp := postMessages(t, srv, "/v1/messages", "secret", "not json", nil)
	if resp.StatusCode != http.StatusBadRequest || up.gotHeader != nil {
		t.Fatalf("status = %d, ушёл наверх = %v", resp.StatusCode, up.gotHeader != nil)
	}
	_ = bodyOf(t, resp)
	files := traceFiles(t, dir)
	if len(files) != 3 || files["client.request"] != "not json" || !strings.Contains(files["client.response"], "could not mask") {
		t.Errorf("files = %v", files)
	}
	if m := metaOf(t, files); m.Status != 400 || m.UpstreamHeaders != nil {
		t.Errorf("meta = %+v", m)
	}
}

func TestТрассировкаОтказПоРазмеру(t *testing.T) {
	dir := t.TempDir()
	srv, _, _ := newTracedGateway(t, dir, "-", nil)
	big := strings.Repeat("x", 2<<20)
	resp := postMessages(t, srv, "/v1/messages", "secret", big, nil)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	_ = bodyOf(t, resp)
	files := traceFiles(t, dir)
	if _, ok := files["client.request"]; ok || len(files) != 2 {
		t.Errorf("files = %v", keysOf(files))
	}
	if m := metaOf(t, files); m.Status != 413 {
		t.Errorf("meta = %+v", m)
	}
}

func TestТрассировкаПустойОтветАпстрима(t *testing.T) {
	dir := t.TempDir()
	srv, _, _ := newTracedGateway(t, dir, "-", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	_ = bodyOf(t, postMessages(t, srv, "/v1/messages", "secret", userBody, nil))
	files := traceFiles(t, dir)
	if v, ok := files["upstream.response"]; !ok || v != "" {
		t.Errorf("upstream.response = %q, ok=%v", v, ok)
	}
	if v, ok := files["client.response"]; !ok || v != "" {
		t.Errorf("client.response = %q, ok=%v", v, ok)
	}
}

func TestТрассировкаSSEНеБуферизуется(t *testing.T) {
	dir := t.TempDir()
	release := make(chan struct{})
	srv, _, _ := newTracedGateway(t, dir, "", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "event: message_start\ndata: {\"type\":\"message_start\"}\n\n")
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	})
	resp := postMessages(t, srv, "/v1/messages", "secret", userBody, nil)
	got := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(resp.Body).ReadString('\n')
		got <- line
	}()
	select {
	case line := <-got:
		if !strings.Contains(line, "message_start") {
			t.Errorf("first = %q", line)
		}
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("первое событие не дошло — трассировка буферизует ответ")
	}
	close(release)
	_ = bodyOf(t, resp)
}

func keysOf(m map[string]string) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
