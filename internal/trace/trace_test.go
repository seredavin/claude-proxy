package trace

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTracer(t *testing.T) (*Tracer, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	tr, err := New(filepath.Join(t.TempDir(), "trace"), Options{Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return tr, &logs
}

func TestПолныйНаборФайлов(t *testing.T) {
	tr, _ := newTracer(t)
	rec := tr.Begin()
	rec.WriteRequest(Client, []byte(`{"a":"10.0.0.5"}`))
	rec.WriteRequest(Upstream, []byte(`{"a":"10.7.3.9"}`))
	_, _ = rec.ResponseWriter(Upstream).Write([]byte("event: x\n\n"))
	_, _ = rec.ResponseWriter(Client).Write([]byte("event: y\n\n"))
	rec.Finish(Meta{Method: "POST", Path: "/v1/messages", Status: 200, Token: "dev",
		RequestHeaders: Headers(http.Header{"Authorization": {"Bearer x"}})})

	entries, err := os.ReadDir(tr.Dir())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
		info, _ := e.Info()
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s: права %o", e.Name(), info.Mode().Perm())
		}
		if !strings.HasPrefix(e.Name(), rec.Prefix()+".") {
			t.Errorf("%s: чужой префикс", e.Name())
		}
	}
	if len(names) != 5 {
		t.Fatalf("файлов %d: %v", len(names), names)
	}
	if info, _ := os.Stat(tr.Dir()); info.Mode().Perm() != 0o700 {
		t.Errorf("каталог: права %o", info.Mode().Perm())
	}

	got, _ := os.ReadFile(filepath.Join(tr.Dir(), rec.Prefix()+".upstream.response"))
	if string(got) != "event: x\n\n" {
		t.Errorf("upstream.response = %q — Finish не сбросил буфер", got)
	}
	metaRaw, _ := os.ReadFile(filepath.Join(tr.Dir(), rec.Prefix()+".meta.json"))
	var meta Meta
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		t.Fatalf("meta: %v", err)
	}
	if meta.Status != 200 || meta.Token != "dev" || meta.Started.IsZero() {
		t.Errorf("meta = %+v", meta)
	}
	if !strings.Contains(string(metaRaw), "\"<redacted>\"") && strings.Contains(string(metaRaw), "u003c") {
		t.Errorf("<redacted> экранирован: %s", metaRaw)
	}
}

func TestПустойОтветДаётПустойФайл(t *testing.T) {
	tr, _ := newTracer(t)
	rec := tr.Begin()
	rec.ResponseWriter(Upstream)
	rec.Finish(Meta{})
	info, err := os.Stat(filepath.Join(tr.Dir(), rec.Prefix()+".upstream.response"))
	if err != nil || info.Size() != 0 {
		t.Errorf("stat = %v, %v", info, err)
	}
	if _, err := os.Stat(filepath.Join(tr.Dir(), rec.Prefix()+".client.response")); !os.IsNotExist(err) {
		t.Errorf("client.response не должен существовать: %v", err)
	}
}

func TestЗаголовкиБезCredential(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer sk-ant-oat01-x")
	h.Set("Proxy-Authorization", "Basic x")
	h.Set("X-Api-Key", "sk-ant-api03-x")
	h.Set("X-Gateway-Key", "abc")
	h.Set("Cookie", "a=b")
	h.Set("Anthropic-Version", "2023-06-01")
	h.Add("Anthropic-Beta", "one")
	h.Add("Anthropic-Beta", "two")
	got := Headers(h)
	for _, k := range []string{"Authorization", "Proxy-Authorization", "X-Api-Key", "X-Gateway-Key", "Cookie"} {
		if got[k] != "<redacted>" {
			t.Errorf("%s = %q", k, got[k])
		}
	}
	if got["Anthropic-Version"] != "2023-06-01" || got["Anthropic-Beta"] != "one, two" {
		t.Errorf("got = %v", got)
	}
	if Headers(nil) != nil {
		t.Error("пустые заголовки должны давать nil")
	}
}

func TestКаталогПропалПредупреждениеНеОшибка(t *testing.T) {
	tr, logs := newTracer(t)
	if err := os.RemoveAll(tr.Dir()); err != nil {
		t.Fatal(err)
	}
	rec := tr.Begin()
	rec.WriteRequest(Client, []byte("x"))
	if n, err := rec.ResponseWriter(Upstream).Write([]byte("y")); n != 1 || err != nil {
		t.Errorf("Write = %d, %v", n, err)
	}
	rec.Finish(Meta{})
	if !strings.Contains(logs.String(), "трасса не записана") {
		t.Errorf("нет предупреждения: %s", logs.String())
	}
}

func TestNewНедоступныйПуть(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(file, "sub")
	_, err := New(bad, Options{})
	if err == nil || !strings.Contains(err.Error(), bad) {
		t.Errorf("err = %v", err)
	}
}
