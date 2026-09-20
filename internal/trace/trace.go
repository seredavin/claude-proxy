// Package trace пишет тела запросов и ответов шлюза в каталог — по набору
// файлов на запрос, чтобы увидеть, что именно ушло на апстрим и что
// вернулось. Режим отладки: лимитов и ротации нет, ошибки записи
// логируются и не влияют на проксирование.
package trace

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Side — сторона обмена: от клиента / клиенту или на апстрим / от апстрима.
type Side string

const (
	Client   Side = "client"
	Upstream Side = "upstream"
)

// Options — настройки трассировщика.
type Options struct {
	Logger *slog.Logger
}

// Tracer — каталог трассировки и счётчик запросов.
type Tracer struct {
	dir string
	log *slog.Logger
	seq atomic.Uint64
}

// New создаёт каталог (0700) и проверяет, что в него можно писать.
func New(dir string, opts Options) (*Tracer, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("каталог трассировки %s: %w", dir, err)
	}
	probe, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return nil, fmt.Errorf("каталог трассировки %s недоступен для записи: %w", dir, err)
	}
	_ = probe.Close()
	_ = os.Remove(probe.Name())
	return &Tracer{dir: dir, log: opts.Logger}, nil
}

// Dir — каталог трассировки.
func (t *Tracer) Dir() string { return t.dir }

// Begin открывает трассу нового запроса.
func (t *Tracer) Begin() *Record {
	now := time.Now().UTC()
	return &Record{
		tracer:  t,
		started: now,
		prefix:  fmt.Sprintf("%s-%06d", now.Format("20060102T150405.000Z"), t.seq.Add(1)),
		writers: map[Side]*bufio.Writer{},
		files:   map[Side]*os.File{},
	}
}

// Record — трасса одного запроса.
type Record struct {
	tracer  *Tracer
	started time.Time
	prefix  string

	mu      sync.Mutex
	writers map[Side]*bufio.Writer
	files   map[Side]*os.File
	// failed — на стороне уже была ошибка записи; повторно не шумим.
	failed map[Side]bool
}

// Started — момент начала запроса.
func (r *Record) Started() time.Time { return r.started }

// Prefix — общий префикс файлов трассы.
func (r *Record) Prefix() string { return r.prefix }

func (r *Record) path(name string) string {
	return filepath.Join(r.tracer.dir, r.prefix+"."+name)
}

// WriteRequest пишет тело запроса стороны целиком.
func (r *Record) WriteRequest(side Side, body []byte) {
	if err := os.WriteFile(r.path(string(side)+".request"), body, 0o600); err != nil {
		r.warn(side, "request", err)
	}
}

// ResponseWriter — writer тела ответа стороны. Файл создаётся сразу,
// даже если байтов не будет: пустой файл значит «ответ был, тело пустое»,
// а отсутствие файла — «до этой стороны не дошло». Закрывает Finish.
func (r *Record) ResponseWriter(side Side) *ResponseWriter {
	r.mu.Lock()
	defer r.mu.Unlock()
	if w, ok := r.writers[side]; ok {
		return &ResponseWriter{rec: r, side: side, w: w}
	}
	f, err := os.OpenFile(r.path(string(side)+".response"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		r.warnLocked(side, "response", err)
		return &ResponseWriter{rec: r, side: side}
	}
	w := bufio.NewWriterSize(f, 64*1024)
	r.files[side] = f
	r.writers[side] = w
	return &ResponseWriter{rec: r, side: side, w: w}
}

// ResponseWriter пишет байты ответа в файл трассы; ошибки глотает.
type ResponseWriter struct {
	rec  *Record
	side Side
	w    *bufio.Writer
}

// Write всегда сообщает об успехе: трасса не должна ломать поток.
func (w *ResponseWriter) Write(p []byte) (int, error) {
	if w.w != nil {
		w.rec.mu.Lock()
		_, err := w.w.Write(p)
		w.rec.mu.Unlock()
		if err != nil {
			w.rec.warn(w.side, "response", err)
		}
	}
	return len(p), nil
}

// Meta — сводка запроса для meta.json.
type Meta struct {
	Started        time.Time         `json:"started"`
	DurationMs     int64             `json:"duration_ms"`
	Method         string            `json:"method"`
	Path           string            `json:"path"`
	Status         int               `json:"status"`
	Token          string            `json:"token,omitempty"`
	RequestHeaders map[string]string `json:"request_headers,omitempty"`
	// UpstreamHeaders — заголовки ответа апстрима; nil, если апстрим не вызывался.
	UpstreamHeaders map[string]string `json:"upstream_headers,omitempty"`
	Mask            *MaskMeta         `json:"mask,omitempty"`
}

// MaskMeta — счётчики маскирования, если оно включено.
type MaskMeta struct {
	Masked   map[string]int `json:"masked,omitempty"`
	Unmasked int            `json:"unmasked"`
	Errors   int            `json:"errors"`
}

// Finish закрывает файлы ответов и пишет meta.json. Вызывается один раз.
func (r *Record) Finish(meta Meta) {
	r.mu.Lock()
	for side, w := range r.writers {
		if err := w.Flush(); err != nil {
			r.warnLocked(side, "response", err)
		}
		_ = r.files[side].Close()
	}
	r.writers = map[Side]*bufio.Writer{}
	r.files = map[Side]*os.File{}
	r.mu.Unlock()

	meta.Started = r.started
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // <redacted> должен читаться глазами
	enc.SetIndent("", "  ")
	if err := enc.Encode(meta); err != nil {
		r.warn("", "meta", err)
		return
	}
	if err := os.WriteFile(r.path("meta.json"), buf.Bytes(), 0o600); err != nil {
		r.warn("", "meta", err)
	}
}

// redactedHeaders — заголовки, несущие credential или сессию.
var redactedHeaders = map[string]bool{
	"Authorization": true, "Proxy-Authorization": true, "X-Api-Key": true,
	"X-Gateway-Key": true, "Cookie": true, "Set-Cookie": true,
}

// Headers переводит заголовки в плоскую карту, пряча credential'ы.
// Повторяющиеся значения склеиваются через «, ».
func Headers(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, vs := range h {
		key := http.CanonicalHeaderKey(k)
		if redactedHeaders[key] {
			out[key] = "<redacted>"
			continue
		}
		joined := ""
		for i, v := range vs {
			if i > 0 {
				joined += ", "
			}
			joined += v
		}
		out[key] = joined
	}
	return out
}

func (r *Record) warn(side Side, what string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.warnLocked(side, what, err)
}

func (r *Record) warnLocked(side Side, what string, err error) {
	if r.failed == nil {
		r.failed = map[Side]bool{}
	}
	key := Side(string(side) + "/" + what)
	if r.failed[key] {
		return
	}
	r.failed[key] = true
	r.tracer.log.Warn("трасса не записана", "prefix", r.prefix, "side", string(side), "file", what, "err", err)
}
