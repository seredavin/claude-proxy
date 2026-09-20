package gateway

import (
	"log/slog"
	"net"
	"net/http"
	"time"
)

// statusClientClosed — клиент отсоединился, не дождавшись ответа.
// Кода в HTTP для этого нет, 499 заимствован у nginx и живёт только в логе.
const statusClientClosed = 499

// recorder запоминает статус и объём ответа для access-лога.
//
// Тела не касается: ни заголовки, ни токены в лог не попадают.
type recorder struct {
	http.ResponseWriter
	status      int
	written     int64
	wroteHeader bool
	// mask — счётчики маскирования; nil, когда оно выключено.
	mask *maskState
}

func (r *recorder) WriteHeader(status int) {
	if r.wroteHeader {
		return
	}
	r.wroteHeader = true
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *recorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(b)
	r.written += int64(n)
	return n, err
}

// Unwrap открывает http.ResponseController доступ к Flush нижележащего
// writer'а. Без него ReverseProxy не сможет сбрасывать буфер и сломается SSE.
func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// logAccess пишет одну строку на запрос.
//
// Заголовков в ней нет умышленно: токен шлюза, Authorization и x-api-key
// не должны оказаться в логах. От токена остаётся только метка.
func (g *Gateway) logAccess(rec *recorder, r *http.Request, start time.Time, tokenLabel string) {
	attrs := []any{
		"remote", remoteIP(r),
		"method", r.Method,
		"path", r.URL.Path,
		"status", rec.status,
		"bytes", rec.written,
		"dur_ms", time.Since(start).Milliseconds(),
	}
	if tokenLabel != "" {
		attrs = append(attrs, "token", tokenLabel)
	}
	// Только счётчики: ни значений, ни суррогатов.
	if rec.mask != nil {
		st := rec.mask.counters()
		for _, category := range st.Categories() {
			attrs = append(attrs, "mask_"+category, st.Masked[category])
		}
		if st.Unmasked > 0 {
			attrs = append(attrs, "unmasked", st.Unmasked)
		}
		if st.Errors > 0 {
			attrs = append(attrs, "unmask_errors", st.Errors)
		}
	}

	level := slog.LevelInfo
	if rec.status >= http.StatusInternalServerError {
		level = slog.LevelError
	}
	g.log.Log(r.Context(), level, "request", attrs...)
}

// remoteIP отбрасывает порт: в логе он только шумит.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
