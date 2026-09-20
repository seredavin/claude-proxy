// Package gateway реализует HTTP-слой шлюза: проверку токена, зачистку
// заголовков и проксирование в Anthropic API.
//
// Поведение повторяет прежние nginx-шаблоны: те же коды и тексты ошибок,
// те же таймауты, отключённая буферизация ради SSE.
package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/seredavin/claude-proxy/internal/auth"
	"github.com/seredavin/claude-proxy/internal/config"
	"github.com/seredavin/claude-proxy/internal/mask"
	"github.com/seredavin/claude-proxy/internal/trace"
)

// Таймауты общения с Anthropic. Длинные генерации на дефолтных 60s рвутся.
const (
	upstreamConnectTimeout = 30 * time.Second
	// Предел ожидания заголовков ответа — время до первого байта.
	upstreamResponseTimeout = 600 * time.Second
	// Предел паузы внутри уже начатой передачи. Отсчитывается заново после
	// каждого успешного чтения или записи, поэтому не ограничивает длину
	// стрима — только молчание в нём.
	upstreamStallTimeout = 600 * time.Second
	upstreamIdleTimeout  = 90 * time.Second
)

// Options — всё, что нужно шлюзу для работы.
type Options struct {
	Mode     config.Mode
	Tokens   auth.Set
	APIKey   string
	Upstream *url.URL
	// UpstreamKey — пропуск на следующий шлюз цепочки. Пусто — апстрим
	// Anthropic, подставлять нечего.
	UpstreamKey  string
	MaxBodyBytes int64
	Logger       *slog.Logger

	// Masker — реестр таблиц маскирования. nil — тела не читаются и не
	// меняются. MaskOnError — что делать с телом, которое не разобралось.
	Masker      *mask.Registry
	MaskOnError config.MaskPolicy

	// Tracer — трассировка тел в каталог. nil — выключена.
	Tracer *trace.Tracer

	// Transport подменяется в тестах. Пустое значение — транспорт по умолчанию.
	Transport http.RoundTripper
}

// Gateway — http.Handler шлюза.
type Gateway struct {
	mode     config.Mode
	tokens   auth.Set
	apiKey   string
	upstream *url.URL
	maxBody  int64
	log      *slog.Logger
	proxy    *httputil.ReverseProxy

	masker      *mask.Registry
	maskOnError config.MaskPolicy
	tracer      *trace.Tracer
}

// New собирает шлюз.
func New(opts Options) *Gateway {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	transport := opts.Transport
	if transport == nil {
		transport = NewTransport()
	}

	g := &Gateway{
		mode:        opts.Mode,
		tokens:      opts.Tokens,
		apiKey:      opts.APIKey,
		upstream:    opts.Upstream,
		maxBody:     opts.MaxBodyBytes,
		log:         opts.Logger,
		masker:      opts.Masker,
		maskOnError: opts.MaskOnError,
		tracer:      opts.Tracer,
	}

	g.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(opts.Upstream)
			// SetURL не трогает заголовок Host, а Anthropic обязан увидеть свой.
			pr.Out.Host = opts.Upstream.Host

			// Внутренняя топология наружу не уходит: клиентские
			// X-Forwarded-* отбрасываем и своих не добавляем.
			for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded"} {
				pr.Out.Header.Del(h)
			}

			// Пропуск на этот шлюз наверх не уходит ни в одном режиме: в oauth
			// он уже проверен, в apikey — не проверялся и наверху не нужен.
			// Если апстрим — следующее звено цепочки, вместо него подставляется
			// его собственный пропуск.
			pr.Out.Header.Del("X-Gateway-Key")
			if opts.UpstreamKey != "" {
				pr.Out.Header.Set("X-Gateway-Key", opts.UpstreamKey)
			}

			// Демаскировать сжатый ответ нельзя. Без заголовка клиента
			// транспорт сам попросит gzip и прозрачно распакует.
			if opts.Masker != nil {
				pr.Out.Header.Del("Accept-Encoding")
			}

			// Заголовки к апстриму — в трассу уже после зачистки.
			if ts, _ := pr.Out.Context().Value(traceStateKey{}).(*traceState); ts != nil {
				ts.requestHeaders = trace.Headers(pr.Out.Header)
			}
		},
		ModifyResponse: g.modifyResponse,
		// -1 — писать клиенту сразу, не накапливая буфер. Без этого ломается
		// SSE: ответ приходит одним куском в конце генерации.
		FlushInterval: -1,
		Transport:     transport,
		ErrorHandler:  g.handleUpstreamError,
		// Без этого ошибки копирования тела уходят в стандартный логгер мимо
		// структурированного вывода — в journal они выглядели бы чужеродно.
		ErrorLog: slog.NewLogLogger(opts.Logger.Handler(), slog.LevelWarn),
	}

	return g
}

// NewTransport создаёт транспорт до Anthropic.
//
// Сертификат апстрима проверяется по системным корням (поведение Go по
// умолчанию). Proxy берётся из HTTPS_PROXY/NO_PROXY — на случай, когда
// исход наружу разрешён только через корпоративный прокси.
func NewTransport() *http.Transport {
	return newTransport(upstreamStallTimeout, upstreamStallTimeout)
}

// newTransport вынесен отдельно ради тестов: им нужны короткие таймауты.
func newTransport(readStall, writeStall time.Duration) *http.Transport {
	dialer := &net.Dialer{
		Timeout:   upstreamConnectTimeout,
		KeepAlive: 30 * time.Second,
	}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialWithDeadlines(dialer, readStall, writeStall),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       upstreamIdleTimeout,
		TLSHandshakeTimeout:   upstreamConnectTimeout,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: upstreamResponseTimeout,
	}
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &recorder{ResponseWriter: w, status: http.StatusOK}

	// Проверка здоровья и префлайт отвечают без авторизации и не пишутся в access-лог.
	switch {
	case r.URL.Path == "/healthz":
		writeOK(rec)
		return

	// Claude Code при старте зондирует корень БЕЗ токена шлюза. Ответ 401
	// клиент считает недоступностью шлюза и падает с «Unable to connect»
	// ещё до первого запроса, поэтому корень отвечает 200 всем.
	case r.URL.Path == "/":
		writeOK(rec)
		return
	}

	label, ok := g.authorize(rec, r)
	if !ok {
		g.logAccess(rec, r, start, label)
		return
	}

	// Трасса начинается до проверки предела тела: отказ 413 тоже должен
	// оставить meta.json и тело ответа.
	if g.tracer != nil {
		rec.trace = &traceState{rec: g.tracer.Begin()}
		r = r.WithContext(context.WithValue(r.Context(), traceStateKey{}, rec.trace))
	}

	if g.maxBody > 0 {
		if r.ContentLength > g.maxBody {
			writeError(rec, http.StatusRequestEntityTooLarge, "request_too_large",
				fmt.Sprintf("request body exceeds gateway limit of %d bytes", g.maxBody))
			g.logAccess(rec, r, start, label)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, g.maxBody)
	}

	// Тело читается целиком только когда его надо переписать или записать.
	if g.masker != nil || rec.trace != nil {
		body, ok := g.readBody(rec, r)
		if !ok {
			g.logAccess(rec, r, start, label)
			return
		}
		if rec.trace != nil {
			rec.trace.rec.WriteRequest(trace.Client, body)
		}
		if g.masker != nil {
			state := &maskState{session: g.masker.Session(label)}
			rec.mask = state
			r = r.WithContext(context.WithValue(r.Context(), maskStateKey{}, state))
			if body, ok = g.maskBody(rec, state, body); !ok {
				g.logAccess(rec, r, start, label)
				return
			}
		}
		setBody(r, body)
		if rec.trace != nil {
			rec.trace.rec.WriteRequest(trace.Upstream, body)
		}
	}

	g.proxy.ServeHTTP(rec, r)
	g.logAccess(rec, r, start, label)
}

// traceStateKey — ключ контекста, по которому Rewrite и ModifyResponse
// находят трассу запроса.
type traceStateKey struct{}

// traceState — трасса одного запроса и заголовки, собранные по пути.
type traceState struct {
	rec             *trace.Record
	requestHeaders  map[string]string
	upstreamHeaders map[string]string
	// clientOut — writer тела ответа клиенту; создаётся при первом
	// WriteHeader, чтобы пустой ответ тоже оставил файл.
	clientOut *trace.ResponseWriter
}

// readBody читает тело запроса целиком. false — запрос завершён ошибкой.
func (g *Gateway) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, true
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// MaxBytesReader уже пометил соединение на закрытие; прочие ошибки
		// чтения — клиент оборвал передачу.
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request_too_large",
				fmt.Sprintf("request body exceeds gateway limit of %d bytes", g.maxBody))
		} else {
			writeError(w, http.StatusBadRequest, "invalid_request_error", "gateway could not read request body")
		}
		return nil, false
	}
	return body, true
}

// setBody подменяет тело запроса прочитанными байтами.
func setBody(r *http.Request, body []byte) {
	if len(body) == 0 {
		r.Body = http.NoBody
		r.ContentLength = 0
		r.Header.Del("Content-Length")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))
}

// maskStateKey — ключ контекста, по которому ModifyResponse находит
// таблицу и счётчики запроса.
type maskStateKey struct{}

// maskState — маскирование одного запроса: таблица метки, счётчики запроса
// и поток ответа (его счётчики читаются после завершения проксирования).
type maskState struct {
	session *mask.Session
	stats   mask.Stats
	stream  *mask.Stream
}

// counters — итоговые счётчики запроса и ответа для access-лога.
func (m *maskState) counters() mask.Stats {
	st := m.stats
	if m.stream != nil {
		s := m.stream.Stats()
		st.Unmasked += s.Unmasked
		st.Errors += s.Errors
	}
	return st
}

// maskBody маскирует прочитанное тело. Возвращает байты для апстрима;
// false — запрос завершён ошибкой и на апстрим не идёт.
func (g *Gateway) maskBody(w http.ResponseWriter, state *maskState, body []byte) ([]byte, bool) {
	if len(body) == 0 {
		return body, true
	}
	masked, stats, err := state.session.MaskRequest(body)
	if err != nil {
		if g.maskOnError == config.MaskOpen {
			g.log.Warn("тело не замаскировано, отправлено как есть", "token", state.session.Label(), "err", err)
			return body, true
		}
		g.log.Warn("тело не замаскировано, запрос отклонён", "token", state.session.Label(), "err", err)
		writeError(w, http.StatusBadRequest, "invalid_request_error",
			"gateway could not mask request: "+err.Error())
		return nil, false
	}
	state.stats = stats
	return masked, true
}

// modifyResponse — трасса ответа апстрима (до демаскирования, байт в байт),
// затем демаскирование.
func (g *Gateway) modifyResponse(resp *http.Response) error {
	if ts, _ := resp.Request.Context().Value(traceStateKey{}).(*traceState); ts != nil {
		ts.upstreamHeaders = trace.Headers(resp.Header)
		resp.Body = readCloser{
			Reader: io.TeeReader(resp.Body, ts.rec.ResponseWriter(trace.Upstream)),
			Closer: resp.Body,
		}
	}
	return g.unmaskResponse(resp)
}

// readCloser — TeeReader с исходным Close: закрывать тело апстрима должен
// прокси, а не трасса.
type readCloser struct {
	io.Reader
	io.Closer
}

// unmaskResponse возвращает исходные значения в ответ апстрима. Сбой
// разбора никогда не блокирует ответ: в эту сторону утечки быть не может.
func (g *Gateway) unmaskResponse(resp *http.Response) error {
	state, _ := resp.Request.Context().Value(maskStateKey{}).(*maskState)
	if state == nil {
		return nil
	}
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch mediaType {
	case "text/event-stream":
		state.stream = state.session.UnmaskStream(resp.Body)
		resp.Body = state.stream
		// Длина потока после подстановки другая; SSE и так идёт chunked.
		resp.ContentLength = -1
		resp.Header.Del("Content-Length")
	case "application/json":
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return err
		}
		out, n, uerr := state.session.UnmaskJSON(body)
		if uerr != nil {
			g.log.Warn("ответ не разобрался, передан как есть", "token", state.session.Label(), "err", uerr)
			state.stats.Errors++
			out = body
		} else {
			state.stats.Unmasked += n
		}
		resp.Body = io.NopCloser(bytes.NewReader(out))
		resp.ContentLength = int64(len(out))
		resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	}
	return nil
}

// authorize проверяет пропуск на шлюз и готовит заголовки для апстрима.
// Возвращает метку сработавшего токена.
func (g *Gateway) authorize(w http.ResponseWriter, r *http.Request) (label string, ok bool) {
	switch g.mode {
	case config.ModeAPIKey:
		// Пропуск на шлюз приезжает в Authorization: Bearer <token>,
		// ключ Console подставляет сам шлюз.
		label, ok = g.tokens.Lookup(bearerToken(r.Header.Get("Authorization")))
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication_error", "invalid gateway token")
			return "", false
		}
		r.Header.Del("Authorization")
		r.Header.Set("X-Api-Key", g.apiKey)
		return label, true

	default: // config.ModeOAuth
		label, ok = g.tokens.Lookup(r.Header.Get("X-Gateway-Key"))
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication_error", "invalid gateway key")
			return "", false
		}
		// Credential Anthropic обязателен: без него ответил бы уже Anthropic,
		// а его 401 клиент трактует как недоступность шлюза. X-Api-Key тоже
		// считается credential'ом — его подставляет предыдущее звено цепочки,
		// работающее в режиме apikey.
		if r.Header.Get("Authorization") == "" && r.Header.Get("X-Api-Key") == "" {
			writeError(w, http.StatusUnauthorized, "authentication_error", "missing oauth token")
			return label, false
		}
		return label, true
	}
}

// handleUpstreamError вызывается, когда до Anthropic не удалось достучаться
// или соединение оборвалось до ответа.
func (g *Gateway) handleUpstreamError(w http.ResponseWriter, r *http.Request, err error) {
	// Клиент ушёл сам — это не отказ шлюза, писать ему уже некуда.
	if errors.Is(err, context.Canceled) || errors.Is(r.Context().Err(), context.Canceled) {
		if rec, isRec := w.(*recorder); isRec {
			rec.status = statusClientClosed
		}
		return
	}

	g.log.Error("апстрим недоступен", "upstream", g.upstream.Host, "err", err)
	writeError(w, http.StatusBadGateway, "api_error",
		"gateway could not reach "+g.upstream.Host)
}

// bearerToken достаёт значение из "Bearer <token>" без учёта регистра схемы.
// Пустая строка означает «токена нет» и никогда не совпадёт с настроенным.
func bearerToken(header string) string {
	const scheme = "bearer"
	if len(header) < len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return ""
	}
	rest := header[len(scheme):]
	if rest == "" || (rest[0] != ' ' && rest[0] != '\t') {
		return ""
	}
	return strings.TrimLeft(rest, " \t")
}

func writeOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// writeError отдаёт ошибку в формате Anthropic API — клиент и диагностика
// разбирают её теми же средствами, что и ответы самого Anthropic.
func writeError(w http.ResponseWriter, status int, kind, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"type":"error","error":{"type":%q,"message":%q}}`+"\n", kind, message)
}
