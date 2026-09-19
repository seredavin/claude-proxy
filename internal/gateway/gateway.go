// Package gateway реализует HTTP-слой шлюза: проверку токена, зачистку
// заголовков и проксирование в Anthropic API.
//
// Поведение повторяет прежние nginx-шаблоны: те же коды и тексты ошибок,
// те же таймауты, отключённая буферизация ради SSE.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/seredavin/claude-proxy/internal/auth"
	"github.com/seredavin/claude-proxy/internal/config"
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
		mode:     opts.Mode,
		tokens:   opts.Tokens,
		apiKey:   opts.APIKey,
		upstream: opts.Upstream,
		maxBody:  opts.MaxBodyBytes,
		log:      opts.Logger,
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
		},
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

	if g.maxBody > 0 {
		if r.ContentLength > g.maxBody {
			writeError(rec, http.StatusRequestEntityTooLarge, "request_too_large",
				fmt.Sprintf("request body exceeds gateway limit of %d bytes", g.maxBody))
			g.logAccess(rec, r, start, label)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, g.maxBody)
	}

	g.proxy.ServeHTTP(rec, r)
	g.logAccess(rec, r, start, label)
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
