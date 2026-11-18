package chatgpt

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/seredavin/claude-proxy/internal/config"
)

const refreshLimit = 32 << 10

type refreshGateway struct {
	endpoint string
	key      string
}

// ConfigureRefreshGateway задаёт доверенное внешнее звено для обновления.
func (s *Store) ConfigureRefreshGateway(upstream *url.URL, key string) error {
	if upstream == nil || upstream.Scheme != "https" || upstream.Hostname() == "" ||
		upstream.User != nil || (upstream.Path != "" && upstream.Path != "/") ||
		upstream.RawPath != "" || upstream.RawQuery != "" || upstream.ForceQuery || upstream.Fragment != "" ||
		strings.TrimSpace(key) == "" {
		return errors.New("клиентский OAuth требует HTTPS-адрес внешнего шлюза без пути, параметров и credentials, а также пропуск шлюза")
	}
	s.gateway = &refreshGateway{
		endpoint: (&url.URL{Scheme: "https", Host: upstream.Host, Path: config.ChatGPTRefreshPath}).String(),
		key:      key,
	}
	return nil
}

// RefreshRelay пересылает только OAuth refresh grant. Проверка TLS и
// пропуска маршрута выполняется шлюзом перед вызовом.
func RefreshRelay(transport http.RoundTripper) http.Handler {
	s := NewStore("")
	s.client.Transport = transport
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			relayResponse(w, 405, tokenResponse{Error: "invalid_request"})
			return
		}
		if r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			relayResponse(w, 400, tokenResponse{Error: "invalid_request"})
			return
		}
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, refreshLimit))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				relayResponse(w, 413, tokenResponse{Error: "invalid_request"})
			} else {
				relayResponse(w, 400, tokenResponse{Error: "invalid_request"})
			}
			return
		}
		values, err := url.ParseQuery(string(data))
		if err != nil || len(values) != 2 || len(values["client_id"]) != 1 || len(values["refresh_token"]) != 1 ||
			values.Get("client_id") == "" || values.Get("client_id") == dynamicClient || values.Get("refresh_token") == "" {
			relayResponse(w, 400, tokenResponse{Error: "invalid_request"})
			return
		}
		values.Set("grant_type", "refresh_token")
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		token, err := s.exchange(ctx, values)
		switch {
		case errors.Is(err, errInvalidGrant):
			relayResponse(w, 400, tokenResponse{Error: "invalid_grant"})
		case err != nil || token.RefreshToken == "":
			relayResponse(w, 502, tokenResponse{Error: "temporarily_unavailable"})
		default:
			token.IDToken = ""
			token.Error = ""
			relayResponse(w, 200, token)
		}
	})
}

func relayResponse(w http.ResponseWriter, status int, result tokenResponse) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(result)
}
