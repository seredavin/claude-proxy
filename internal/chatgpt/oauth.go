package chatgpt

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const dynamicClient = "dynamic_agent_client"

var errInvalidGrant = errors.New("сеанс ChatGPT больше недействителен")

type tokenResponse struct {
	AccessToken  string  `json:"access_token"`
	RefreshToken string  `json:"refresh_token"`
	IDToken      string  `json:"id_token"`
	TokenType    string  `json:"token_type"`
	Scope        *string `json:"scope"`
	ExpiresIn    int64   `json:"expires_in"`
	Error        string  `json:"error"`
}

func applyTokens(p *profile, next tokenResponse) {
	p.AccessToken = next.AccessToken
	p.Expires = time.Now().Add(time.Duration(next.ExpiresIn) * time.Second)
	if next.RefreshToken != "" {
		p.RefreshToken = next.RefreshToken
	}
	if next.IDToken != "" {
		p.IDToken = next.IDToken
	}
	if next.Scope != nil {
		p.Scope = *next.Scope
	}
}

func (s *Store) exchange(ctx context.Context, form url.Values) (tokenResponse, error) {
	var token tokenResponse
	form.Set("resource", resource)
	status, err := s.form(ctx, tokenURL, form, &token)
	if err != nil {
		return token, err
	}
	switch token.Error {
	case "invalid_grant", "invalid_refresh_token", "token_expired", "refresh_token_expired",
		"refresh_token_invalidated", "refresh_token_reused":
		return token, errInvalidGrant
	}
	if status != http.StatusOK || token.AccessToken == "" || token.ExpiresIn <= 0 || token.ExpiresIn > 7*86400 ||
		!strings.EqualFold(token.TokenType, "Bearer") || strings.ContainsAny(token.AccessToken, " \r\n\t") {
		return token, fmt.Errorf("OpenAI не выдал действующий OAuth-токен (HTTP %d)", status)
	}
	return token, nil
}

func (s *Store) form(ctx context.Context, endpoint string, form url.Values, result any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, errors.New("не удалось связаться с сервером авторизации OpenAI")
	}
	defer resp.Body.Close()
	if result != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(result); err != nil {
			return resp.StatusCode, fmt.Errorf("некорректный ответ сервера авторизации OpenAI (HTTP %d)", resp.StatusCode)
		}
	}
	return resp.StatusCode, nil
}

func (s *Store) Login(ctx context.Context, name string, browser func(string) error) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	host, err := s.hostID(ctx)
	if err != nil {
		return err
	}
	return s.locked(ctx, name, func(path string) error {
		p, err := readProfile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return s.login(ctx, p, path, host, browser)
	})
}

func (s *Store) login(ctx context.Context, p profile, path, host string, browser func(string) error) error {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()

	state, nonce, verifier := randomToken(), randomToken(), randomToken()
	clientID := p.ClientID
	callback := "http://" + listener.Addr().String() + "/auth/callback"
	challenge := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"client_id": {clientID}, "response_type": {"code"}, "redirect_uri": {callback},
		"scope":    {"openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"},
		"resource": {resource}, "state": {state}, "nonce": {nonce}, "ext_agent_host_id": {host},
		"code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])},
	}
	if clientID == "" {
		query.Set("client_id", dynamicClient)
		query.Set("agent_name_hint", "claude-proxy")
	} else {
		if p.IDToken != "" {
			query.Set("id_token_hint", p.IDToken)
		}
		if !hasPlan(p.Scope) {
			query.Set("prompt", "consent")
		}
	}
	q, err := receiveCallback(ctx, listener, state, func() error {
		return browser(issuer + "/api/accounts/authorize?" + query.Encode())
	})
	if err != nil {
		return err
	}
	if q.Get("error") != "" {
		return errors.New("вход в ChatGPT отменён или отклонён")
	}
	if issued := q.Get("client_id"); clientID == "" {
		clientID = issued
	} else if issued != "" && issued != clientID {
		return errors.New("сервер авторизации вернул другой идентификатор клиента")
	}
	if clientID == "" || clientID == dynamicClient || q.Get("code") == "" {
		return errors.New("сервер авторизации не завершил регистрацию клиента")
	}
	token, err := s.exchange(ctx, url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID},
		"code": {q.Get("code")}, "code_verifier": {verifier}, "redirect_uri": {callback},
	})
	if err != nil {
		return err
	}
	identity, err := s.verifyIdentity(ctx, token.IDToken, clientID, nonce)
	if err != nil {
		return err
	}
	if p.Subject != "" && identity.Subject != p.Subject {
		return errors.New("выбран другой аккаунт ChatGPT. Используйте отдельное имя профиля")
	}
	p = profile{ClientID: clientID, Subject: identity.Subject, Email: identity.Email}
	applyTokens(&p, token)
	if !hasPlan(p.Scope) || p.RefreshToken == "" {
		p.AccessToken, p.RefreshToken, p.Scope = "", "", ""
		p.Expires = time.Time{}
		if err := saveProfile(path, p); err != nil {
			return err
		}
		return errors.New("ChatGPT не выдал разрешение на использование плана и обновление токенов. Повторите вход, чтобы дать согласие")
	}
	return saveProfile(path, p)
}

func receiveCallback(ctx context.Context, listener net.Listener, state string, open func() error) (url.Values, error) {
	result := make(chan url.Values, 1)
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method != http.MethodGet || r.URL.Path != "/auth/callback" ||
			subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 {
			http.Error(w, "Некорректный callback", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "Вернитесь в терминал для результата входа.")
		select {
		case result <- q:
		default:
		}
	})}
	defer srv.Close()
	go srv.Serve(listener)
	if err := open(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case q := <-result:
		return q, nil
	}
}

func randomToken() string {
	var buf [32]byte
	_, _ = rand.Read(buf[:])
	return base64.RawURLEncoding.EncodeToString(buf[:])
}

func (s *Store) Logout(ctx context.Context, name string) error {
	return s.locked(ctx, name, func(path string) error {
		p, err := readProfile(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		revoked := p.RefreshToken == ""
		if !revoked {
			metadata, err := s.discovery(ctx)
			if err == nil && officialAuthURL(metadata.Revocation) {
				status, err := s.form(ctx, metadata.Revocation, url.Values{
					"token": {p.RefreshToken}, "token_type_hint": {"refresh_token"}, "client_id": {p.ClientID},
				}, nil)
				revoked = err == nil && status == http.StatusOK
			}
		}
		p.AccessToken, p.RefreshToken, p.IDToken, p.Scope = "", "", "", ""
		p.Expires = time.Time{}
		if err := saveProfile(path, p); err != nil {
			return err
		}
		if !revoked {
			return errors.New("локальный сеанс очищен. OpenAI не подтвердил отзыв токена, отключите приложение в настройках ChatGPT")
		}
		return nil
	})
}
