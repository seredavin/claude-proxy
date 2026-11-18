package chatgpt

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testTransport func(*http.Request) (*http.Response, error)

func (f testTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func reply(value any) (*http.Response, error) {
	data, err := json.Marshal(value)
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data)))}, err
}

func TestLocalLoginAndLogout(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s := NewStore(t.TempDir())
	scope := "openid resource.invoke chatgpt.tokens.use.direct offline_access"
	const client = "oaiapp_test"
	const subject = "test-sub"
	var nonce, challenge, redirect, host string
	s.client.Transport = testTransport(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			return reply(discovery{Issuer: issuer, JWKS: issuer + "/jwks", Revocation: issuer + "/revoke"})
		case "/jwks":
			return reply(map[string]any{"keys": []jwk{{ID: "test", Type: "RSA", Algorithm: "RS256",
				Modulus: base64.RawURLEncoding.EncodeToString(key.N.Bytes()), Exponent: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		case "/api/accounts/oauth/token":
			if err := r.ParseForm(); err != nil {
				return nil, err
			}
			verifier := r.Form.Get("code_verifier")
			if len(verifier) < 43 || len(verifier) > 128 {
				t.Error("недопустимая длина PKCE verifier")
			}
			digest := sha256.Sum256([]byte(verifier))
			if base64.RawURLEncoding.EncodeToString(digest[:]) != challenge ||
				r.Form.Get("redirect_uri") != redirect || r.Form.Get("client_id") != client || r.Form.Get("resource") != resource {
				t.Error("некорректный обмен кода")
			}
			claims, _ := json.Marshal(identity{Issuer: issuer, Subject: subject, Nonce: nonce, Audience: json.RawMessage(`"oaiapp_test"`), Expires: time.Now().Add(time.Hour).Unix()})
			jwt := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test"}`)) + "." + base64.RawURLEncoding.EncodeToString(claims)
			sum := sha256.Sum256([]byte(jwt))
			sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
			if err != nil {
				return nil, err
			}
			return reply(tokenResponse{TokenType: "Bearer", AccessToken: "test-access", RefreshToken: "test-refresh", Scope: &scope,
				ExpiresIn: 3600, IDToken: jwt + "." + base64.RawURLEncoding.EncodeToString(sig)})
		case "/revoke":
			if err := r.ParseForm(); err != nil || r.Form.Get("token") != "test-refresh" || r.Form.Get("client_id") != client {
				t.Error("некорректный отзыв сеанса")
			}
			return reply(nil)
		default:
			return nil, fmt.Errorf("неожиданный путь: %s", r.URL.Path)
		}
	})
	ctx := context.Background()
	browser := func(value string) error {
		u, err := url.Parse(value)
		if err != nil {
			return err
		}
		q := u.Query()
		nonce, challenge, redirect = q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri")
		if host != "" && host != q.Get("ext_agent_host_id") {
			t.Error("идентификатор хоста изменился")
		}
		host = q.Get("ext_agent_host_id")
		for _, state := range []string{"wrong", q.Get("state")} {
			callback := url.Values{"state": {state}, "code": {"test-code"}, "client_id": {client}}
			resp, err := http.Get(redirect + "?" + callback.Encode())
			if err != nil {
				return err
			}
			resp.Body.Close()
			if state == "wrong" && resp.StatusCode != 400 || state != "wrong" && resp.StatusCode != 200 {
				t.Errorf("неожиданный статус callback: %d", resp.StatusCode)
			}
		}
		return nil
	}
	for i := 0; i < 2; i++ {
		if err := s.Login(ctx, "test", browser); err != nil {
			t.Fatal(err)
		}
	}
	if token, err := s.AccessToken(ctx, "test"); token != "test-access" || err != nil {
		t.Fatalf("профиль недоступен: %v", err)
	}
	if err := s.Logout(ctx, "test"); err != nil {
		t.Fatal(err)
	}
	p, err := readProfile(filepath.Join(s.dir, "test.json"))
	if err != nil || p.Subject != subject || p.ClientID != client || p.AccessToken != "" || p.RefreshToken != "" || p.IDToken != "" {
		t.Fatal("выход не очистил сеанс или потерял регистрацию")
	}
}

func TestRotatingRefreshAcrossStores(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	p := profile{ClientID: "test-client", RefreshToken: "old", Scope: "resource.invoke chatgpt.tokens.use.direct"}
	if err := saveProfile(path, p); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("права профиля: %v", err)
	}
	var requests atomic.Int32
	transport := testTransport(func(r *http.Request) (*http.Response, error) {
		requests.Add(1)
		if err := r.ParseForm(); err != nil || r.Form.Get("refresh_token") != "old" {
			t.Error("обновление должно использовать исходный refresh token")
		}
		return reply(tokenResponse{AccessToken: "new", RefreshToken: "rotated", ExpiresIn: 3600, TokenType: "Bearer"})
	})
	var running sync.WaitGroup
	for i := 0; i < 4; i++ {
		running.Go(func() {
			s := NewStore(dir)
			s.client.Transport = transport
			token, err := s.AccessToken(context.Background(), "test")
			if token != "new" || err != nil {
				t.Errorf("обновление профиля: %v", err)
			}
		})
	}
	running.Wait()
	got, err := readProfile(path)
	if err != nil || got.RefreshToken != "rotated" || requests.Load() != 1 {
		t.Fatalf("ожидалось одно атомарное обновление: %v, запросов %d", err, requests.Load())
	}
}

func TestImportKeepsSeparateHostAndProtectsActiveProfile(t *testing.T) {
	ctx := context.Background()
	laptop := NewStore(t.TempDir())
	remote := NewStore(t.TempDir())
	laptopHost, err := laptop.hostID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	incoming := profile{ClientID: "oaiapp_test", Subject: "test-account", IDToken: "test-id-token",
		AccessToken: "test-access", RefreshToken: "test-refresh", Expires: time.Now().Add(time.Hour),
		Scope: "resource.invoke chatgpt.tokens.use.direct"}
	wire, err := json.Marshal(incoming)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Import(ctx, "personal", strings.NewReader(string(wire))); err != nil {
		t.Fatal(err)
	}
	remoteHost, err := remote.hostID(ctx)
	if err != nil || laptopHost == remoteHost {
		t.Fatal("импорт должен использовать отдельный идентификатор сервера")
	}
	token, err := remote.AccessToken(ctx, "personal")
	if err != nil || token != incoming.AccessToken {
		t.Fatalf("импортированный профиль недоступен: %v", err)
	}
	if err := remote.Import(ctx, "personal", strings.NewReader(string(wire))); err == nil {
		t.Fatal("повторный импорт не должен переписывать активную сессию")
	}
}

func TestAccessTokenRotatesThroughGateway(t *testing.T) {
	s := NewStore(t.TempDir())
	old := profile{ClientID: "oaiapp_test", RefreshToken: "old-refresh", Scope: "resource.invoke chatgpt.tokens.use.direct"}
	path := filepath.Join(s.dir, "client.json")
	if err := saveProfile(path, old); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	relay := RefreshRelay(testTransport(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL.String() != tokenURL || r.Header.Get("X-Gateway-Key") != "" ||
			r.ParseForm() != nil || r.Form.Get("resource") != resource || r.Form.Get("grant_type") != "refresh_token" ||
			r.Form.Get("client_id") != old.ClientID || r.Form.Get("refresh_token") != old.RefreshToken {
			t.Error("неверный запрос обновления")
		}
		return reply(tokenResponse{TokenType: "Bearer", AccessToken: "new-access", RefreshToken: "new-refresh", ExpiresIn: 3600})
	}))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_claude_proxy/chatgpt/refresh" || r.Header.Get("X-Gateway-Key") != "gateway-test" {
			t.Error("неверная авторизация на шлюзе")
		}
		relay.ServeHTTP(w, r)
	}))
	defer srv.Close()
	s.client.Transport = srv.Client().Transport
	upstream, _ := url.Parse(srv.URL)
	if err := s.ConfigureRefreshGateway(upstream, "gateway-test"); err != nil {
		t.Fatal(err)
	}
	var pending sync.WaitGroup
	for range 2 {
		pending.Go(func() {
			if got, err := s.AccessToken(context.Background(), "client"); got != "new-access" || err != nil {
				t.Errorf("обновление: %v", err)
			}
		})
	}
	pending.Wait()
	got, err := readProfile(path)
	if err != nil || got.RefreshToken != "new-refresh" || calls.Load() != 1 {
		t.Fatalf("ротация: %v, запросов %d", err, calls.Load())
	}
}
