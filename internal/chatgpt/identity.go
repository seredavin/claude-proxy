package chatgpt

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

type discovery struct {
	Issuer     string `json:"issuer"`
	JWKS       string `json:"jwks_uri"`
	Revocation string `json:"revocation_endpoint"`
}

func (s *Store) discovery(ctx context.Context) (discovery, error) {
	var metadata discovery
	err := s.get(ctx, issuer+"/.well-known/openid-configuration", &metadata)
	if err == nil && metadata.Issuer != issuer {
		err = errors.New("неизвестный издатель OpenID Connect")
	}
	return metadata, err
}

func officialAuthURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Host == "auth.openai.com" && u.User == nil &&
		u.Path != "" && u.Fragment == ""
}

func (s *Store) get(ctx context.Context, endpoint string, result any) error {
	if !officialAuthURL(endpoint) {
		return errors.New("неизвестная конечная точка авторизации OpenAI")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return errors.New("не удалось загрузить данные авторизации OpenAI")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("сервер OpenAI не выдал данные авторизации")
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(result); err != nil {
		return errors.New("некорректные данные авторизации OpenAI")
	}
	return nil
}

type identity struct {
	Issuer          string          `json:"iss"`
	Subject         string          `json:"sub"`
	Email           string          `json:"email"`
	Audience        json.RawMessage `json:"aud"`
	AuthorizedParty string          `json:"azp"`
	Expires         int64           `json:"exp"`
	Nonce           string          `json:"nonce"`
}

type jwk struct {
	ID        string `json:"kid"`
	Type      string `json:"kty"`
	Algorithm string `json:"alg"`
	Use       string `json:"use"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
}

func (s *Store) verifyIdentity(ctx context.Context, jwt, clientID, nonce string) (identity, error) {
	var claims identity
	invalid := errors.New("некорректный ID token ChatGPT")
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return claims, invalid
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	if err != nil || json.Unmarshal(headerBytes, &header) != nil || header.Algorithm != "RS256" || header.KeyID == "" {
		return claims, invalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return claims, invalid
	}
	metadata, err := s.discovery(ctx)
	if err != nil {
		return claims, err
	}
	var keys struct {
		Keys []jwk `json:"keys"`
	}
	if err := s.get(ctx, metadata.JWKS, &keys); err != nil {
		return claims, err
	}

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	verified := false
	for _, key := range keys.Keys {
		if key.ID != header.KeyID || key.Type != "RSA" ||
			(key.Algorithm != "" && key.Algorithm != "RS256") || (key.Use != "" && key.Use != "sig") {
			continue
		}
		n, errN := base64.RawURLEncoding.DecodeString(key.Modulus)
		e, errE := base64.RawURLEncoding.DecodeString(key.Exponent)
		if errN != nil || errE != nil || len(e) == 0 || len(e) > 4 {
			continue
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature) == nil {
			verified = true
			break
		}
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if !verified || err != nil || json.Unmarshal(body, &claims) != nil ||
		claims.Issuer != issuer || claims.Subject == "" || claims.Nonce != nonce ||
		claims.Expires <= time.Now().Unix() || !validAudience(claims, clientID) {
		return identity{}, invalid
	}
	return claims, nil
}

func validAudience(claims identity, clientID string) bool {
	var single string
	if json.Unmarshal(claims.Audience, &single) == nil {
		return single == clientID && (claims.AuthorizedParty == "" || claims.AuthorizedParty == clientID)
	}
	var multiple []string
	return json.Unmarshal(claims.Audience, &multiple) == nil && slices.Contains(multiple, clientID) &&
		(claims.AuthorizedParty == clientID || (len(multiple) == 1 && claims.AuthorizedParty == ""))
}
