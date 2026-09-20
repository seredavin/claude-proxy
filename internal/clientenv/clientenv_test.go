package clientenv

import (
	"strings"
	"testing"

	"github.com/seredavin/claude-proxy/internal/config"
)

func TestRenderOAuth(t *testing.T) {
	cfg := &config.Config{Mode: config.ModeOAuth, Domain: "proxy.example.com", Listen: ":9443"}
	got := Render(cfg, "hexvalue")

	want := []string{
		"export ANTHROPIC_BASE_URL=https://proxy.example.com:9443",
		`export ANTHROPIC_CUSTOM_HEADERS="X-Gateway-Key: hexvalue"`,
		"export ANTHROPIC_AUTH_TOKEN=sk-ant-oat01-",
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
		"unset CLAUDE_CODE_OAUTH_TOKEN ANTHROPIC_API_KEY",
	}
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("нет строки %q в:\n%s", w, got)
		}
	}
}

func TestRenderAPIKeyНеРаскрываетКлючConsole(t *testing.T) {
	cfg := &config.Config{Mode: config.ModeAPIKey, Domain: "proxy.internal", Listen: ":9443", APIKey: "sk-ant-api03-secret"}
	got := Render(cfg, "hexvalue")

	if !strings.Contains(got, "export ANTHROPIC_AUTH_TOKEN=hexvalue") {
		t.Errorf("в режиме apikey клиент предъявляет пропуск шлюза:\n%s", got)
	}
	if strings.Contains(got, "sk-ant-api03-secret") {
		t.Errorf("ключ Console утёк в клиентскую инструкцию:\n%s", got)
	}
	if strings.Contains(got, "X-Gateway-Key") {
		t.Errorf("в режиме apikey отдельного заголовка нет:\n%s", got)
	}
}

func TestRenderБезТокенаДаётПлейсхолдер(t *testing.T) {
	cfg := &config.Config{Mode: config.ModeOAuth, Domain: "proxy.example.com", Listen: ":9443"}
	if !strings.Contains(Render(cfg, ""), "<GATEWAY_TOKEN>") {
		t.Error("ожидался плейсхолдер вместо секрета")
	}
}

func TestBaseURLВсегдаСПортом(t *testing.T) {
	tests := []struct {
		listen string
		domain string
		want   string
	}{
		{":9443", "proxy.example.com", "https://proxy.example.com:9443"},
		{"127.0.0.1:8443", "proxy.example.com", "https://proxy.example.com:8443"},
		{"", "proxy.example.com", "https://proxy.example.com:9443"},
		{":9443", "", "https://<имя-шлюза>:9443"},
	}
	for _, tc := range tests {
		got := baseURL(&config.Config{Listen: tc.listen, Domain: tc.domain, TLS: config.TLSSelf})
		if got != tc.want {
			t.Errorf("baseURL(listen=%q, domain=%q) = %q, ожидалось %q", tc.listen, tc.domain, got, tc.want)
		}
	}
}

// Без TLS клиент на той же машине: адрес берётся из слушателя, а не из
// имени шлюза, и никакого доверия к сертификату не требуется.
func TestBaseURLБезTLS(t *testing.T) {
	tests := []struct {
		listen string
		domain string
		want   string
	}{
		{"127.0.0.1:9443", "", "http://127.0.0.1:9443"},
		{"[::1]:9443", "", "http://[::1]:9443"},
		{"localhost:8443", "", "http://localhost:8443"},
		{"127.0.0.1:9443", "ignored.example.com", "http://127.0.0.1:9443"},
	}
	for _, tc := range tests {
		got := baseURL(&config.Config{Listen: tc.listen, Domain: tc.domain, TLS: config.TLSNone})
		if got != tc.want {
			t.Errorf("baseURL(none, listen=%q, domain=%q) = %q, ожидалось %q", tc.listen, tc.domain, got, tc.want)
		}
	}
}

// Текст снят с реализации до появления Vars: печать через пары не должна
// изменить ни одного байта в том, что видят операторы.
func TestRenderЧерезVarsСовпадаетСПрежнимТекстом(t *testing.T) {
	oauth := &config.Config{Mode: config.ModeOAuth, Domain: "proxy.example.com", Listen: ":9443", TLS: config.TLSSelf}
	wantOAuth := "export ANTHROPIC_BASE_URL=https://proxy.example.com:9443\n" +
		"export ANTHROPIC_CUSTOM_HEADERS=\"X-Gateway-Key: hexvalue\"\n" +
		"export ANTHROPIC_AUTH_TOKEN=sk-ant-oat01-...   # получить: claude setup-token\n" +
		"# Служебный трафик Claude Code идёт напрямую на api.anthropic.com мимо шлюза.\n" +
		"# В изолированной сети его надо отключить, иначе CLI падает на старте:\n" +
		"export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1\n" +
		"export CLAUDE_CODE_SKIP_FAST_MODE_ORG_CHECK=1\n" +
		"export CLAUDE_CODE_SKIP_FAST_MODE_NETWORK_ERRORS=1\n" +
		"unset CLAUDE_CODE_OAUTH_TOKEN ANTHROPIC_API_KEY\n"
	if got := Render(oauth, "hexvalue"); got != wantOAuth {
		t.Errorf("oauth:\n--- получено ---\n%s--- ожидалось ---\n%s", got, wantOAuth)
	}

	apikey := &config.Config{Mode: config.ModeAPIKey, Domain: "proxy.internal", Listen: ":9443", TLS: config.TLSSelf}
	wantAPIKey := "export ANTHROPIC_BASE_URL=https://proxy.internal:9443\n" +
		"export ANTHROPIC_AUTH_TOKEN=hexvalue\n" +
		"unset ANTHROPIC_API_KEY CLAUDE_CODE_OAUTH_TOKEN\n"
	if got := Render(apikey, "hexvalue"); got != wantAPIKey {
		t.Errorf("apikey:\n--- получено ---\n%s--- ожидалось ---\n%s", got, wantAPIKey)
	}
}

func TestVarsOAuthСнимаетЧужиеСекреты(t *testing.T) {
	cfg := &config.Config{Mode: config.ModeOAuth, Listen: "127.0.0.1:9443", TLS: config.TLSNone}
	unset := map[string]bool{}
	set := map[string]string{}
	for _, v := range Vars(cfg, "hexvalue") {
		switch {
		case v.Unset:
			unset[v.Name] = true
		case v.Name != "":
			set[v.Name] = v.Value
		}
	}
	for _, name := range []string{"CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"} {
		if !unset[name] {
			t.Errorf("%s должна сниматься", name)
		}
	}
	if set["ANTHROPIC_BASE_URL"] != "http://127.0.0.1:9443" {
		t.Errorf("ANTHROPIC_BASE_URL = %q", set["ANTHROPIC_BASE_URL"])
	}
	if set["ANTHROPIC_CUSTOM_HEADERS"] != "X-Gateway-Key: hexvalue" {
		t.Errorf("ANTHROPIC_CUSTOM_HEADERS = %q — значение без кавычек, это не shell", set["ANTHROPIC_CUSTOM_HEADERS"])
	}
	if set["ANTHROPIC_AUTH_TOKEN"] != AuthTokenPlaceholder {
		t.Errorf("ANTHROPIC_AUTH_TOKEN = %q, ожидался плейсхолдер", set["ANTHROPIC_AUTH_TOKEN"])
	}
}

func TestRenderБезTLSПечатаетHTTP(t *testing.T) {
	cfg := &config.Config{Mode: config.ModeOAuth, Listen: "127.0.0.1:9443", TLS: config.TLSNone}
	got := Render(cfg, "hexvalue")
	if !strings.Contains(got, "export ANTHROPIC_BASE_URL=http://127.0.0.1:9443\n") {
		t.Errorf("нет http-адреса слушателя в:\n%s", got)
	}
	if !strings.Contains(got, `export ANTHROPIC_CUSTOM_HEADERS="X-Gateway-Key: hexvalue"`) {
		t.Errorf("остальные переменные должны совпадать с TLS-вариантом:\n%s", got)
	}
}
