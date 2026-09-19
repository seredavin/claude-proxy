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
		got := baseURL(&config.Config{Listen: tc.listen, Domain: tc.domain})
		if got != tc.want {
			t.Errorf("baseURL(listen=%q, domain=%q) = %q, ожидалось %q", tc.listen, tc.domain, got, tc.want)
		}
	}
}
