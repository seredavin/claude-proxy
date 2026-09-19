package service

import (
	"strings"
	"testing"

	"github.com/seredavin/claude-proxy/internal/config"
)

func TestEnvLinesПропускаетПустые(t *testing.T) {
	raw := config.Defaults()
	raw.Tokens = "default:abc"
	raw.Domain = "proxy.example.com"

	lines := strings.Join(envLines(raw), "\n")

	if !strings.Contains(lines, `CLAUDE_PROXY_TOKENS="default:abc"`) {
		t.Errorf("нет токенов:\n%s", lines)
	}
	if strings.Contains(lines, "CLAUDE_PROXY_ANTHROPIC_API_KEY") {
		t.Errorf("пустой ключ Console не должен попадать в файл:\n%s", lines)
	}
	if strings.Contains(lines, "CLAUDE_PROXY_CERT_FILE") {
		t.Errorf("пустой путь к сертификату не должен попадать в файл:\n%s", lines)
	}
}

func TestQuoteEnv(t *testing.T) {
	tests := map[string]string{
		"abc":     `"abc"`,
		"a b":     `"a b"`,
		`a"b`:     `"a\"b"`,
		`a\b`:     `"a\\b"`,
		"a$b":     `"a\$b"`,
		"a:1,b:2": `"a:1,b:2"`,
	}
	for in, want := range tests {
		if got := quoteEnv(in); got != want {
			t.Errorf("quoteEnv(%q) = %s, ожидалось %s", in, got, want)
		}
	}
}

func TestEnvValueЧитаетТоЧтоНаписали(t *testing.T) {
	raw := config.Defaults()
	raw.Tokens = `team-a:aaa,team-b:b"b`
	content := strings.Join(envLines(raw), "\n")

	if got := envValue(content, "CLAUDE_PROXY_TOKENS"); got != raw.Tokens {
		t.Errorf("envValue = %q, ожидалось %q", got, raw.Tokens)
	}
}

func TestEnvValueПониматьСтарыйФормат(t *testing.T) {
	// .env прежней установки писался без кавычек.
	content := "GATEWAY_MODE=oauth\nGATEWAY_TOKEN=deadbeef\n"
	if got := envValue(content, "GATEWAY_TOKEN"); got != "deadbeef" {
		t.Errorf("envValue = %q", got)
	}
	if got := envValue(content, "НЕТ_ТАКОГО"); got != "" {
		t.Errorf("envValue вернул %q для отсутствующего ключа", got)
	}
}
