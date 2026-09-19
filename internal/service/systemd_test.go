package service

import (
	"os"
	"path/filepath"
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
	if strings.Contains(lines, "CLAUDE_PROXY_UPSTREAM_KEY") {
		t.Errorf("пустой пропуск на следующее звено не должен попадать в файл:\n%s", lines)
	}
}

func TestEnvLinesWritesUpstreamKey(t *testing.T) {
	raw := config.Defaults()
	raw.Tokens = "default:abc"
	raw.Upstream = "https://edge.example.com:9443"
	raw.UpstreamKey = "next-secret"

	lines := strings.Join(envLines(raw), "\n")

	if !strings.Contains(lines, `CLAUDE_PROXY_UPSTREAM_KEY="next-secret"`) {
		t.Errorf("пропуск на следующее звено не попал в файл:\n%s", lines)
	}
}

func TestForeignEnvLinesSurviveReinstall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "claude-proxy.env")
	content := strings.Join([]string{
		"# Создано claude-proxy install 2026-01-01",
		`CLAUDE_PROXY_TOKENS="default:abc"`,
		`GATEWAY_TOKEN="legacy-alias"`,
		"SSL_CERT_FILE=/usr/local/share/ca-certificates/internal-ca.crt",
		`HTTPS_PROXY="http://corp-proxy:3128"`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got := foreignEnvLines(path)
	want := []string{
		"SSL_CERT_FILE=/usr/local/share/ca-certificates/internal-ca.crt",
		`HTTPS_PROXY="http://corp-proxy:3128"`,
	}
	if len(got) != len(want) {
		t.Fatalf("перенесено %v, ожидалось %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("строка %d = %q, ожидалось %q", i, got[i], want[i])
		}
	}
}

func TestForeignEnvLinesMissingFile(t *testing.T) {
	if got := foreignEnvLines(filepath.Join(t.TempDir(), "missing.env")); got != nil {
		t.Errorf("ожидался пустой результат, получено %v", got)
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
