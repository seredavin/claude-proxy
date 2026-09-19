// Package clientenv печатает набор переменных окружения для клиентской машины.
package clientenv

import (
	"fmt"
	"net"
	"strings"

	"github.com/seredavin/claude-proxy/internal/config"
)

// Render собирает блок команд export для целевой машины.
//
// token — значение одного из токенов шлюза. Пустое значение выводится
// плейсхолдером: так удобно печатать инструкцию, не зная секрета.
func Render(cfg *config.Config, token string) string {
	if token == "" {
		token = "<GATEWAY_TOKEN>"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "export ANTHROPIC_BASE_URL=%s\n", baseURL(cfg))

	if cfg.Mode == config.ModeAPIKey {
		// Ключ Console подставляет сам шлюз, клиенту нужен только пропуск.
		fmt.Fprintf(&b, "export ANTHROPIC_AUTH_TOKEN=%s\n", token)
		b.WriteString("unset ANTHROPIC_API_KEY CLAUDE_CODE_OAUTH_TOKEN\n")
		return b.String()
	}

	fmt.Fprintf(&b, "export ANTHROPIC_CUSTOM_HEADERS=\"X-Gateway-Key: %s\"\n", token)
	b.WriteString("export ANTHROPIC_AUTH_TOKEN=sk-ant-oat01-...   # получить: claude setup-token\n")
	b.WriteString("# Служебный трафик Claude Code идёт напрямую на api.anthropic.com мимо шлюза.\n")
	b.WriteString("# В изолированной сети его надо отключить, иначе CLI падает на старте:\n")
	b.WriteString("export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1\n")
	b.WriteString("export CLAUDE_CODE_SKIP_FAST_MODE_ORG_CHECK=1\n")
	b.WriteString("export CLAUDE_CODE_SKIP_FAST_MODE_NETWORK_ERRORS=1\n")
	b.WriteString("unset CLAUDE_CODE_OAUTH_TOKEN ANTHROPIC_API_KEY\n")
	return b.String()
}

// baseURL собирает адрес шлюза. Порт указывается всегда: без него Node
// пойдёт на 443 и не достучится.
func baseURL(cfg *config.Config) string {
	host := cfg.Domain
	if host == "" {
		host = "<имя-шлюза>"
	}

	_, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil || port == "" {
		port = "9443"
	}
	return "https://" + net.JoinHostPort(host, port)
}
