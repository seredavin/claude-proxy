// Package clientenv печатает набор переменных окружения для клиентской машины.
package clientenv

import (
	"fmt"
	"net"
	"strings"

	"github.com/seredavin/claude-proxy/internal/config"
)

// Плейсхолдер токена подписки: настоящий живёт на клиенте, шлюз его не знает.
const AuthTokenPlaceholder = "sk-ant-oat01-..."

// Var — одна строка клиентского окружения.
//
// Пустое Name — строка-комментарий (Comment целиком). Unset — переменную
// надо убрать, а не задать. Comment у переменной — пояснение в той же строке.
type Var struct {
	Name    string
	Value   string
	Unset   bool
	Comment string
}

// Vars — набор переменных для клиентской машины в порядке печати.
//
// token — значение одного из токенов шлюза. Пустое значение подставляется
// плейсхолдером: так удобно печатать инструкцию, не зная секрета.
//
// Один источник и для Render, и для запуска claude из своего процесса —
// так они не могут разойтись в том, что именно клиенту нужно.
func Vars(cfg *config.Config, token string) []Var {
	if token == "" {
		token = "<GATEWAY_TOKEN>"
	}

	vars := []Var{{Name: "ANTHROPIC_BASE_URL", Value: baseURL(cfg)}}

	if cfg.Mode == config.ModeAPIKey {
		// Ключ Console подставляет сам шлюз, клиенту нужен только пропуск.
		return append(vars,
			Var{Name: "ANTHROPIC_AUTH_TOKEN", Value: token},
			Var{Name: "ANTHROPIC_API_KEY", Unset: true},
			Var{Name: "CLAUDE_CODE_OAUTH_TOKEN", Unset: true},
		)
	}

	return append(vars,
		Var{Name: "ANTHROPIC_CUSTOM_HEADERS", Value: "X-Gateway-Key: " + token},
		Var{Name: "ANTHROPIC_AUTH_TOKEN", Value: AuthTokenPlaceholder, Comment: "получить: claude setup-token"},
		Var{Comment: "Служебный трафик Claude Code идёт напрямую на api.anthropic.com мимо шлюза."},
		Var{Comment: "В изолированной сети его надо отключить, иначе CLI падает на старте:"},
		Var{Name: "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", Value: "1"},
		Var{Name: "CLAUDE_CODE_SKIP_FAST_MODE_ORG_CHECK", Value: "1"},
		Var{Name: "CLAUDE_CODE_SKIP_FAST_MODE_NETWORK_ERRORS", Value: "1"},
		Var{Name: "CLAUDE_CODE_OAUTH_TOKEN", Unset: true},
		Var{Name: "ANTHROPIC_API_KEY", Unset: true},
	)
}

// Render собирает блок команд export для целевой машины из Vars.
func Render(cfg *config.Config, token string) string {
	var b strings.Builder
	var unset []string
	flush := func() {
		if len(unset) > 0 {
			b.WriteString("unset " + strings.Join(unset, " ") + "\n")
			unset = nil
		}
	}

	for _, v := range Vars(cfg, token) {
		switch {
		case v.Unset:
			// Соседние unset собираются в одну строку.
			unset = append(unset, v.Name)
			continue
		case v.Name == "":
			flush()
			b.WriteString("# " + v.Comment + "\n")
			continue
		}
		flush()
		value := v.Value
		if strings.ContainsAny(value, " \t") {
			value = `"` + value + `"`
		}
		fmt.Fprintf(&b, "export %s=%s", v.Name, value)
		if v.Comment != "" {
			b.WriteString("   # " + v.Comment)
		}
		b.WriteString("\n")
	}
	flush()
	return b.String()
}

// baseURL собирает адрес шлюза. Порт указывается всегда: без него Node
// пойдёт на 443 и не достучится.
func baseURL(cfg *config.Config) string {
	listenHost, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil || port == "" {
		port = "9443"
	}

	// Без TLS шлюз слушает только loopback, и клиент на той же машине —
	// хост берём прямо из адреса слушателя, имя шлюза здесь ни при чём.
	if cfg.TLS == config.TLSNone {
		return "http://" + net.JoinHostPort(listenHost, port)
	}

	host := cfg.Domain
	if host == "" {
		host = "<имя-шлюза>"
	}
	return "https://" + net.JoinHostPort(host, port)
}
