package config

import (
	"strings"
	"testing"
)

// routeEnv — окружение валидной конфигурации с маршрутами.
func routeEnv() map[string]string {
	return map[string]string{
		"CLAUDE_PROXY_TOKENS":              "plain:AAA,routed:BBB",
		"CLAUDE_PROXY_UPSTREAM_ROUTES":     "routed=https://edge-b.example.com:9443",
		"CLAUDE_PROXY_UPSTREAM_ROUTE_KEYS": "routed=KEYB",
	}
}

// routeArgs — минимальный набор флагов, чтобы пройти валидацию TLS.
var routeArgs = []string{"--tls", "files", "--cert-file", "c.pem", "--key-file", "k.pem"}

func TestМаршрутыРазбираются(t *testing.T) {
	cfg, _, err := load(t, routeArgs, routeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Routes) != 1 {
		t.Fatalf("Routes = %v, ожидался один маршрут", cfg.Routes)
	}
	rt := cfg.Routes[0]
	if rt.Label != "routed" {
		t.Errorf("Label = %q", rt.Label)
	}
	if rt.Upstream.Host != "edge-b.example.com:9443" {
		t.Errorf("Upstream = %s, ожидался хост маршрута", rt.Upstream)
	}
	if rt.Key != "KEYB" {
		t.Errorf("Key = %q", rt.Key)
	}
}

func TestМаршрутыФлагамиПерекрываютсяПеременными(t *testing.T) {
	args := append(append([]string{}, routeArgs...),
		"--upstream-routes", "routed=https://flag.example.com:9443")
	cfg, warnings, err := load(t, args, routeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Routes[0].Upstream.Host != "edge-b.example.com:9443" {
		t.Errorf("переменная не перебила флаг: %s", cfg.Routes[0].Upstream)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "--upstream-routes") {
		t.Errorf("ожидалось предупреждение про --upstream-routes, получено %v", warnings)
	}
}

func TestБезМаршрутовПоведениеПрежнее(t *testing.T) {
	cfg, _, err := load(t, routeArgs, map[string]string{"CLAUDE_PROXY_TOKENS": "a:AAA"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Routes) != 0 {
		t.Errorf("Routes = %v, ожидалось пусто", cfg.Routes)
	}
}

func TestОшибкиМаршрутов(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"метка без токена", map[string]string{
			"CLAUDE_PROXY_TOKENS":          "a:AAA",
			"CLAUDE_PROXY_UPSTREAM_ROUTES": "ghost=https://edge.example.com:9443",
		}, "ghost"},
		{"ключ без маршрута", map[string]string{
			"CLAUDE_PROXY_TOKENS":              "a:AAA",
			"CLAUDE_PROXY_UPSTREAM_ROUTES":     "a=https://edge.example.com:9443",
			"CLAUDE_PROXY_UPSTREAM_ROUTE_KEYS": "a=KEY,b=KEY2",
		}, "нет маршрута"},
		{"ключи без маршрутов", map[string]string{
			"CLAUDE_PROXY_TOKENS":              "a:AAA",
			"CLAUDE_PROXY_UPSTREAM_ROUTE_KEYS": "a=KEY",
		}, "только вместе"},
		{"повтор метки", map[string]string{
			"CLAUDE_PROXY_TOKENS":          "a:AAA",
			"CLAUDE_PROXY_UPSTREAM_ROUTES": "a=https://e1.example.com:9443, a=https://e2.example.com:9443",
		}, "дважды"},
		{"повтор ключа", map[string]string{
			"CLAUDE_PROXY_TOKENS":              "a:AAA",
			"CLAUDE_PROXY_UPSTREAM_ROUTES":     "a=https://edge.example.com:9443",
			"CLAUDE_PROXY_UPSTREAM_ROUTE_KEYS": "a=KEY,a=KEY2",
		}, "дважды"},
		{"не https", map[string]string{
			"CLAUDE_PROXY_TOKENS":          "a:AAA",
			"CLAUDE_PROXY_UPSTREAM_ROUTES": "a=http://edge.example.com:9443",
		}, "https://host"},
		{"порт без хоста", map[string]string{
			"CLAUDE_PROXY_TOKENS":          "a:AAA",
			"CLAUDE_PROXY_UPSTREAM_ROUTES": "a=https://:9443",
		}, "https://host"},
		{"элемент без метки", map[string]string{
			"CLAUDE_PROXY_TOKENS":          "a:AAA",
			"CLAUDE_PROXY_UPSTREAM_ROUTES": "https://edge.example.com:9443",
		}, "метка=https://host"},
		{"ключ маршрута на Anthropic", map[string]string{
			"CLAUDE_PROXY_TOKENS":              "a:AAA",
			"CLAUDE_PROXY_UPSTREAM_ROUTES":     "a=https://api.anthropic.com",
			"CLAUDE_PROXY_UPSTREAM_ROUTE_KEYS": "a=KEY",
		}, "бесполезен"},
		{"регистр имени Anthropic не обходит проверку", map[string]string{
			"CLAUDE_PROXY_TOKENS":              "a:AAA",
			"CLAUDE_PROXY_UPSTREAM_ROUTES":     "a=https://API.Anthropic.COM.",
			"CLAUDE_PROXY_UPSTREAM_ROUTE_KEYS": "a=KEY",
		}, "бесполезен"},
		{"маршрут на Anthropic без ключа допустим", map[string]string{
			"CLAUDE_PROXY_TOKENS":          "a:AAA",
			"CLAUDE_PROXY_UPSTREAM_ROUTES": "a=https://api.anthropic.com",
		}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := load(t, routeArgs, tc.env)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("не ожидался отказ: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("ожидался отказ")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ошибка %q не содержит %q", err, tc.want)
			}
		})
	}
}

func TestОшибкаФорматаНеРаскрываетКлючМаршрута(t *testing.T) {
	const secret = "secret-route-token"
	for _, input := range []string{secret, "=" + secret} {
		env := routeEnv()
		env["CLAUDE_PROXY_UPSTREAM_ROUTE_KEYS"] = input
		_, _, err := load(t, routeArgs, env)
		if err == nil {
			t.Fatalf("ожидался отказ для %q", input)
		}
		if !strings.Contains(err.Error(), "--upstream-route-keys") || strings.Contains(err.Error(), secret) {
			t.Errorf("ожидалась диагностика формата без значения ключа, получено: %v", err)
		}
	}
}
