package main

import (
	"errors"
	"flag"
	"strings"
	"testing"

	"github.com/seredavin/claude-proxy/internal/config"
)

// planFrom разбирает args как cmdLocal и строит план на окружении env.
func planFrom(t *testing.T, args []string, env map[string]string, found bool) (*localPlan, error) {
	t.Helper()
	fs := flag.NewFlagSet("local", flag.ContinueOnError)
	raw := config.Bind(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	getenv := func(k string) string { return env[k] }
	lookPath := func(name string) (string, error) {
		if !found {
			return "", errors.New("executable file not found in $PATH")
		}
		return "/usr/local/bin/" + name, nil
	}
	return planLocal(raw, fs, getenv, "claude", lookPath)
}

func TestPlanLocalОтказы(t *testing.T) {
	good := map[string]string{
		"CLAUDE_PROXY_UPSTREAM":     "https://edge.example.com:9443",
		"CLAUDE_PROXY_UPSTREAM_KEY": "EDGE",
		"ANTHROPIC_AUTH_TOKEN":      "sk-ant-oat01-x",
	}
	without := func(keys ...string) map[string]string {
		m := map[string]string{}
		for k, v := range good {
			m[k] = v
		}
		for _, k := range keys {
			delete(m, k)
		}
		return m
	}
	with := func(k, v string) map[string]string {
		m := without()
		m[k] = v
		return m
	}

	tests := []struct {
		name  string
		args  []string
		env   map[string]string
		found bool
		want  string // фрагмент текста ошибки
	}{
		{"tls из окружения", nil, with("CLAUDE_PROXY_TLS", "self"), true, "только без TLS"},
		{"tls флагом", []string{"--tls", "auto"}, good, true, "только без TLS"},
		{"нет пропуска внешнего звена", nil, without("CLAUDE_PROXY_UPSTREAM_KEY"), true, "только в цепочке"},
		{"нет апстрима", nil, without("CLAUDE_PROXY_UPSTREAM"), true, "upstream"},
		{"нет токена подписки", nil, without("ANTHROPIC_AUTH_TOKEN"), true, "claude setup-token"},
		{"внешний адрес", []string{"--listen", "0.0.0.0:9443"}, good, true, "none"},
		{"claude не найден", nil, good, false, "--claude"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := planFrom(t, tc.args, tc.env, tc.found)
			if err == nil {
				t.Fatal("ожидался отказ")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ошибка %q не содержит %q", err, tc.want)
			}
		})
	}
}

func TestPlanLocalУмолчанияИПропуск(t *testing.T) {
	env := map[string]string{
		"CLAUDE_PROXY_UPSTREAM":     "https://edge.example.com:9443",
		"CLAUDE_PROXY_UPSTREAM_KEY": "EDGE",
		"ANTHROPIC_AUTH_TOKEN":      "sk-ant-oat01-x",
	}
	first, err := planFrom(t, nil, env, true)
	if err != nil {
		t.Fatal(err)
	}
	if first.cfg.TLS != config.TLSNone || first.cfg.Listen != "127.0.0.1:0" {
		t.Errorf("умолчания: tls=%q listen=%q", first.cfg.TLS, first.cfg.Listen)
	}
	if first.cfg.UpstreamKey != "EDGE" || first.cfg.Upstream.Host != "edge.example.com:9443" {
		t.Errorf("апстрим из окружения не применился: %s / %q", first.cfg.Upstream, first.cfg.UpstreamKey)
	}
	if first.authToken != "sk-ant-oat01-x" || first.claudePath != "/usr/local/bin/claude" {
		t.Errorf("authToken=%q claudePath=%q", first.authToken, first.claudePath)
	}
	if len(first.token) < 32 {
		t.Errorf("пропуск не сгенерирован: %q", first.token)
	}
	if _, ok := first.cfg.Tokens.Lookup(first.token); !ok {
		t.Error("сгенерированный пропуск должен приниматься звеном")
	}

	second, err := planFrom(t, nil, env, true)
	if err != nil {
		t.Fatal(err)
	}
	if second.token == first.token {
		t.Error("пропуск должен быть новым на каждый запуск")
	}
}

func TestPlanLocalЯвныеЗначенияСохраняются(t *testing.T) {
	env := map[string]string{
		"CLAUDE_PROXY_UPSTREAM":     "https://edge.example.com:9443",
		"CLAUDE_PROXY_UPSTREAM_KEY": "EDGE",
		"CLAUDE_PROXY_LISTEN":       "[::1]:9443",
		"ANTHROPIC_AUTH_TOKEN":      "sk-ant-oat01-x",
	}
	plan, err := planFrom(t, []string{"--tokens", "mine:abc"}, env, true)
	if err != nil {
		t.Fatal(err)
	}
	if plan.cfg.Listen != "[::1]:9443" {
		t.Errorf("адрес из файла настроек должен перекрывать умолчание: %q", plan.cfg.Listen)
	}
	if plan.token != "abc" {
		t.Errorf("явный пропуск должен уходить claude как есть: %q", plan.token)
	}
}

func TestPlanLocalРежимAPIKeyБезТокенаПодписки(t *testing.T) {
	env := map[string]string{
		"CLAUDE_PROXY_UPSTREAM":     "https://edge.example.com:9443",
		"CLAUDE_PROXY_UPSTREAM_KEY": "EDGE",
	}
	plan, err := planFrom(t, []string{"--mode", "apikey", "--api-key", "sk-ant-api03-x"}, env, true)
	if err != nil {
		t.Fatalf("в apikey токен подписки не нужен: %v", err)
	}
	if plan.authToken != "" {
		t.Errorf("authToken в apikey = %q", plan.authToken)
	}
}
