package config

import (
	"testing"
)

func TestOpenAIUpstreams(t *testing.T) {
	for _, tc := range []struct {
		name, general, routes, legacy string
		wantA, wantB                  string
	}{
		{"общий OpenAI", "personal:gpt-test", "", "b=https://edge.example", "personal", ""},
		{"OpenAI по метке", "", "b=work:gpt-test", "", "", "work"},
		{"два профиля", "personal:gpt-test", "b=work:gpt-test", "", "personal", "work"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := Defaults()
			raw.TLS, raw.Listen, raw.Tokens = "none", "127.0.0.1:0", "a:AAA,b:BBB"
			raw.OpenAIUpstream, raw.OpenAIRoutes, raw.UpstreamRoutes = tc.general, tc.routes, tc.legacy
			cfg, err := Resolve(raw)
			if err != nil {
				t.Fatal(err)
			}
			for label, want := range map[string]string{"a": tc.wantA, "b": tc.wantB} {
				target := cfg.OpenAIFor(label)
				if want == "" && target == nil {
					continue
				}
				if target == nil || target.Profile != want || target.Model != "gpt-test" {
					t.Errorf("метка %s: %#v", label, target)
				}
			}
		})
	}
}

func TestConflictingOpenAIUpstreams(t *testing.T) {
	for _, tc := range []struct{ general, routes, legacy, keys string }{
		{"personal:gpt", "", "", "key"},
		{"../personal:gpt", "", "", ""},
		{"personal:", "", "", ""},
		{"", "a=work:gpt", "a=https://edge.example", ""},
		{"", "a=work:gpt,a=other:gpt", "", ""},
		{"", "missing=work:gpt", "", ""},
	} {
		raw := Defaults()
		raw.TLS, raw.Listen, raw.Tokens = "none", "127.0.0.1:0", "a:AAA"
		raw.OpenAIUpstream, raw.OpenAIRoutes = tc.general, tc.routes
		raw.UpstreamRoutes, raw.UpstreamKey = tc.legacy, tc.keys
		if _, err := Resolve(raw); err == nil {
			t.Errorf("ожидался отказ для %+v", tc)
		}
	}
}

func TestOpenAIModelAliases(t *testing.T) {
	target, err := parseOpenAITarget("personal:gpt-fast=gpt-fast-upstream|gpt-strong=gpt-strong-upstream")
	if err != nil {
		t.Fatal(err)
	}
	if model, ok := target.ResolveModel("gpt-fast"); !ok || model != "gpt-fast-upstream" {
		t.Errorf("псевдоним преобразован в %q", model)
	}
	if _, ok := target.ResolveModel("gpt-fast-upstream"); ok {
		t.Error("прямой идентификатор OpenAI нельзя использовать без псевдонима")
	}
	for _, invalid := range []string{"personal:a=b|a=c", "personal:a=b|claude-a=c", "personal:a=b|", "personal:a=", "personal:a=b|fixed"} {
		if _, err := parseOpenAITarget(invalid); err == nil {
			t.Errorf("невалидный формат принят: %s", invalid)
		}
	}
	fixed, err := parseOpenAITarget("personal:gpt-fixed")
	if err != nil {
		t.Fatal(err)
	}
	if model, ok := fixed.ResolveModel("claude-model"); !ok || model != "gpt-fixed" {
		t.Error("поведение фиксированной модели изменилось")
	}
}

func TestClientOAuthRequiresTLSAndGatewayOAuth(t *testing.T) {
	raw := Defaults()
	raw.Tokens = "gpt:gateway"
	raw.OpenAIRoutes = "gpt=@client:fast=gpt-test"
	raw.TLS, raw.CertFile, raw.KeyFile = "files", "server.crt", "server.key"
	cfg, err := Resolve(raw)
	if err != nil || cfg.OpenAIFor("gpt") == nil || !cfg.OpenAIFor("gpt").ClientOAuth || cfg.OpenAIFor("gpt").Profile != "" {
		t.Fatalf("не принят клиентский маршрут: %v", err)
	}
	raw.Mode = "apikey"
	if _, err := Resolve(raw); err == nil {
		t.Fatal("клиентский OAuth принят в режиме apikey")
	}
	raw.Mode, raw.TLS, raw.Listen = "oauth", "none", "127.0.0.1:0"
	if _, err := Resolve(raw); err == nil {
		t.Fatal("клиентский OAuth принят без TLS")
	}
}
