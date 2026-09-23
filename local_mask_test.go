package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seredavin/claude-proxy/internal/mask"
)

func TestPlanLocalПравилаМаскированияИзОкружения(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.rules")
	bad := filepath.Join(dir, "bad.rules")
	if err := os.WriteFile(good, []byte("host *.corp.local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("regex X (\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"CLAUDE_PROXY_UPSTREAM":     "https://edge.example.com:9443",
		"CLAUDE_PROXY_UPSTREAM_KEY": "EDGE",
		"ANTHROPIC_AUTH_TOKEN":      "sk-ant-oat01-x",
		"CLAUDE_PROXY_MASK_RULES":   good,
	}
	plan, err := planFrom(t, nil, env, true)
	if err != nil {
		t.Fatal(err)
	}
	if plan.cfg.Mask == nil || plan.cfg.MaskRules != good {
		t.Errorf("правила не загружены: %+v", plan.cfg)
	}

	env["CLAUDE_PROXY_MASK_RULES"] = bad
	if _, err := planFrom(t, nil, env, true); err == nil || !strings.Contains(err.Error(), bad+":1") {
		t.Errorf("ожидался отказ с файлом и строкой, получено %v", err)
	}
}

func TestPlanLocalКлючМаскирования(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "mask.rules")
	key := filepath.Join(dir, "mask.key")
	if err := os.WriteFile(rules, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := mask.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte(k+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"CLAUDE_PROXY_UPSTREAM":      "https://edge.example.com:9443",
		"CLAUDE_PROXY_UPSTREAM_KEY":  "EDGE",
		"ANTHROPIC_AUTH_TOKEN":       "sk-ant-oat01-x",
		"CLAUDE_PROXY_MASK_RULES":    rules,
		"CLAUDE_PROXY_MASK_KEY_FILE": key,
	}
	plan, err := planFrom(t, nil, env, true)
	if err != nil {
		t.Fatal(err)
	}
	if plan.cfg.MaskKey == nil {
		t.Error("ключ не загружен")
	}

	// Открытые права — отказ до запуска claude.
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := planFrom(t, nil, env, true); err == nil || !strings.Contains(err.Error(), key) {
		t.Errorf("ожидался отказ с путём ключа, получено %v", err)
	}
}
