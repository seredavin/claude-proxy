package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seredavin/claude-proxy/internal/mask"
)

func writeMaskKey(t *testing.T, key string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mask.key")
	if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// tagFor выдаёт метку через реестр — так же, как шлюз в режиме меток.
func tagFor(t *testing.T, key, value string) string {
	t.Helper()
	k, err := mask.ParseKey(key)
	if err != nil {
		t.Fatal(err)
	}
	rules, _ := mask.ParseRules(strings.NewReader("secret "+value), "rules")
	s := mask.NewRegistry(rules, mask.Options{Key: k, Tags: true}).Session("t")
	out, _, err := s.MaskRequest([]byte(`{"v":"` + value + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(strings.TrimPrefix(string(out), `{"v":"`), `"}`)
}

func TestUnmask(t *testing.T) {
	own, _ := mask.GenerateKey()
	alien, _ := mask.GenerateKey()
	path := writeMaskKey(t, own)
	mine, theirs := tagFor(t, own, "hunter2"), tagFor(t, alien, "hunter2")

	var stdout, stderr bytes.Buffer
	in := strings.NewReader("pw " + mine + " and " + theirs + "\n")
	noenv := func(string) string { return "" }
	if err := cmdUnmask([]string{"--mask-key-file", path}, noenv, in, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "pw hunter2 and "+theirs+"\n" {
		t.Errorf("stdout = %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "не расшифровано меток: 1") {
		t.Errorf("stderr = %q", stderr.String())
	}

	// Ключ из переменной окружения.
	stdout.Reset()
	env := func(name string) string {
		if name == "CLAUDE_PROXY_MASK_KEY_FILE" {
			return path
		}
		return ""
	}
	if err := cmdUnmask(nil, env, strings.NewReader(mine), &stdout, &stderr); err != nil || stdout.String() != "hunter2" {
		t.Errorf("из переменной: %q, %v", stdout.String(), err)
	}

	if err := cmdUnmask(nil, noenv, strings.NewReader(""), &stdout, &stderr); err == nil {
		t.Error("без ключа команда должна отказать")
	}
}
