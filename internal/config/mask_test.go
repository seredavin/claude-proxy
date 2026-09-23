package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seredavin/claude-proxy/internal/mask"
)

// maskBase — минимальный набор флагов, с которым Resolve проходит.
var maskBase = []string{"--tls", "files", "--cert-file", "c.pem", "--key-file", "k.pem", "--tokens", "t"}

func writeRules(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mask.rules")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestМаскированиеВыключеноБезФайлаПравил(t *testing.T) {
	cfg, _, err := load(t, maskBase, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mask != nil || cfg.MaskRules != "" || cfg.MaskOnError != MaskClosed || cfg.MaskDebug {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestМаскированиеЗагружаетПравила(t *testing.T) {
	path := writeRules(t, "# пусто\n")
	cfg, _, err := load(t, append(append([]string{}, maskBase...), "--mask-rules", path, "--mask-on-error", "open", "--mask-debug"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mask == nil || cfg.MaskOnError != MaskOpen || !cfg.MaskDebug {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestМаскированиеОшибкаВПравилахСНомеромСтроки(t *testing.T) {
	path := writeRules(t, "host a\nregex X (\n")
	_, _, err := load(t, append(append([]string{}, maskBase...), "--mask-rules", path), nil)
	if err == nil || !strings.Contains(err.Error(), path+":2") {
		t.Errorf("err = %v", err)
	}
}

func TestМаскированиеОшибкиФлагов(t *testing.T) {
	tests := []struct {
		name string
		args []string
		env  map[string]string
		want string
	}{
		{"on-error без правил", []string{"--mask-on-error", "open"}, nil, "--mask-on-error"},
		{"debug без правил", []string{"--mask-debug"}, nil, "--mask-debug"},
		{"debug из окружения без правил", nil, map[string]string{"CLAUDE_PROXY_MASK_DEBUG": "1"}, "--mask-debug"},
		{"неизвестная политика", []string{"--mask-rules", "x", "--mask-on-error", "maybe"}, nil, "closed или open"},
		{"нет файла", []string{"--mask-rules", "/nonexistent/mask.rules"}, nil, "файл правил"},
	}
	for _, tt := range tests {
		_, _, err := load(t, append(append([]string{}, maskBase...), tt.args...), tt.env)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, ожидалось %q", tt.name, err, tt.want)
		}
	}
}

func TestМаскированиеПеременнаяПеребиваетФлаг(t *testing.T) {
	envPath := writeRules(t, "ip off\n")
	cfg, warnings, err := load(t, append(append([]string{}, maskBase...), "--mask-rules", "/flag/mask.rules"),
		map[string]string{"CLAUDE_PROXY_MASK_RULES": envPath, "CLAUDE_PROXY_MASK_ON_ERROR": "open"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaskRules != envPath || cfg.MaskOnError != MaskOpen {
		t.Errorf("cfg = %+v", cfg)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "--mask-rules") {
		t.Errorf("warnings = %v", warnings)
	}
}

func TestTraceDirИзФлагаИПеременной(t *testing.T) {
	cfg, _, err := load(t, append(append([]string{}, maskBase...), "--trace-dir", "/tmp/trace"), nil)
	if err != nil || cfg.TraceDir != "/tmp/trace" {
		t.Errorf("cfg.TraceDir = %q err = %v", cfg.TraceDir, err)
	}
	cfg, _, err = load(t, maskBase, map[string]string{"CLAUDE_PROXY_TRACE_DIR": "/var/trace"})
	if err != nil || cfg.TraceDir != "/var/trace" {
		t.Errorf("cfg.TraceDir = %q err = %v", cfg.TraceDir, err)
	}
	cfg, _, err = load(t, maskBase, nil)
	if err != nil || cfg.TraceDir != "" {
		t.Errorf("по умолчанию выключено: %q err = %v", cfg.TraceDir, err)
	}
}

func writeKey(t *testing.T, perm os.FileMode) string {
	t.Helper()
	key, err := mask.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mask.key")
	if err := os.WriteFile(path, []byte(key+"\n"), perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestКлючМаскированияИзФлагаИПеременной(t *testing.T) {
	rules := writeRules(t, "")
	key := writeKey(t, 0o600)
	cfg, _, err := load(t, append(append([]string{}, maskBase...), "--mask-rules", rules, "--mask-key-file", key), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaskKey == nil || cfg.MaskKeyFile != key {
		t.Errorf("ключ из флага не загружен: %+v", cfg)
	}
	cfg, _, err = load(t, append(append([]string{}, maskBase...), "--mask-rules", rules),
		map[string]string{"CLAUDE_PROXY_MASK_KEY_FILE": key})
	if err != nil || cfg.MaskKey == nil {
		t.Errorf("ключ из переменной не загружен: %v", err)
	}
}

func TestКлючМаскированияОшибки(t *testing.T) {
	rules := writeRules(t, "")
	open := writeKey(t, 0o644)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"ключ без правил", []string{"--mask-key-file", writeKey(t, 0o600)}, "только вместе с --mask-rules"},
		{"права 644", []string{"--mask-rules", rules, "--mask-key-file", open}, "chmod 600 " + open},
		{"нет файла", []string{"--mask-rules", rules, "--mask-key-file", "/nonexistent/mask.key"}, "ключа маскирования"},
	}
	for _, tt := range tests {
		_, _, err := load(t, append(append([]string{}, maskBase...), tt.args...), nil)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, ожидалось %q", tt.name, err, tt.want)
		}
	}
}
