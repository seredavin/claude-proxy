package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seredavin/claude-proxy/internal/config"
)

func TestEnvLinesМаскирование(t *testing.T) {
	raw := config.Defaults()
	raw.Tokens = "default:abc"
	without := strings.Join(envLines(raw), "\n")
	if strings.Contains(without, "CLAUDE_PROXY_MASK") {
		t.Errorf("без настроек маскирования переменных быть не должно:\n%s", without)
	}

	raw.MaskRules = "/etc/claude-proxy/mask.rules"
	raw.MaskOnError = "open"
	raw.MaskDebug = "true"
	with := strings.Join(envLines(raw), "\n")
	for _, want := range []string{
		`CLAUDE_PROXY_MASK_RULES="/etc/claude-proxy/mask.rules"`,
		`CLAUDE_PROXY_MASK_ON_ERROR="open"`,
		`CLAUDE_PROXY_MASK_DEBUG="true"`,
	} {
		if !strings.Contains(with, want) {
			t.Errorf("нет %s:\n%s", want, with)
		}
	}
}

func TestФайлПравилНедоступенСервисномуПользователю(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mask.rules")
	if err := os.WriteFile(path, []byte("ip all\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Чужой uid без прав на файл 600 — как claude-proxy при файле root:600.
	err := rulesReadableBy(path, os.Getuid()+1, os.Getgid()+1, "claude-proxy")
	if err == nil || !strings.Contains(err.Error(), "setfacl -m u:claude-proxy:r "+path) {
		t.Errorf("err = %v", err)
	}
	if err := rulesReadableBy(path, os.Getuid(), os.Getgid(), "me"); err != nil {
		t.Errorf("владелец должен читать: %v", err)
	}
}
