package mask

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// KeySize — длина ключа маскирования в байтах.
const KeySize = 32

// keyContext — префикс вывода подключей. Версия в нём позволяет сменить
// схему, не путая суррогаты старой и новой.
const keyContext = "claude-proxy/mask/v1/"

// Key — ключ маскирования: с ним суррогаты IP и хостов вычисляются из
// значения, а не выбираются случайно, и обратимы только с этим ключом.
type Key struct {
	ip4Net, ip4Host, ip6Net, ip6Host feistelKey
	pubNet                           []byte
	nameMAC                          []byte
	nameEnc                          cipher.Block
	fingerprint                      string
}

// NewKey выводит из мастер-ключа подключи для каждого назначения.
func NewKey(master []byte) (*Key, error) {
	if len(master) != KeySize {
		return nil, fmt.Errorf("ключ маскирования должен быть %d байт, получено %d", KeySize, len(master))
	}
	sub := func(purpose string) []byte {
		m := hmac.New(sha256.New, master)
		m.Write([]byte(keyContext + purpose))
		return m.Sum(nil)
	}
	block := func(purpose string) cipher.Block {
		b, err := aes.NewCipher(sub(purpose))
		if err != nil {
			// Длина подключа — всегда 32 байта; ошибки здесь не бывает.
			panic("aes: " + err.Error())
		}
		return b
	}
	return &Key{
		ip4Net:      feistelKey{block("ip4-net")},
		ip4Host:     feistelKey{block("ip4-host")},
		ip6Net:      feistelKey{block("ip6-net")},
		ip6Host:     feistelKey{block("ip6-host")},
		pubNet:      sub("pub-net"),
		nameMAC:     sub("name-mac"),
		nameEnc:     block("name-enc"),
		fingerprint: hex.EncodeToString(sub("fingerprint")[:4]),
	}, nil
}

// Fingerprint — 8 hex-символов, вычисленных из ключа необратимо. По нему
// видно, что два процесса работают с одним ключом.
func (k *Key) Fingerprint() string { return k.fingerprint }

// GenerateKey возвращает новый ключ в base64 — строку для файла ключа.
func GenerateKey() (string, error) {
	b := make([]byte, KeySize)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// ParseKey разбирает ключ в base64 — с выравниванием или без.
func ParseKey(s string) (*Key, error) {
	s = strings.TrimSpace(s)
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(s)
	}
	if err != nil {
		return nil, fmt.Errorf("ключ маскирования не похож на base64")
	}
	return NewKey(b)
}

// LoadKeyFile читает и проверяет файл ключа: права закрыты от группы и
// остальных, содержимое — 32 байта в base64.
func LoadKeyFile(path string) (*Key, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("файл ключа маскирования: %w", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("файл ключа маскирования %s доступен группе или остальным (права %04o)\n    закройте доступ: chmod 600 %s",
			path, perm, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("файл ключа маскирования: %w", err)
	}
	k, err := ParseKey(string(data))
	if err != nil {
		return nil, fmt.Errorf("файл ключа маскирования %s: %w (создайте его командой claude-proxy gen-mask-key)", path, err)
	}
	return k, nil
}
