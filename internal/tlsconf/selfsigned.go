package tlsconf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// DefaultSelfSignedDays — срок самоподписанного сертификата.
// 825 дней — верхний предел, который ещё принимают браузеры и Node.
const DefaultSelfSignedDays = 825

// GenerateSelfSigned создаёт пару fullchain.pem / privkey.pem в каталоге dir.
//
// Имя попадает в subjectAltName — в DNS или в IP, смотря что передано.
// Только CN недостаточно: Node.js его игнорирует и проверяет исключительно SAN.
//
// Сертификат помечен как CA, потому что на клиентах он же служит якорем
// доверия (NODE_EXTRA_CA_CERTS указывает прямо на него).
func GenerateSelfSigned(name, dir string, days int) error {
	if name == "" {
		return fmt.Errorf("не задано имя для сертификата")
	}
	if days <= 0 {
		return fmt.Errorf("срок действия должен быть положительным, получено %d", days)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("генерация ключа: %w", err)
	}

	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		return fmt.Errorf("генерация серийного номера: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour), // запас на расхождение часов
		NotAfter:              now.AddDate(0, 0, days),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if ip := net.ParseIP(name); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{name}
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("выпуск сертификата: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("сериализация ключа: %w", err)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("каталог %s: %w", dir, err)
	}
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")

	if err := writePEM(certPath, 0o644, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return err
	}
	if err := writePEM(keyPath, 0o600, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return err
	}
	return nil
}

func writePEM(path string, mode os.FileMode, block *pem.Block) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("запись %s: %w", path, err)
	}
	defer f.Close()

	if err := pem.Encode(f, block); err != nil {
		return fmt.Errorf("запись %s: %w", path, err)
	}
	// Права выставляем явно: существующий файл O_CREATE не переоткрывает режим.
	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("права на %s: %w", path, err)
	}
	return f.Close()
}

func parseLeaf(der []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(der)
}
