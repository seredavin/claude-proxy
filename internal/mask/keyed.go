package mask

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"strings"
)

// Домены перестановок: одна пара «ключ, домен» — одна перестановка.
const (
	domNet10 byte = iota + 1
	domNet172
	domNet192
	domNetULA
	domHost4
	domHost6
)

var (
	net10  = netip.MustParsePrefix("10.0.0.0/8")
	net172 = netip.MustParsePrefix("172.16.0.0/12")
	net192 = netip.MustParsePrefix("192.168.0.0/16")
)

// maxNetProbes — предел проб суррогатной сети публичного адреса.
const maxNetProbes = 64

// --- Приватные IPv4 ---

// maskPrivate4 шифрует приватный IPv4: сеть внутри диапазона класса,
// хост — с твиком реальной сети. Адреса одной /24 остаются в одной /24.
func (k *Key) maskPrivate4(a netip.Addr) netip.Addr {
	b := a.As4()
	realNet := binary.BigEndian.Uint32(b[:]) &^ 0xff
	switch {
	case net10.Contains(a):
		n := k.ip4Net.encrypt(uint64(b[1])<<8|uint64(b[2]), 16, domNet10, 0)
		b[1], b[2] = byte(n>>8), byte(n)
	case net172.Contains(a):
		n := k.ip4Net.encrypt(uint64(b[1]&0x0f)<<8|uint64(b[2]), 12, domNet172, 0)
		b[1], b[2] = 0x10|byte(n>>8), byte(n)
	default:
		b[2] = byte(k.ip4Net.encrypt(uint64(b[2]), 8, domNet192, 0))
	}
	b[3] = k.host4(realNet, b[3])
	return netip.AddrFrom4(b)
}

// revealPrivate4 — обратная к maskPrivate4: сначала сеть, затем хост по
// восстановленной сети.
func (k *Key) revealPrivate4(a netip.Addr) netip.Addr {
	b := a.As4()
	switch {
	case net10.Contains(a):
		n := k.ip4Net.decrypt(uint64(b[1])<<8|uint64(b[2]), 16, domNet10, 0)
		b[1], b[2] = byte(n>>8), byte(n)
	case net172.Contains(a):
		n := k.ip4Net.decrypt(uint64(b[1]&0x0f)<<8|uint64(b[2]), 12, domNet172, 0)
		b[1], b[2] = 0x10|byte(n>>8), byte(n)
	default:
		b[2] = byte(k.ip4Net.decrypt(uint64(b[2]), 8, domNet192, 0))
	}
	realNet := binary.BigEndian.Uint32(b[:]) &^ 0xff
	b[3] = byte(k.ip4Host.decryptRange(uint64(b[3]), 8, 1, 254, domHost4, uint64(realNet)))
	return netip.AddrFrom4(b)
}

// host4 — номер хоста IPv4 внутри 1..254; 0 и 255 остаются на месте.
func (k *Key) host4(realNet uint32, host byte) byte {
	return byte(k.ip4Host.encryptRange(uint64(host), 8, 1, 254, domHost4, uint64(realNet)))
}

// --- ULA IPv6 ---

// maskULA шифрует адрес из fc00::/7: первый байт (fc/fd) сохраняется,
// 56 бит сети переставляются, 64 бита хоста — с твиком реальной сети.
func (k *Key) maskULA(a netip.Addr) netip.Addr {
	b := a.As16()
	realPrefix := binary.BigEndian.Uint64(b[:8])
	n := k.ip6Net.encrypt(realPrefix&mask64(56), 56, domNetULA, 0)
	binary.BigEndian.PutUint64(b[:8], realPrefix&^mask64(56)|n)
	binary.BigEndian.PutUint64(b[8:], k.host6(realPrefix, binary.BigEndian.Uint64(b[8:])))
	return netip.AddrFrom16(b)
}

func (k *Key) revealULA(a netip.Addr) netip.Addr {
	b := a.As16()
	surPrefix := binary.BigEndian.Uint64(b[:8])
	n := k.ip6Net.decrypt(surPrefix&mask64(56), 56, domNetULA, 0)
	realPrefix := surPrefix&^mask64(56) | n
	binary.BigEndian.PutUint64(b[:8], realPrefix)
	host := k.ip6Host.decryptRange(binary.BigEndian.Uint64(b[8:]), 64, 1, ^uint64(0), domHost6, realPrefix)
	binary.BigEndian.PutUint64(b[8:], host)
	return netip.AddrFrom16(b)
}

// host6 — 64 бита хоста IPv6; нулевой хост (anycast маршрутизатора
// подсети) остаётся на месте.
func (k *Key) host6(realPrefix, host uint64) uint64 {
	return k.ip6Host.encryptRange(host, 64, 1, ^uint64(0), domHost6, realPrefix)
}

// --- Публичные адреса ---

// publicNet — суррогатная сеть для реальной публичной /24 (/64) на пробе
// probe: IPv4 — /24 из 100.64.0.0/10, IPv6 — /64 из 2001:db8::/32.
func (k *Key) publicNet(realNet netip.Prefix, probe int) netip.Prefix {
	m := hmac.New(sha256.New, k.pubNet)
	if realNet.Addr().Is4() {
		b := realNet.Addr().As4()
		m.Write([]byte{4})
		m.Write(b[:3])
		m.Write([]byte{byte(probe)})
		sum := m.Sum(nil)
		idx := binary.BigEndian.Uint16(sum[:2]) & 0x3fff
		return netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64 | byte(idx>>8), byte(idx), 0}), 24)
	}
	b := realNet.Addr().As16()
	m.Write([]byte{6})
	m.Write(b[:8])
	m.Write([]byte{byte(probe)})
	sum := m.Sum(nil)
	var s [16]byte
	s[0], s[1], s[2], s[3] = 0x20, 0x01, 0x0d, 0xb8
	copy(s[4:8], sum[:4])
	return netip.PrefixFrom(netip.AddrFrom16(s), 64)
}

// keyedIP — суррогат адреса по ключу. Вызывается под s.mu: публичные
// адреса закрепляют сеть в таблице сессии.
func (s *Session) keyedIP(value string) (string, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return "", err
	}
	k := s.key
	switch {
	case addr.Is4() && isPrivate(addr):
		return k.maskPrivate4(addr).String(), nil
	case addr.Is6() && ulaV6.Contains(addr):
		return k.maskULA(addr).String(), nil
	}

	bits := 24
	if addr.Is6() {
		bits = 64
	}
	realNet, _ := addr.Prefix(bits)
	surNet, ok := s.nets[realNet]
	if !ok {
		for probe := 0; ; probe++ {
			if probe == maxNetProbes {
				return "", fmt.Errorf("исчерпан пул суррогатных сетей для %s", value)
			}
			cand := k.publicNet(realNet, probe)
			if !s.usedNets[cand] {
				surNet = cand
				break
			}
		}
		s.nets[realNet] = surNet
		s.usedNets[surNet] = true
	}
	if addr.Is4() {
		b := addr.As4()
		sb := surNet.Addr().As4()
		sb[3] = k.host4(binary.BigEndian.Uint32(b[:])&^0xff, b[3])
		return netip.AddrFrom4(sb).String(), nil
	}
	b := addr.As16()
	sb := surNet.Addr().As16()
	binary.BigEndian.PutUint64(sb[8:], k.host6(binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])))
	return netip.AddrFrom16(sb).String(), nil
}

// RevealIP восстанавливает приватный адрес по суррогату. Публичные адреса
// ключом не восстанавливаются: их сети вычислены хешем, а не шифром.
func (k *Key) RevealIP(sur string) (string, error) {
	a, err := netip.ParseAddr(sur)
	if err != nil {
		return "", err
	}
	switch {
	case a.Is4() && isPrivate(a):
		return k.revealPrivate4(a).String(), nil
	case a.Is6() && ulaV6.Contains(a):
		return k.revealULA(a).String(), nil
	}
	return "", fmt.Errorf("суррогат публичного адреса %s ключом не восстанавливается", sur)
}

// --- Имена хостов ---

// hostAlphabet — символы имени хоста; имя упаковывается в число по
// основанию len+1 (цифра 0 не используется, поэтому ведущие символы не
// теряются).
const hostAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789-._"

var (
	hostRadix    = big.NewInt(int64(len(hostAlphabet) + 1))
	hostEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

	// errHostUnkeyable — имя нельзя зашифровать в суррогат: чужие символы
	// или суррогат длиннее 253 символов. Вызывающий берёт host-N.example.
	errHostUnkeyable = errors.New("имя хоста не шифруется в суррогат")
)

const (
	hostTagSize = 8
	hostPrefix  = "host-"
	hostSuffix  = ".example"
	maxDNSLabel = 63
	maxDNSName  = 253
)

// maskHost шифрует имя (в нижнем регистре) в host-<base32>.example.
// Схема SIV: тег — HMAC от открытого текста, он же IV для AES-CTR. Одно
// имя — один суррогат, разные имена — разные, чужой ключ не сходится с
// тегом.
func (k *Key) maskHost(name string) (string, error) {
	if name == "" || len(name) > maxDNSName {
		return "", errHostUnkeyable
	}
	n := new(big.Int)
	for i := len(name) - 1; i >= 0; i-- {
		d := strings.IndexByte(hostAlphabet, name[i])
		if d < 0 {
			return "", errHostUnkeyable
		}
		n.Mul(n, hostRadix)
		n.Add(n, big.NewInt(int64(d+1)))
	}
	packed := n.Bytes()

	m := hmac.New(sha256.New, k.nameMAC)
	m.Write(packed)
	tag := m.Sum(nil)[:hostTagSize]
	out := make([]byte, hostTagSize+len(packed))
	copy(out, tag)
	k.hostStream(tag).XORKeyStream(out[hostTagSize:], packed)

	token := hostEncoding.EncodeToString(out)
	var labels []string
	for first := true; token != ""; first = false {
		size := maxDNSLabel
		if first {
			size -= len(hostPrefix)
		}
		if size > len(token) {
			size = len(token)
		}
		labels = append(labels, token[:size])
		token = token[size:]
	}
	sur := hostPrefix + strings.Join(labels, ".") + hostSuffix
	if len(sur) > maxDNSName {
		return "", errHostUnkeyable
	}
	return sur, nil
}

func (k *Key) hostStream(tag []byte) cipher.Stream {
	iv := make([]byte, 16)
	copy(iv, tag)
	return cipher.NewCTR(k.nameEnc, iv)
}

// RevealHost восстанавливает имя хоста (в нижнем регистре) по суррогату.
func (k *Key) RevealHost(sur string) (string, error) {
	if !strings.HasPrefix(sur, hostPrefix) || !strings.HasSuffix(sur, hostSuffix) {
		return "", fmt.Errorf("%q — не суррогат хоста", sur)
	}
	token := strings.ReplaceAll(sur[len(hostPrefix):len(sur)-len(hostSuffix)], ".", "")
	raw, err := hostEncoding.DecodeString(token)
	if err != nil || len(raw) <= hostTagSize {
		return "", fmt.Errorf("%q — не суррогат хоста", sur)
	}
	tag := raw[:hostTagSize]
	packed := make([]byte, len(raw)-hostTagSize)
	k.hostStream(tag).XORKeyStream(packed, raw[hostTagSize:])
	m := hmac.New(sha256.New, k.nameMAC)
	m.Write(packed)
	if !hmac.Equal(tag, m.Sum(nil)[:hostTagSize]) {
		return "", fmt.Errorf("суррогат %q не сходится с ключом", sur)
	}
	n := new(big.Int).SetBytes(packed)
	var b strings.Builder
	d := new(big.Int)
	for n.Sign() > 0 {
		n.DivMod(n, hostRadix, d)
		i := int(d.Int64())
		if i == 0 {
			return "", fmt.Errorf("суррогат %q повреждён", sur)
		}
		b.WriteByte(hostAlphabet[i-1])
	}
	return b.String(), nil
}
