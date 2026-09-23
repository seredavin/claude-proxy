package mask

import (
	"crypto/cipher"
	"encoding/binary"
)

// feistelRounds — число раундов сети Фейстеля, как в NIST FF1.
const feistelRounds = 10

// feistelKey — перестановка чисел шириной 1..64 бит: сеть Фейстеля с
// раундовой функцией на AES. Твик и домен входят в раундовую функцию, так
// что одна пара «ключ, домен» с разными твиками даёт независимые
// перестановки.
type feistelKey struct {
	block cipher.Block
}

// round — раундовая функция: AES от (раунд, ширина, домен, твик, половина),
// обрезанный до bits бит.
func (f feistelKey) round(i int, width uint, domain byte, tweak uint64, half uint64, bits uint) uint64 {
	var in, out [16]byte
	in[0] = byte(i)
	in[1] = byte(width)
	in[2] = domain
	binary.BigEndian.PutUint64(in[4:12], tweak)
	binary.BigEndian.PutUint32(in[12:16], uint32(half))
	f.block.Encrypt(out[:], in[:])
	return binary.BigEndian.Uint64(out[:8]) & mask64(bits)
}

func mask64(bits uint) uint64 {
	if bits >= 64 {
		return ^uint64(0)
	}
	return 1<<bits - 1
}

// encrypt переставляет x шириной width бит.
func (f feistelKey) encrypt(x uint64, width uint, domain byte, tweak uint64) uint64 {
	u := width / 2
	v := width - u
	a, b := x>>v, x&mask64(v)
	for i := 0; i < feistelRounds; i++ {
		m := u
		if i%2 == 1 {
			m = v
		}
		c := a ^ f.round(i, width, domain, tweak, b, m)
		a, b = b, c
	}
	return a<<v | b
}

// decrypt — обратная к encrypt.
func (f feistelKey) decrypt(y uint64, width uint, domain byte, tweak uint64) uint64 {
	u := width / 2
	v := width - u
	a, b := y>>v, y&mask64(v)
	for i := feistelRounds - 1; i >= 0; i-- {
		m := u
		if i%2 == 1 {
			m = v
		}
		a, b = b^f.round(i, width, domain, tweak, a, m), a
	}
	return a<<v | b
}

// encryptRange переставляет x внутри [lo, hi] cycle walking'ом: шифруем,
// пока результат не попадёт в диапазон. Значения вне диапазона остаются
// на месте — это неподвижные точки (адрес сети, широковещательный).
func (f feistelKey) encryptRange(x uint64, width uint, lo, hi uint64, domain byte, tweak uint64) uint64 {
	if x < lo || x > hi {
		return x
	}
	for {
		x = f.encrypt(x, width, domain, tweak)
		if x >= lo && x <= hi {
			return x
		}
	}
}

// decryptRange — обратная к encryptRange.
func (f feistelKey) decryptRange(y uint64, width uint, lo, hi uint64, domain byte, tweak uint64) uint64 {
	if y < lo || y > hi {
		return y
	}
	for {
		y = f.decrypt(y, width, domain, tweak)
		if y >= lo && y <= hi {
			return y
		}
	}
}
