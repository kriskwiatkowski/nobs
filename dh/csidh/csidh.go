package csidh

import (
	"io"
)

// 511-bit number representing prime field element GF(p)
type fp [numWords]uint64

// Represents projective point on elliptic curve E over fp
type point struct {
	x fp
	z fp
}

// Curve coefficients
type coeff struct {
	a fp
	c fp
}

type fpRngGen struct {
	// working buffer needed to avoid memory allocation
	wbuf [64]byte
}

// Defines operations on public key
type PublicKey struct {
	fpRngGen
	// Montgomery coefficient: represents y^2 = x^3 + Ax^2 + x
	a fp
}

// Defines operations on private key
type PrivateKey struct {
	fpRngGen
	e [PrivateKeySize]int8
}

// randFp generates random element from Fp
func (s *fpRngGen) randFp(v *fp, rng io.Reader) {
	mask := uint64(1<<(pbits%limbBitSize)) - 1
	for {
		*v = fp{}
		_, err := io.ReadFull(rng, s.wbuf[:])
		if err != nil {
			panic("Can't read random number")
		}

		for i := 0; i < len(s.wbuf); i++ {
			j := i / limbByteSize
			k := uint(i % 8)
			v[j] |= uint64(s.wbuf[i]) << (8 * k)
		}

		v[len(v)-1] &= mask
		if isLess(v, &p) {
			return
		}
	}
}

func cofactorMultiples(p *point, a *coeff, halfL, halfR int, order *fp) (bool, bool) {
	var Q point
	var r1, d1, r2, d2 bool

	if (halfR - halfL) == 1 {
		if !p.z.isZero() {
			var tmp = fp{primes[halfL]}
			xMul512(p, p, a, &tmp)

			if !p.z.isZero() {
				// order does not divide p+1
				return false, true
			}

			mul512(order, order, primes[halfL])
			if sub512(&tmp, &fourSqrtP, order) == 1 {
				// order > 4*sqrt(p) -> supersingular
				return true, true
			}
		}
		return false, false
	}

	// perform another recursive step
	mid := halfL + ((halfR - halfL + 1) / 2)
	var mulL, mulR = fp{1}, fp{1}
	for i := halfL; i < mid; i++ {
		mul512(&mulR, &mulR, primes[i])
	}
	for i := mid; i < halfR; i++ {
		mul512(&mulL, &mulL, primes[i])
	}

	xMul512(&Q, p, a, &mulR)
	xMul512(p, p, a, &mulL)

	r1, d1 = cofactorMultiples(&Q, a, mid, halfR, order)
	r2, d2 = cofactorMultiples(p, a, halfL, mid, order)
	return r1 || r2, d1 || d2
}

func groupAction(pub *PublicKey, prv *PrivateKey, rng io.Reader) {
	var k [2]fp
	var e [2][primeCount]uint8
	var done = [2]bool{false, false}
	var A = coeff{a: pub.a, c: one}

	k[0][0] = 4
	k[1][0] = 4

	for i, v := range primes {
		t := (prv.e[uint(i)>>1] << ((uint(i) % 2) * 4)) >> 4
		if t > 0 {
			e[0][i] = uint8(t)
			e[1][i] = 0
			mul512(&k[1], &k[1], v)
		} else if t < 0 {
			e[1][i] = uint8(-t)
			e[0][i] = 0
			mul512(&k[0], &k[0], v)
		} else {
			e[0][i] = 0
			e[1][i] = 0
			mul512(&k[0], &k[0], v)
			mul512(&k[1], &k[1], v)
		}
	}

	for {
		var P point
		var rhs fp
		prv.randFp(&P.x, rng)
		P.z = one
		montEval(&rhs, &A.a, &P.x)
		sign := rhs.isNonQuadRes()

		if done[sign] {
			continue
		}

		xMul512(&P, &P, &A, &k[sign])
		done[sign] = true

		for i, v := range primes {
			if e[sign][i] != 0 {
				var cof = fp{1}
				var K point

				for j := i + 1; j < len(primes); j++ {
					if e[sign][j] != 0 {
						mul512(&cof, &cof, primes[j])
					}
				}

				xMul512(&K, &P, &A, &cof)
				if !K.z.isZero() {
					isom(&P, &A, &K, v)
					e[sign][i] = e[sign][i] - 1
					if e[sign][i] == 0 {
						mul512(&k[sign], &k[sign], primes[i])
					}
				}
			}
			done[sign] = done[sign] && (e[sign][i] == 0)
		}

		modExpRdc512(&A.c, &A.c, &pMin1)
		mulRdc(&A.a, &A.a, &A.c)
		A.c = one

		if done[0] && done[1] {
			break
		}
	}
	pub.a = A.a
}

// PrivateKey operations

func (c *PrivateKey) Import(key []byte) bool {
	if len(key) < len(c.e) {
		return false
	}
	for i, v := range key {
		c.e[i] = int8(v)
	}
	return true
}

func (c PrivateKey) Export(out []byte) bool {
	if len(out) < len(c.e) {
		return false
	}
	for i, v := range c.e {
		out[i] = byte(v)
	}
	return true
}

func GeneratePrivateKey(key *PrivateKey, rng io.Reader) error {
	for i := range key.e {
		key.e[i] = 0
	}

	for i := 0; i < len(primes); {
		_, err := io.ReadFull(rng, key.wbuf[:])
		if err != nil {
			return err
		}

		for j := range key.wbuf {
			if int8(key.wbuf[j]) <= expMax && int8(key.wbuf[j]) >= -expMax {
				key.e[i>>1] |= int8((key.wbuf[j] & 0xF) << uint((i%2)*4))
				i = i + 1
				if i == len(primes) {
					break
				}
			}
		}
	}
	return nil
}

// Public key operations

// Assumes key is in Montgomery domain
func (c *PublicKey) Import(key []byte) bool {
	if len(key) != numWords*limbByteSize {
		return false
	}
	for i := 0; i < len(key); i++ {
		j := i / limbByteSize
		k := uint64(i % 8)
		c.a[j] |= uint64(key[i]) << (8 * k)
	}
	return true
}

// Assumes key is exported as encoded in Montgomery domain
func (c *PublicKey) Export(out []byte) bool {
	if len(out) != numWords*limbByteSize {
		return false
	}
	for i := 0; i < len(out); i++ {
		j := i / limbByteSize
		k := uint64(i % 8)
		out[i] = byte(c.a[j] >> (8 * k))
	}
	return true
}

func (c *PublicKey) reset() {
	for i := range c.a {
		c.a[i] = 0
	}
}

func GeneratePublicKey(pub *PublicKey, prv *PrivateKey, rng io.Reader) {
	pub.reset()
	groupAction(pub, prv, rng)
}

// Validate does public key validation. It returns true if
// a 'pub' is a valid cSIDH public key, otherwise false.
func Validate(pub *PublicKey, rng io.Reader) bool {
	// Check if in range
	if !isLess(&pub.a, &p) {
		return false
	}

	// j-invariant for montgomery curves is something like
	// j = (256*(A^3-3)^3)/(A^2 - 4), so any |A| = 2 is invalid
	if pub.a.equal(&two) || pub.a.equal(&twoNeg) {
		return false
	}

	// P must have big enough order to prove supersingularity. The
	// probability that this loop will be repeated is negligible.
	for {
		var P point
		var A = point{pub.a, one}

		pub.randFp(&P.x, rng)
		P.z = one

		xDbl(&P, &P, &A)
		xDbl(&P, &P, &A)

		res, done := cofactorMultiples(&P, &coeff{A.x, A.z}, 0, len(primes), &fp{1})
		if done {
			return res
		}
	}
}

// DeriveSecret computes a cSIDH shared secret. If successful, returns true
// and fills 'out' with shared secret. Function returns false in case 'pub' is invalid.
func DeriveSecret(out *[64]byte, pub *PublicKey, prv *PrivateKey, rng io.Reader) bool {
	if !Validate(pub, rng) {
		return false
	}
	groupAction(pub, prv, rng)
	pub.Export(out[:])
	return true
}
