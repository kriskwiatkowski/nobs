package csidh

import "io"
import "crypto/rand"

// OZAPTF
var buf [8 * limbByteSize]byte

// TODO: this is weird. How do I know loop will end?
func randFp(fp *Fp) {
	//	var buf [len(fp) * limbByteSize]byte
	mask := uint64(1<<(pbits%limbBitSize)) - 1
	for {
		*fp = Fp{}
		if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
			// OZAPTF: to be re-done (AES_CTR)
			panic("Can't read random number")
		}

		for i := 0; i < len(buf); i++ {
			j := i / limbByteSize
			k := uint(i % 8)
			fp[j] |= uint64(buf[i]) << (8 * k)
		}

		fp[len(fp)-1] &= mask
		if checkBigger(&p, fp) {
			return
		}
	}
}

// assumes len(x) == len(y)
// return 1 if equal 0 if not
// OZAPTF: I actually need to know if x is zero
func ctEq64(x, y []uint64) uint {
	var t uint64
	var h, l uint64
	for i := 0; i < len(x); i++ {
		t |= x[i] ^ y[i]
	}

	h = ((t >> 32) - 1) >> 63
	l = ((t & 0xFFFFFFFF) - 1) >> 63
	return uint(h & l & 1)
}

// evaluates x^3 + Ax^2 + x
func montEval(res, A, x *Fp) {
	var t Fp

	*res = *x
	mulRdc(res, res, res)
	mulRdc(&t, A, x)
	addRdc(res, res, &t)
	addRdc(res, res, &fp_1)
	mulRdc(res, res, x)
}

func (c *PrivateKey) Generate(rand io.Reader) error {
	for i, _ := range c.e {
		c.e[i] = 0
	}

	for i := 0; i < len(primes); {
		_, err := io.ReadFull(rand, c.tmp[:])
		if err != nil {
			return err
		}

		for j, _ := range c.tmp {
			if int8(c.tmp[j]) <= expMax && int8(c.tmp[j]) >= -expMax {
				c.e[i>>1] |= int8((c.tmp[j] & 0xf) << uint((i%2)*4))
				i = i + 1
				if i == len(primes) {
					break
				}
			}
		}
	}
	return nil
}

func (c *PublicKey) groupAction(pub *PublicKey, prv *PrivateKey) {
	var k [2]Fp
	var e [2][kPrimeCount]uint8
	var done = [2]bool{false, false}
	var A = Coeff{a: pub.A, c: fp_1}
	var zero [8]uint64

	k[0][0] = 4
	k[1][0] = 4

	for i, v := range primes {
		t := int8((prv.e[uint(i)>>1] << ((uint(i) % 2) * 4)) >> 4)
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
		var P Point
		var rhs Fp
		randFp(&P.x)
		P.z = fp_1
		montEval(&rhs, &A.a, &P.x)
		sign := isNonQuadRes(&rhs)

		if done[sign] {
			continue
		}

		xMul512(&P, &P, &A, &k[sign])
		done[sign] = true

		for i, v := range primes {
			if e[sign][i] != 0 {
				var cof = Fp{1}
				var K Point

				for j := i + 1; j < len(primes); j++ {
					if e[sign][j] != 0 {
						mul512(&cof, &cof, primes[j])
					}
				}

				xMul512(&K, &P, &A, &cof)
				if ctEq64(K.z[:], zero[:]) == 0 {
					MapPoint(&P, &A, &K, v)
					e[sign][i] = e[sign][i] - 1
					if e[sign][i] == 0 {
						mul512(&k[sign], &k[sign], primes[i])
					}
				}
			}
			done[sign] = done[sign] && (e[sign][i] == 0)
		}

		modExpRdc(&A.c, &A.c, &pMin2)
		mulRdc(&A.a, &A.a, &A.c)
		A.c = fp_1

		if done[0] && done[1] {
			break
		}
	}
	c.A = A.a
}

func (c *PublicKey) Generate(prv *PrivateKey) {
	var emptyKey PublicKey
	c.groupAction(&emptyKey, prv)
}

// Assumes lower<upper
// TODO: non constant time
// TODO: this needs to be rewritten - function called recursivelly
/* compute [(p+1)/l] P for all l in our list of primes. */
/* divide and conquer is much faster than doing it naively,
 * but uses more memory. */
var Zero Fp // OZAPTF move somewhere
func cofactorMultiples(p, a *Point, halfL, halfR int, order *Fp) (bool, bool) {
	var A Coeff = Coeff{a.x, a.z}
	if (halfR - halfL) == 1 {
		if !p.z.Equals(&Zero) {
			var tmp Fp = Fp{primes[halfL]}
			xMul512(p, p, &A, &tmp)

			if !p.z.Equals(&Zero) {
				// order does not divide p+1
				return false, true
			}

			mul512(order, order, primes[halfL])
			if sub512(&tmp, &fourSqrtP, order) != 0 {
				// order > 4*sqrt(p) -> supersingular
				return true, true
			}
		}
		// Dunno, point order to halfL to prove shalfRersingularity.
		return false, false
	}

	// perform another recursive step
	mid := halfL + ((halfR - halfL + 1) / 2)
	var mulL, mulR Fp = Fp{1}, Fp{1}
	for i := halfL; i < mid; i++ {
		mul512(&mulR, &mulR, primes[i])
	}
	for i := mid; i < halfR; i++ {
		mul512(&mulL, &mulL, primes[i])
	}

	var Q Point
	xMul512(&Q, p, &A, &mulR)
	xMul512(p, p, &A, &mulL)

	// TODO: make it in for loop instead of calling a function
	//       it won't need to do returns.
	var r1, d1, r2, d2 bool
	r1, d1 = cofactorMultiples(&Q, a, mid, halfR, order)
	r2, d2 = cofactorMultiples(p, a, halfL, mid, order)
	return r1 || r2, d1 || d2
}

// Key validation
func (c *PublicKey) Validate() bool {
	var tmp Fp

	// Check if in range
	if sub512(&tmp, &p, &c.A) == 1 {
		return false
	}

	if c.A.Equals(&p) {
		return false
	}

	// j-invariant for montgomery curves is something like
	// j = (256*(A^3-3)^3)/(A^2 - 4), so any |A| = 2 is invalid
	if c.A.Equals(&two) || c.A.Equals(&minTwo) {
		return false
	}

	// P must have big enough order to prove supersingularity. The
	// probability that this loop will be repeated is negligible.
	// TODO: do max 10 loops
	for {
		var A Point = Point{c.A, fp_1}

		var P Point
		randFp(&P.x)
		P.z = fp_1

		xDbl(&P, &P, &A)
		xDbl(&P, &P, &A)

		var order Fp = Fp{1}
		res, done := cofactorMultiples(&P, &A, 0, len(primes), &order)
		if done {
			return res
		}
		// iterate once again
	}

	return false
}

// todo: probably should be similar to some other interface
// OZAPTF: should be attribute of private key
func (c *PublicKey) DeriveSecret(out []byte, pub *PublicKey, prv *PrivateKey) bool {
	var ss PublicKey
	// TODO: validation doesn't work yet correctly
	if !pub.Validate() {
		randFp(&pub.A)
		return false
	}
	ss.groupAction(pub, prv)
	ss.Export(out)
	return true
}

// TODO:
func init() {
	if len(primes) != kPrimeCount {
		panic("Wrong number of primes")
	}
}
