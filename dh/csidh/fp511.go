// +build noasm amd64 arm64 ppc64le riscv64

package csidh

import (
	"math/bits"

	"golang.org/x/sys/cpu"
)

// CPU Capabilities. Those flags are referred by assembly code. According to
// https://github.com/golang/go/issues/28230, variables referred from the
// assembly must be in the same package.
// We declare variables not constants, in order to facilitate testing.
var (
	// Signals support for BMI2 (MULX)
	hasBMI2 = cpu.X86.HasBMI2 //nolint
	// Signals support for ADX and BMI2
	hasADXandBMI2 = cpu.X86.HasBMI2 && cpu.X86.HasADX
)

// Constant time select.
// if pick == 0xFF..FF (out = in1)
// if pick == 0 (out = in2)
// else out is undefined.
func ctPick64(which uint64, in1, in2 uint64) uint64 {
	return (in1 & which) | (in2 & ^which)
}

// ctIsNonZero64 returns 0 in case i == 0, otherwise it returns 1.
// Constant-time.
func ctIsNonZero64(i uint64) int {
	// In case i==0 then i-1 will set MSB. Only in such case (i OR ~(i-1))
	// will result in MSB being not set (logical implication: (i-1)=>i is
	// false iff (i-1)==0 and i==non-zero). In every other case MSB is
	// set and hence function returns 1.
	return int((i | (^(i - 1))) >> 63)
}

func mulGeneric(r, x, y *fp) {
	var s fp // keeps intermediate results
	var t1, t2 [9]uint64
	var c, q uint64

	for i := 0; i < numWords-1; i++ {
		q = ((x[i] * y[0]) + s[0]) * pNegInv[0]
		mul576(&t1, &p, q)
		mul576(&t2, y, x[i])

		// x[i]*y + q_i*p
		t1[0], c = bits.Add64(t1[0], t2[0], 0)
		t1[1], c = bits.Add64(t1[1], t2[1], c)
		t1[2], c = bits.Add64(t1[2], t2[2], c)
		t1[3], c = bits.Add64(t1[3], t2[3], c)
		t1[4], c = bits.Add64(t1[4], t2[4], c)
		t1[5], c = bits.Add64(t1[5], t2[5], c)
		t1[6], c = bits.Add64(t1[6], t2[6], c)
		t1[7], c = bits.Add64(t1[7], t2[7], c)
		t1[8], _ = bits.Add64(t1[8], t2[8], c)

		// s = (s + x[i]*y + q_i * p) / R
		_, c = bits.Add64(t1[0], s[0], 0)
		s[0], c = bits.Add64(t1[1], s[1], c)
		s[1], c = bits.Add64(t1[2], s[2], c)
		s[2], c = bits.Add64(t1[3], s[3], c)
		s[3], c = bits.Add64(t1[4], s[4], c)
		s[4], c = bits.Add64(t1[5], s[5], c)
		s[5], c = bits.Add64(t1[6], s[6], c)
		s[6], c = bits.Add64(t1[7], s[7], c)
		s[7], _ = bits.Add64(t1[8], 0, c)
	}

	// last iteration stores result in r
	q = ((x[numWords-1] * y[0]) + s[0]) * pNegInv[0]
	mul576(&t1, &p, q)
	mul576(&t2, y, x[numWords-1])

	t1[0], c = bits.Add64(t1[0], t2[0], c)
	t1[1], c = bits.Add64(t1[1], t2[1], c)
	t1[2], c = bits.Add64(t1[2], t2[2], c)
	t1[3], c = bits.Add64(t1[3], t2[3], c)
	t1[4], c = bits.Add64(t1[4], t2[4], c)
	t1[5], c = bits.Add64(t1[5], t2[5], c)
	t1[6], c = bits.Add64(t1[6], t2[6], c)
	t1[7], c = bits.Add64(t1[7], t2[7], c)
	t1[8], _ = bits.Add64(t1[8], t2[8], c)

	_, c = bits.Add64(t1[0], s[0], 0)
	r[0], c = bits.Add64(t1[1], s[1], c)
	r[1], c = bits.Add64(t1[2], s[2], c)
	r[2], c = bits.Add64(t1[3], s[3], c)
	r[3], c = bits.Add64(t1[4], s[4], c)
	r[4], c = bits.Add64(t1[5], s[5], c)
	r[5], c = bits.Add64(t1[6], s[6], c)
	r[6], c = bits.Add64(t1[7], s[7], c)
	r[7], _ = bits.Add64(t1[8], 0, c)
}

// Returns result of x<y operation.
func isLess(x, y *fp) bool {
	for i := numWords - 1; i >= 0; i-- {
		v, c := bits.Sub64(y[i], x[i], 0)
		if c != 0 {
			return false
		}
		if v != 0 {
			return true
		}
	}
	// x == y
	return false
}

// r = x + y mod p.
func addRdc(r, x, y *fp) {
	var c uint64
	var t fp
	r[0], c = bits.Add64(x[0], y[0], 0)
	r[1], c = bits.Add64(x[1], y[1], c)
	r[2], c = bits.Add64(x[2], y[2], c)
	r[3], c = bits.Add64(x[3], y[3], c)
	r[4], c = bits.Add64(x[4], y[4], c)
	r[5], c = bits.Add64(x[5], y[5], c)
	r[6], c = bits.Add64(x[6], y[6], c)
	r[7], _ = bits.Add64(x[7], y[7], c)

	t[0], c = bits.Sub64(r[0], p[0], 0)
	t[1], c = bits.Sub64(r[1], p[1], c)
	t[2], c = bits.Sub64(r[2], p[2], c)
	t[3], c = bits.Sub64(r[3], p[3], c)
	t[4], c = bits.Sub64(r[4], p[4], c)
	t[5], c = bits.Sub64(r[5], p[5], c)
	t[6], c = bits.Sub64(r[6], p[6], c)
	t[7], c = bits.Sub64(r[7], p[7], c)

	var w = 0 - c
	r[0] = ctPick64(w, r[0], t[0])
	r[1] = ctPick64(w, r[1], t[1])
	r[2] = ctPick64(w, r[2], t[2])
	r[3] = ctPick64(w, r[3], t[3])
	r[4] = ctPick64(w, r[4], t[4])
	r[5] = ctPick64(w, r[5], t[5])
	r[6] = ctPick64(w, r[6], t[6])
	r[7] = ctPick64(w, r[7], t[7])
}

// r = x - y.
func sub512(r, x, y *fp) uint64 {
	var c uint64
	r[0], c = bits.Sub64(x[0], y[0], 0)
	r[1], c = bits.Sub64(x[1], y[1], c)
	r[2], c = bits.Sub64(x[2], y[2], c)
	r[3], c = bits.Sub64(x[3], y[3], c)
	r[4], c = bits.Sub64(x[4], y[4], c)
	r[5], c = bits.Sub64(x[5], y[5], c)
	r[6], c = bits.Sub64(x[6], y[6], c)
	r[7], c = bits.Sub64(x[7], y[7], c)
	return c
}

// r = x - y mod p.
func subRdc(r, x, y *fp) {
	var c uint64

	// Same as sub512(r,x,y). Unfortunately
	// compiler is not able to inline it.
	r[0], c = bits.Sub64(x[0], y[0], 0)
	r[1], c = bits.Sub64(x[1], y[1], c)
	r[2], c = bits.Sub64(x[2], y[2], c)
	r[3], c = bits.Sub64(x[3], y[3], c)
	r[4], c = bits.Sub64(x[4], y[4], c)
	r[5], c = bits.Sub64(x[5], y[5], c)
	r[6], c = bits.Sub64(x[6], y[6], c)
	r[7], c = bits.Sub64(x[7], y[7], c)

	// if x<y => r=x-y+p
	var w = 0 - c
	r[0], c = bits.Add64(r[0], ctPick64(w, p[0], 0), 0)
	r[1], c = bits.Add64(r[1], ctPick64(w, p[1], 0), c)
	r[2], c = bits.Add64(r[2], ctPick64(w, p[2], 0), c)
	r[3], c = bits.Add64(r[3], ctPick64(w, p[3], 0), c)
	r[4], c = bits.Add64(r[4], ctPick64(w, p[4], 0), c)
	r[5], c = bits.Add64(r[5], ctPick64(w, p[5], 0), c)
	r[6], c = bits.Add64(r[6], ctPick64(w, p[6], 0), c)
	r[7], _ = bits.Add64(r[7], ctPick64(w, p[7], 0), c)
}

// Fixed-window mod exp for fpBitLen bit value with 4 bit window. Returned
// result is a number in montgomery domain.
// r = b ^ e (mod p).
// Constant time.
func modExpRdcCommon(r, b, e *fp, fpBitLen int) {
	var precomp [16]fp
	var t fp
	var c uint64

	// Precompute step, computes an array of small powers of 'b'. As this
	// algorithm implements 4-bit window, we need 2^4=16 of such values.
	// b^0 = 1, which is equal to R from REDC.
	precomp[0] = one // b ^ 0
	precomp[1] = *b  // b ^ 1
	for i := 2; i < 16; i = i + 2 {
		// OPTIMIZE: implement fast squering. Then interleaving fast squaring
		// with multiplication should improve performance.
		mulRdc(&precomp[i], &precomp[i/2], &precomp[i/2]) // sqr
		mulRdc(&precomp[i+1], &precomp[i], b)
	}

	*r = one
	for i := fpBitLen/4 - 1; i >= 0; i-- {
		for j := 0; j < 4; j++ {
			mulRdc(r, r, r)
		}
		// note: non resistant to cache SCA
		idx := (e[i/16] >> uint((i%16)*4)) & 15
		mulRdc(r, r, &precomp[idx])
	}

	// if p <= r < 2p then r = r-p
	t[0], c = bits.Sub64(r[0], p[0], 0)
	t[1], c = bits.Sub64(r[1], p[1], c)
	t[2], c = bits.Sub64(r[2], p[2], c)
	t[3], c = bits.Sub64(r[3], p[3], c)
	t[4], c = bits.Sub64(r[4], p[4], c)
	t[5], c = bits.Sub64(r[5], p[5], c)
	t[6], c = bits.Sub64(r[6], p[6], c)
	t[7], c = bits.Sub64(r[7], p[7], c)

	var w = 0 - c
	r[0] = ctPick64(w, r[0], t[0])
	r[1] = ctPick64(w, r[1], t[1])
	r[2] = ctPick64(w, r[2], t[2])
	r[3] = ctPick64(w, r[3], t[3])
	r[4] = ctPick64(w, r[4], t[4])
	r[5] = ctPick64(w, r[5], t[5])
	r[6] = ctPick64(w, r[6], t[6])
	r[7] = ctPick64(w, r[7], t[7])
}

// modExpRdc does modular exponentation of 512-bit number.
// Constant-time.
func modExpRdc512(r, b, e *fp) {
	modExpRdcCommon(r, b, e, 512)
}

// modExpRdc does modular exponentation of 64-bit number.
// Constant-time.
func modExpRdc64(r, b *fp, e uint64) {
	modExpRdcCommon(r, b, &fp{e}, 64)
}

// isNonQuadRes checks whether value v is quadratic residue.
// Implementation uses Fermat's little theorem (or
// Euler's criterion)
//      a^(p-1) == 1, hence
//      (a^2) ((p-1)/2) == 1
// Which means v is a quadratic residue iff v^((p-1)/2) == 1.
// Caller provided v must be in montgomery domain.
// Returns 0 in case v is quadratic residue or 1 in case
// v is quadratic non-residue.
func (v *fp) isNonQuadRes() int {
	var res fp
	var b uint64

	modExpRdc512(&res, v, &pMin1By2)
	for i := range res {
		b |= res[i] ^ one[i]
	}

	return ctIsNonZero64(b)
}

// isZero returns false in case v is equal to 0, otherwise
// true. Constant time.
func (v *fp) isZero() bool {
	var r uint64
	for i := 0; i < numWords; i++ {
		r |= v[i]
	}
	return ctIsNonZero64(r) == 0
}

// equal checks if v is equal to in. Constant time.
func (v *fp) equal(in *fp) bool {
	var r uint64
	for i := range v {
		r |= v[i] ^ in[i]
	}
	return ctIsNonZero64(r) == 0
}
