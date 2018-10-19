package csidh

import (
	"fmt"
	"math/big"
	mrand "math/rand"
)

// Commonly used variables
var (
	// Number of interations
	kNumIter = 10000
	// Modulus
	kModulus, _ = new(big.Int).SetString(fp2S(p), 16)
	// Zero in Fp512
	ZeroFp512 = Fp{}
	// One in Fp512
	OneFp512 = Fp{1, 0, 0, 0, 0, 0, 0, 0}
)

// Converts dst to Montgomery if "toMont==true" or from Montgomery domain otherwise.
func toMont(dst *big.Int, toMont bool) {
	var bigP, bigR big.Int

	intSetU64(&bigP, p[:])
	bigR.SetUint64(1)
	bigR.Lsh(&bigR, 512)

	if !toMont {
		bigR.ModInverse(&bigR, &bigP)
	}
	dst.Mul(dst, &bigR)
	dst.Mod(dst, &bigP)
}

func fp2S(v Fp) string {
	var str string
	for i := 0; i < 8; i++ {
		str = fmt.Sprintf("%016x", v[i]) + str
	}
	return str
}

// zeroize Fp
func zero(v *Fp) {
	for i, _ := range *v {
		v[i] = 0
	}
}

// returns random value in a range (0,p)
func randomFp() Fp {
	var u Fp
	for i := 0; i < 8; i++ {
		u[i] = mrand.Uint64()
	}
	return u
}

// x<y: <0
// x>y: >0
// x==y: 0
func cmp512(x, y *Fp) int {
	if len(*x) == len(*y) {
		for i := len(*x) - 1; i >= 0; i-- {
			if x[i] < y[i] {
				return -1
			} else if x[i] > y[i] {
				return 1
			}
		}
		return 0
	}
	return len(*x) - len(*y)
}

// return x==y for Fp
func ceqFp(l, r *Fp) bool {
	for idx, _ := range l {
		if l[idx] != r[idx] {
			return false
		}
	}
	return true
}

// return x==y for Point
func ceqPoint(l, r *Point) bool {
	return ceqFp(&l.x, &r.x) && ceqFp(&l.z, &r.z)
}

// return x==y
func ceq512(x, y *Fp) bool {
	return cmp512(x, y) == 0
}

// Converst src to big.Int. Function assumes that src is a slice of uint64
// values encoded in little-endian byte order.
func intSetU64(dst *big.Int, src []uint64) *big.Int {
	var tmp big.Int

	dst.SetUint64(0)
	for i, _ := range src {
		tmp.SetUint64(src[i])
		tmp.Lsh(&tmp, uint(i*64))
		dst.Add(dst, &tmp)
	}
	return dst
}

// Convers src to an array of uint64 values encoded in little-endian
// byte order.
func intGetU64(src *big.Int) []uint64 {
	var tmp, mod big.Int
	dst := make([]uint64, (src.BitLen()/64)+1)

	u64 := uint64(0)
	u64--
	mod.SetUint64(u64)
	for i := 0; i < (src.BitLen()/64)+1; i++ {
		tmp.Set(src)
		tmp.Rsh(&tmp, uint(i)*64)
		tmp.And(&tmp, &mod)
		dst[i] = tmp.Uint64()
	}
	return dst
}

// Returns projective coordinate X of normalized EC 'point' (point.x / point.z).
func toNormX(point *Point) big.Int {
	var bigP, bigDnt, bigDor big.Int

	intSetU64(&bigP, p[:])
	intSetU64(&bigDnt, point.x[:])
	intSetU64(&bigDor, point.z[:])

	bigDor.ModInverse(&bigDor, &bigP)
	bigDnt.Mul(&bigDnt, &bigDor)
	bigDnt.Mod(&bigDnt, &bigP)
	return bigDnt
}

// Converts string to Fp element in Montgomery domain of cSIDH-512
func toFp(num string) Fp {
	var tmp big.Int
	var ok bool
	var ret Fp

	_, ok = tmp.SetString(num, 0)
	if !ok {
		panic("Can't parse a number")
	}
	toMont(&tmp, true)
	copy(ret[:], intGetU64(&tmp))
	return ret
}
