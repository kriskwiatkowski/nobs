package csidh

// 511-bit number representing prime field element GF(p)
type Fp [numWords]uint64

// Represents projective point on elliptic curve E over Fp
type Point struct {
	x Fp
	z Fp
}

// Curve coefficients
type Coeff struct {
	a Fp
	c Fp
}

// non-constant time
func (f *Fp) Equals(in *Fp) bool {
	for i, _ := range f {
		if f[i] != in[i] {
			return false
		}
	}
	return true
}
