package csidh

// p-1
var pMin1 = Fp{
	0x1B81B90533C6C87A, 0xC2721BF457ACA835,
	0x516730CC1F0B4F25, 0xA7AAC6C567F35507,
	0x5AFBFCC69322C9CD, 0xB42D083AEDC88C42,
	0xFC8AB0D15E3E4C4A, 0x65B48E8F740F89BF,
}

// z = x + y mod P
func addRdc(z, x, y *Fp) {
	add512(z, x, y)
	// TODO: check if doing it in add512 is much faster?
	crdc512(z)
}

func subRdc(z, x, y *Fp) {
	borrow := sub512(z, x, y)
	csubrdc512(z, borrow)
}

func mulRdc(z, x, y *Fp) {
	mul(z, x, y)
	crdc512(z)
}

func sqrRdc(z, x *Fp) {
	// TODO: to be implemented faster
	mul(z, x, x)
	crdc512(z)
}

// Fixed-window mod exp for 512 bit value with 4 bit window. Returned
// result is a number in montgomery domain.
// res = b ^ e (mod p).
// Constant time.
func modExpRdc(res, b, e *Fp) {
	var precomp [16]Fp

	// Precompute step, computes an array of small powers of 'b'. As this
	// algorithm implements 4-bit window, we need 2^4=16 of such values.
	// b^0 = 1, which is equal to R from REDC.
	precomp[0] = fp_1 // b ^ 0
	precomp[1] = *b   // b ^ 1
	for i := 2; i < 16; i = i + 2 {
		// Interleave fast squaring with multiplication. It's currently not a case
		// but squaring can be implemented faster than multiplication.
		sqrRdc(&precomp[i], &precomp[i/2])
		mulRdc(&precomp[i+1], &precomp[i], b)
	}

	*res = fp_1
	for i := int(127); i >= 0; i-- {
		for j := 0; j < 4; j++ {
			mulRdc(res, res, res)
		}
		// TODO: non resistant to cache SCA
		idx := (e[i/16] >> uint((i%16)*4)) & 15
		mulRdc(res, res, &precomp[idx])
	}
	// Reduction step
	crdc512(res)
}

// Checks whether value v is quadratic residue. Implementation uses
// Fermat's little theorem (or Euler's criterion)
//      a^(p-1) == 1, hence
//      (a^2) ((p-1)/2) == 1
// Which means v is a quadratic residue iff v^((p-1)/2) == 1.
// Caller provided v must be in montgomery domain.
// Function returns 0 in case v is quadratic residue and 1 in case
// v is quadratic non-residue.
func isNonQuadRes(v *Fp) int {
	var res Fp
	var b uint64

	modExpRdc(&res, v, &pMin1By2)
	for i, _ := range res {
		b |= res[i] ^ fp_1[i]
	}

	// In case b==0 then b-1 will set MSB. Only in such case (b OR ~(b-1))
	// will result in MSB being not set (logical implication: (b-1)=>b is
	// false iff (b-1)==0 and b==non-zero, otherwise true).
	return int((b | (^(b - 1))) >> 63)
}
