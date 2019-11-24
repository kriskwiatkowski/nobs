// +build noasm arm64

package csidh

import "math/bits"

func mul512(r, m1 *fp, m2 uint64) {
	var c, h, l uint64

	c, r[0] = bits.Mul64(m2, m1[0])

	h, l = bits.Mul64(m2, m1[1])
	r[1], c = bits.Add64(l, c, 0)
	c = h + c

	h, l = bits.Mul64(m2, m1[2])
	r[2], c = bits.Add64(l, c, 0)
	c = h + c

	h, l = bits.Mul64(m2, m1[3])
	r[3], c = bits.Add64(l, c, 0)
	c = h + c

	h, l = bits.Mul64(m2, m1[4])
	r[4], c = bits.Add64(l, c, 0)
	c = h + c

	h, l = bits.Mul64(m2, m1[5])
	r[5], c = bits.Add64(l, c, 0)
	c = h + c

	h, l = bits.Mul64(m2, m1[6])
	r[6], c = bits.Add64(l, c, 0)
	c = h + c

	h, l = bits.Mul64(m2, m1[7])
	r[7], _ = bits.Add64(l, c, 0)
}

func mul576(r *[9]uint64, m1 *fp, m2 uint64) {
	var c, h, l uint64

	c, r[0] = bits.Mul64(m2, m1[0])

	h, l = bits.Mul64(m2, m1[1])
	r[1], c = bits.Add64(l, c, 0)
	c = h + c

	h, l = bits.Mul64(m2, m1[2])
	r[2], c = bits.Add64(l, c, 0)
	c = h + c

	h, l = bits.Mul64(m2, m1[3])
	r[3], c = bits.Add64(l, c, 0)
	c = h + c

	h, l = bits.Mul64(m2, m1[4])
	r[4], c = bits.Add64(l, c, 0)
	c = h + c

	h, l = bits.Mul64(m2, m1[5])
	r[5], c = bits.Add64(l, c, 0)
	c = h + c

	h, l = bits.Mul64(m2, m1[6])
	r[6], c = bits.Add64(l, c, 0)
	c = h + c

	h, l = bits.Mul64(m2, m1[7])
	r[7], c = bits.Add64(l, c, 0)
	r[8], c = bits.Add64(h, c, 0)
	r[8] += c
}

func cswap512(x, y *fp, choice uint8) {
	var tmp uint64
	mask64 := 0 - uint64(choice)

	for i := 0; i < numWords; i++ {
		tmp = mask64 & (x[i] ^ y[i])
		x[i] = tmp ^ x[i]
		y[i] = tmp ^ y[i]
	}
}

func mul(res, x, y *fp) {
	mulGeneric(res, x, y)
}

// mulRdc performs montgomery multiplication r = x * y mod P.
// Returned result r is already reduced and in Montgomery domain.
func mulRdc(r, x, y *fp) {
	var t fp
	var c uint64

	mulGeneric(r, x, y)

	// if p <= r < 2p then r = r-p
	t[0], c = bits.Sub64(r[0], p[0], 0)
	t[1], c = bits.Sub64(r[1], p[1], c)
	t[2], c = bits.Sub64(r[2], p[2], c)
	t[3], c = bits.Sub64(r[3], p[3], c)
	t[4], c = bits.Sub64(r[4], p[4], c)
	t[5], c = bits.Sub64(r[5], p[5], c)
	t[6], c = bits.Sub64(r[6], p[6], c)
	t[7], c = bits.Sub64(r[7], p[7], c)

	var w = uint64(0 - uint64(c))
	r[0] = ctPick64(w, r[0], t[0])
	r[1] = ctPick64(w, r[1], t[1])
	r[2] = ctPick64(w, r[2], t[2])
	r[3] = ctPick64(w, r[3], t[3])
	r[4] = ctPick64(w, r[4], t[4])
	r[5] = ctPick64(w, r[5], t[5])
	r[6] = ctPick64(w, r[6], t[6])
	r[7] = ctPick64(w, r[7], t[7])
}
