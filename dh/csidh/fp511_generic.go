package csidh

import "math/bits"

// OZAPTF: this should be compiled only when generic

func locMul512(r, m1 []uint64, m2 uint64) uint64 {
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
	return c
}

func mul576Gen(r *[9]uint64, m1 *fp, m2 uint64) {
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

func cswap512Gen(x, y *fp, choice uint8) {
	var tmp uint64
	mask64 := 0 - uint64(choice)

	for i := 0; i < numWords; i++ {
		tmp = mask64 & (x[i] ^ y[i])
		x[i] = tmp ^ x[i]
		y[i] = tmp ^ y[i]
	}
}
