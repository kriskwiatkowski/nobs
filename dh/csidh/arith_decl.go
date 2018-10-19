package csidh

// u512 specific functions

//go:noescape
func mul512(a, b *Fp, c uint64)

//go:noescape
func add512(x, y, z *Fp) uint64

//go:noescape
func sub512(x, y, z *Fp) uint64

//go:noescape
func cswap512(x, y *Fp, choice uint8)

//go:noescape
func crdc512(x *Fp)

//go:noescape
func csubrdc512(x *Fp, choice uint64)

//go:noescape
func mul(res, x, y *Fp)

//go:noescape
func checkBigger(x, y *Fp) bool
