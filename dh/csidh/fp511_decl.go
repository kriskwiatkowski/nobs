package csidh

//go:noescape
func mul512(a, b *fp, c uint64)

//go:noescape
func mul576(a *[9]uint64, b *fp, c uint64)

//go:noescape
func cswap512(x, y *fp, choice uint8)

//go:noescape
func mulBmiAsm(res, x, y *fp)
