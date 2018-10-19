package csidh

import (
	"math/big"
	mrand "math/rand"
	"testing"
)

// Check if mul512 produces result
// z = x*y mod 2^512
func TestFp512Mul3_Nominal(t *testing.T) {
	var multiplier64 uint64
	var mod big.Int

	// modulus: 2^512
	mod.SetUint64(1).Lsh(&mod, 512)

	for i := 0; i < kNumIter; i++ {
		multiplier64 = mrand.Uint64()

		fV := randomFp()
		exp, _ := new(big.Int).SetString(fp2S(fV), 16)
		exp.Mul(exp, new(big.Int).SetUint64(multiplier64))
		// Truncate to 512 bits
		exp.Mod(exp, &mod)

		mul512(&fV, &fV, multiplier64)
		res, _ := new(big.Int).SetString(fp2S(fV), 16)

		if exp.Cmp(res) != 0 {
			t.Errorf("%X != %X", exp, res)
		}
	}
}

func TestFp512Add3_Nominal(t *testing.T) {
	var mod big.Int
	// modulus: 2^512
	mod.SetUint64(1).Lsh(&mod, 512)

	for i := 0; i < kNumIter; i++ {
		a := randomFp()
		bigA, _ := new(big.Int).SetString(fp2S(a), 16)
		b := randomFp()
		bigB, _ := new(big.Int).SetString(fp2S(b), 16)

		add512(&a, &a, &b)
		bigRet, _ := new(big.Int).SetString(fp2S(a), 16)
		bigA.Add(bigA, bigB)
		// Truncate to 512 bits
		bigA.Mod(bigA, &mod)

		if bigRet.Cmp(bigA) != 0 {
			t.Errorf("%X != %X", bigRet, bigA)
		}
	}
}

func TestFp512Add3_ReturnsCarry(t *testing.T) {
	a := Fp{}
	b := Fp{
		0, 0,
		0, 0,
		0, 0,
		0, 1}
	c := Fp{
		0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}
	if add512(&a, &b, &c) != 1 {
		t.Error("Carry not returned")
	}
}

func TestFp512Add3_DoesntReturnCarry(t *testing.T) {
	a := Fp{
		0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}
	b := Fp{
		0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF, 0}
	c := Fp{
		0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFA, 0}

	if add512(&a, &b, &c) != 0 {
		t.Error("Carry returned")
	}
}

func TestFp512Sub3_Nominal(t *testing.T) {
	var ret Fp
	var mod big.Int
	// modulus: 2^512
	mod.SetUint64(1).Lsh(&mod, 512)

	for i := 0; i < kNumIter; i++ {
		a := randomFp()
		bigA, _ := new(big.Int).SetString(fp2S(a), 16)
		b := randomFp()
		bigB, _ := new(big.Int).SetString(fp2S(b), 16)

		sub512(&ret, &a, &b)
		bigRet, _ := new(big.Int).SetString(fp2S(ret), 16)
		bigA.Sub(bigA, bigB)
		// Truncate to 512 bits
		bigA.Mod(bigA, &mod)

		if bigRet.Cmp(bigA) != 0 {
			t.Errorf("%X != %X", bigRet, bigA)
		}
	}
}

func TestFp512Sub3_DoesntReturnCarry(t *testing.T) {
	a := Fp{}
	b := Fp{
		0xFFFFFFFFFFFFFFFF, 1,
		0, 0,
		0, 0,
		0, 0}
	c := Fp{
		0xFFFFFFFFFFFFFFFF, 2,
		0, 0,
		0, 0,
		0, 0}

	if sub512(&a, &b, &c) != 1 {
		t.Error("Carry not returned")
	}
}

func TestFp512Sub3_ReturnsCarry(t *testing.T) {
	a := Fp{}
	b := Fp{
		0xFFFFFFFFFFFFFFFF, 2,
		0, 0,
		0, 0,
		0, 0}
	c := Fp{
		0xFFFFFFFFFFFFFFFF, 1,
		0, 0,
		0, 0,
		0, 0}

	if sub512(&a, &b, &c) != 0 {
		t.Error("Carry not returned")
	}
}

func TestCswap(t *testing.T) {
	arg1 := randomFp()
	arg2 := randomFp()

	arg1cpy := arg1
	cswap512(&arg1, &arg2, 0)
	if !ceq512(&arg1, &arg1cpy) {
		t.Error("cswap swapped")
	}

	arg1cpy = arg1
	cswap512(&arg1, &arg2, 1)
	if ceq512(&arg1, &arg1cpy) {
		t.Error("cswap didn't swapped")
	}

	arg1cpy = arg1
	cswap512(&arg1, &arg2, 0xF2)
	if ceq512(&arg1, &arg1cpy) {
		t.Error("cswap didn't swapped")
	}
}

func TestAddRdc(t *testing.T) {
	var res Fp

	tmp := OneFp512
	addRdc(&res, &tmp, &p)
	if !ceq512(&res, &tmp) {
		t.Errorf("Wrong value\n%X", res)
	}

	tmp = ZeroFp512
	addRdc(&res, &p, &p)
	if !ceq512(&res, &p) {
		t.Errorf("Wrong value\n%X", res)
	}

	tmp = Fp{1, 1, 1, 1, 1, 1, 1, 1}
	addRdc(&res, &p, &tmp)
	if !ceq512(&res, &tmp) {
		t.Errorf("Wrong value\n%X", res)
	}

	tmp = Fp{1, 1, 1, 1, 1, 1, 1, 1}
	exp := Fp{2, 2, 2, 2, 2, 2, 2, 2}
	addRdc(&res, &tmp, &tmp)
	if !ceq512(&res, &exp) {
		t.Errorf("Wrong value\n%X", res)
	}
}

func TestSubRdc(t *testing.T) {
	var res Fp

	// 1 - 1 mod P
	tmp := OneFp512
	subRdc(&res, &tmp, &tmp)
	if !ceq512(&res, &ZeroFp512) {
		t.Errorf("Wrong value\n%X", res)
	}
	zero(&res)

	// 0 - 1 mod P
	exp := p
	exp[0]--

	subRdc(&res, &ZeroFp512, &OneFp512)
	if !ceq512(&res, &exp) {
		t.Errorf("Wrong value\n%X\n%X", res, exp)
	}
	zero(&res)

	// P - (P-1)
	pMinusOne := p
	pMinusOne[0]--
	subRdc(&res, &p, &pMinusOne)
	if !ceq512(&res, &OneFp512) {
		t.Errorf("Wrong value\n[%X != %X]", res, OneFp512)
	}
	zero(&res)

	subRdc(&res, &p, &OneFp512)
	if !ceq512(&res, &pMinusOne) {
		t.Errorf("Wrong value\n[%X != %X]", res, pMinusOne)
	}
}

func TestMulRdc(t *testing.T) {
	var res Fp
	var m1 = Fp{
		0x85E2579C786882D0, 0x4E3433657E18DA95,
		0x850AE5507965A0B3, 0xA15BC4E676475964}
	var m2 = Fp{
		0x85E2579C786882CF, 0x4E3433657E18DA95,
		0x850AE5507965A0B3, 0xA15BC4E676475964}

	// Expected
	var m1m1 = Fp{
		0xAEBF46E92C88A4B4, 0xCFE857977B946347,
		0xD3B264FF08493901, 0x6EEB3D23746B6C7C,
		0xC0CA874A349D64B4, 0x7AD4A38B406F8504,
		0x38B6B6CEB82472FB, 0x1587015FD7DDFC7D}
	var m1m2 = Fp{
		0x51534771258C4624, 0x2BFEDE86504E2160,
		0xE8127D5E9329670B, 0x0C84DBD584491D75,
		0x656C73C68B16E38C, 0x01C0DA470B30B8DE,
		0x2532E3903EAA950B, 0x3F2C28EA97FE6FEC}

	// 0*0
	tmp := ZeroFp512
	mulRdc(&res, &tmp, &tmp)
	if !ceq512(&res, &tmp) {
		t.Errorf("Wrong value\n%X", res)
	}

	// 1*m1 == m1
	zero(&res)
	mulRdc(&res, &m1, &fp_1)
	if !ceq512(&res, &m1) {
		t.Errorf("Wrong value\n%X", res)
	}

	// OZAPTF: I don't understand those results. but they are correct
	// m1*m2 < p
	zero(&res)
	mulRdc(&res, &m1, &m2)
	if !ceq512(&res, &m1m2) {
		t.Errorf("Wrong value\n%X", res)
	}

	// m1*m1 > p
	zero(&res)
	mulRdc(&res, &m1, &m1)
	if !ceq512(&res, &m1m1) {
		t.Errorf("Wrong value\n%X", res)
	}
}

func TestModExp(t *testing.T) {
	var resExp, base, exp big.Int
	var baseFp, expFp, resFp, resFpExp Fp

	for i := 0; i < kNumIter; i++ {
		// Perform modexp with reference implementation
		// in Montgomery domain
		base.SetString(fp2S(randomFp()), 16)
		exp.SetString(fp2S(randomFp()), 16)
		resExp.Exp(&base, &exp, kModulus)
		toMont(&base, true)
		toMont(&resExp, true)

		// Convert to Fp
		copy(baseFp[:], intGetU64(&base))
		copy(expFp[:], intGetU64(&exp))
		copy(resFpExp[:], intGetU64(&resExp))

		// Perform modexp with our implementation
		modExpRdc(&resFp, &baseFp, &expFp)

		if !ceq512(&resFp, &resFpExp) {
			t.Errorf("Wrong value\n%X!=%X", resFp, intGetU64(&resExp))
		}
	}
}

// Test uses Euler's Criterion
func TestIsNonQuadRes(t *testing.T) {
	var n, nMont big.Int
	var pm1o2, rawP big.Int
	var nMontFp Fp

	// (p-1)/2
	pm1o2.SetString("0x32da4747ba07c4dffe455868af1f26255a16841d76e446212d7dfe63499164e6d3d56362b3f9aa83a8b398660f85a792e1390dfa2bd6541a8dc0dc8299e3643d", 0)
	// modulus value (not in montgomery)
	rawP.SetString("0x65b48e8f740f89bffc8ab0d15e3e4c4ab42d083aedc88c425afbfcc69322c9cda7aac6c567f35507516730cc1f0b4f25c2721bf457aca8351b81b90533c6c87b", 0)

	// There is 641 quadratic residues in this range
	for i := uint64(1); i < 1000; i++ {
		n.SetUint64(i)
		n.Exp(&n, &pm1o2, &rawP)
		// exp == 1 iff n is quadratic non-residue
		exp := n.Cmp(big.NewInt(1))
		if exp < 0 {
			panic("Should never happen")
		}

		nMont.SetUint64(i)
		toMont(&nMont, true)
		copy(nMontFp[:], intGetU64(&nMont))
		ret := isNonQuadRes(&nMontFp)

		if ret != exp {
			toMont(&nMont, false)
			t.Errorf("Test failed for value %s", nMont.Text(10))
		}
	}
}

func TestCheckSmaller(t *testing.T) {
	if checkBigger(&pMin1, &p) == true {
		t.Error("p>pMin1")
	}

	if !checkBigger(&p, &pMin1) {
		t.Error("pMin1<p")
	}

	if checkBigger(&p, &p) {
		t.Error("p==p")
	}
}

func BenchmarkFp512Add(b *testing.B) {
	var arg1 Fp
	arg2 := randomFp()
	arg3 := randomFp()
	for n := 0; n < b.N; n++ {
		add512(&arg1, &arg2, &arg3)
	}
}

func BenchmarkFp512Sub(b *testing.B) {
	var arg1 Fp
	arg2, arg3 := randomFp(), randomFp()
	for n := 0; n < b.N; n++ {
		sub512(&arg1, &arg2, &arg3)
	}
}

func BenchmarkFp512Mul(b *testing.B) {
	var arg1 = mrand.Uint64()
	arg2, arg3 := randomFp(), randomFp()
	for n := 0; n < b.N; n++ {
		mul512(&arg2, &arg3, arg1)
	}
}

func BenchmarkCSwap(b *testing.B) {
	arg1 := randomFp()
	arg2 := randomFp()
	for n := 0; n < b.N; n++ {
		cswap512(&arg1, &arg2, uint8(n%2))
	}
}

func BenchmarkAddRdc(b *testing.B) {
	var res Fp
	arg1 := randomFp()
	arg2 := randomFp()

	for n := 0; n < b.N; n++ {
		addRdc(&res, &arg1, &arg2)
	}
}

func BenchmarkSubRdc(b *testing.B) {
	arg1 := randomFp()
	arg2 := randomFp()
	var res Fp
	for n := 0; n < b.N; n++ {
		subRdc(&res, &arg1, &arg2)
	}
}

func BenchmarkModExpRdc(b *testing.B) {
	arg1 := randomFp()
	arg2 := randomFp()
	var res Fp
	for n := 0; n < b.N; n++ {
		modExpRdc(&res, &arg1, &arg2)
	}
}
