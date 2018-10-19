package csidh

// TODO: This all could simply go to read-only segment
// 	 then any write will crash the program which
//       is actually right thing to do

// P511

const (
	pbits       = 511
	kPrimeCount = 74
	// (2*5+1)^74 is roughly 2^256
	expMax = int8(5)
	// size of the limbs, pretty much hardcoded to 64-bit words
	limbBitSize = 64
	// size of the limbs in bytes
	limbByteSize = limbBitSize >> 3
	// Number of limbs for a field element
	numWords = 8

	// PrivateKeySize is a size of cSIDH/512 private key in bytes.
	PrivateKeySize = 37
	// PublicKeySize is a size of cSIDH/512 public key in bytes.
	PublicKeySize = 64
	// SharedSecretSize is a size of cSIDH/512 shared secret in bytes.
	SharedSecretSize = 64
)

var (
	// Elkies primes up to 374 + prime 587
	// p = 4 * product(primes) - 1
	primes = []uint64{
		3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59,
		61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137,
		139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227,
		229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
		317, 331, 337, 347, 349, 353, 359, 367, 373, 587}

	p = Fp{
		0x1B81B90533C6C87B, 0xC2721BF457ACA835,
		0x516730CC1F0B4F25, 0xA7AAC6C567F35507,
		0x5AFBFCC69322C9CD, 0xB42D083AEDC88C42,
		0xFC8AB0D15E3E4C4A, 0x65B48E8F740F89BF,
	}

	/* Montgomery R = 2^512 mod p */
	// TODO: Change name (remove _)
	fp_1 = Fp{
		0xC8FC8DF598726F0A, 0x7B1BC81750A6AF95,
		0x5D319E67C1E961B4, 0xB0AA7275301955F1,
		0x4A080672D9BA6C64, 0x97A5EF8A246EE77B,
		0x06EA9E5D4383676A, 0x3496E2E117E0EC80,
	}

	/* Montgomery R^2 mod p */
	r_squared_mod_p = Fp{
		0x36905B572FFC1724, 0x67086F4525F1F27D,
		0x4FAF3FBFD22370CA, 0x192EA214BCC584B1,
		0x5DAE03EE2F5DE3D0, 0x1E9248731776B371,
		0xAD5F166E20E4F52D, 0x4ED759AEA6F3917E,
	}

	// -p^-1 mod 2^64
	pNegInv = Fp{
		0x66c1301f632e294d,
	}

	// (p-1)/2. Used as exponent, hence not in
	// montgomery domain
	pMin1By2 = Fp{
		0x8DC0DC8299E3643D, 0xE1390DFA2BD6541A,
		0xA8B398660F85A792, 0xD3D56362B3F9AA83,
		0x2D7DFE63499164E6, 0x5A16841D76E44621,
		0xFE455868AF1F2625, 0x32DA4747BA07C4DF,
	}

	// p-1 mod 2^64. Used as exponent, hence not
	// in montgomery domain
	pMin2 = Fp{
		0x1B81B90533C6C879, 0xC2721BF457ACA835,
		0x516730CC1F0B4F25, 0xA7AAC6C567F35507,
		0x5AFBFCC69322C9CD, 0xB42D083AEDC88C42,
		0xFC8AB0D15E3E4C4A, 0x65B48E8F740F89BF,
	}

	// 2 in Montgomery domain
	two = Fp{
		0x767762E5FD1E1599, 0x33C5743A49A0B6F6,
		0x68FC0C0364C77443, 0xB9AA1E24F83F56DB,
		0x3914101F20520EFB, 0x7B1ED6D95B1542B4,
		0x114A8BE928C8828A, 0x03793732BBB24F40,
	}

	// -2 in Montgomery domain
	minTwo = Fp{
		0xA50A561F36A8B2E2, 0x8EACA7BA0E0BF13E,
		0xE86B24C8BA43DAE2, 0xEE00A8A06FB3FE2B,
		0x21E7ECA772D0BAD1, 0x390E316192B3498E,
		0xEB4024E83575C9C0, 0x623B575CB85D3A7F,
	}

	// 4 in Montgomery domain
	four = Fp{
		0xECEEC5CBFA3C2B32, 0x678AE87493416DEC,
		0xD1F81806C98EE886, 0x73543C49F07EADB6,
		0x7228203E40A41DF7, 0xF63DADB2B62A8568,
		0x229517D251910514, 0x06F26E6577649E80,
	}

	// TODO: Why exactly they are not in montgomery domain?

	twoMinP = Fp{}

	// NOT SURE ABOUT THOSE

	// 4 * sqrt(p)
	fourSqrtP = Fp{
		0x17895E71E1A20B3F, 0x38D0CD95F8636A56,
		0x142B9541E59682CD, 0x856F1399D91D6592,
		0x0000000000000002,
	}
)
