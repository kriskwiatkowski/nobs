package utils

type x86 struct {
	// Signals support for MULX which is in BMI2
	HasBMI2 bool

	// Signals support for ADX
	HasADX bool

	// Signals support for AES
	HasAES bool

	// Signals support for RDSEED
	HasRDSEED bool
}

var X86 x86
