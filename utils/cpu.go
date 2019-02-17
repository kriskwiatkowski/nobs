package utils

type x86 struct {
	// Signals support for MULX which is in BMI2
	HasBMI2 bool

	// Signals support for ADX
	HasADX bool

	// AES hardware support
	HasAES bool

	// SSE3 extension for PUSHFD
	HasSSE3 bool
}

var X86 x86
