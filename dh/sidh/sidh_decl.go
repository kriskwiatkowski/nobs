// +build amd64,!noasm

package sidh

// Returns zero if the input scalar is <= 3^238. scalar must be 48-byte array
// of bytes. This function is specific to P751.
//go:noescape
func checkLessThanThree238(scalar []byte) uint64

// Multiply 48-byte scalar by 3 to get a scalar in 3*[0,3^238). This
// function is specific to P751.
//go:noescape
func multiplyByThree(scalar []byte)
