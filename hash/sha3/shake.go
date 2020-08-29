// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3

// SHAKE128 and SHAKE256 are FIPS approved XOFs. The cSHAKE128/256
// are SHAKE-based XOFs supporting domain separation.
import (
	"encoding/binary"
	"io"
)

// ShakeHash defines the interface to hash functions that
// support arbitrary-length output.
type ShakeHash interface {
	// Write absorbs more data into the hash's state. It panics if input is
	// written to it after output has been read from it.
	io.Writer

	// Read reads more output from the hash; reading affects the hash's
	// state. (ShakeHash.Read is thus very different from Hash.Sum)
	// It never returns an error.
	io.Reader

	// Clone returns a copy of the ShakeHash in its current state.
	Clone() ShakeHash

	// Reset resets the ShakeHash to its initial state.
	Reset()
}

// cSHAKE specific context
type cshakeState struct {
	state // SHA-3 state context and Read/Write operations

	// initBlock is the cSHAKE specific initialization set of bytes. It is initialized
	// by newCShake function and stores concatenation of N followed by S, encoded
	// by the method specified in 3.3 of [1] and padded with bytepad function.
	// Used by Reset() to restore initial state.
	initBlock []byte
}

// Consts for configuring initial SHA-3 state
const (
	sfxShake  = 0x1f
	sfxCShake = 0x04
	rate128   = 168
	rate256   = 136
)

func bytepad(input []byte, w int) []byte {
	// leftEncode always returns max 9 bytes
	buf := make([]byte, 0, 9+len(input)+w)
	buf = append(buf, leftEncode(uint64(w))...)
	buf = append(buf, input...)
	padlen := w - (len(buf) % w)
	return append(buf, make([]byte, padlen)...)
}

func leftEncode(value uint64) []byte {
	var b [9]byte
	binary.BigEndian.PutUint64(b[1:], value)
	// Trim all but last leading zero bytes
	i := byte(1)
	for i < 8 && b[i] == 0 {
		i++
	}
	// Prepend number of encoded bytes
	b[i-1] = 9 - i
	return b[i-1:]
}

func newCShake(N, S []byte, sfx byte, shaId uint8) ShakeHash {
	c := cshakeState{state: state{sfx: sfx, desc: Sha3Desc[shaId]}}

	// leftEncode returns max 9 bytes
	b := make([]byte, 0, 9*2+len(N)+len(S))
	b = append(b, leftEncode(uint64(len(N)*8))...)
	b = append(b, N...)
	b = append(b, leftEncode(uint64(len(S)*8))...)
	b = append(b, S...)
	c.initBlock = bytepad(b, c.BlockSize())
	c.Write(c.initBlock)
	return &c
}

// Reset resets the hash to initial state.
func (c *cshakeState) Reset() {
	c.state.Reset()
	c.Write(c.initBlock)
}

// Clone returns copy of a cSHAKE context within its current state.
func (c *cshakeState) Clone() ShakeHash {
	b := make([]byte, len(c.initBlock))
	copy(b, c.initBlock)
	return &cshakeState{state: c.state, initBlock: b}
}

// Clone returns copy of SHAKE context within its current state.
func (c *state) Clone() ShakeHash {
	dup := *c
	return &dup
}

// NewShake128 creates a new SHAKE128 variable-output-length ShakeHash.
// Its generic security strength is 128 bits against all attacks if at
// least 32 bytes of its output are used.
func NewShake128() ShakeHash {
	return &state{sfx: sfxShake, desc: Sha3Desc[SHAKE128]}
}

// NewShake256 creates a new SHAKE256 variable-output-length ShakeHash.
// Its generic security strength is 256 bits against all attacks if
// at least 64 bytes of its output are used.
func NewShake256() ShakeHash {
	return &state{sfx: sfxShake, desc: Sha3Desc[SHAKE256]}
}

// NewCShake128 creates a new instance of cSHAKE128 variable-output-length ShakeHash,
// a customizable variant of SHAKE128.
// N is used to define functions based on cSHAKE, it can be empty when plain cSHAKE is
// desired. S is a customization byte string used for domain separation - two cSHAKE
// computations on same input with different S yield unrelated outputs.
// When N and S are both empty, this is equivalent to NewShake128.
func NewCShake128(N, S []byte) ShakeHash {
	if len(N) == 0 && len(S) == 0 {
		return NewShake128()
	}
	return newCShake(N, S, sfxCShake, SHAKE128)
}

// NewCShake256 creates a new instance of cSHAKE256 variable-output-length ShakeHash,
// a customizable variant of SHAKE256.
// N is used to define functions based on cSHAKE, it can be empty when plain cSHAKE is
// desired. S is a customization byte string used for domain separation - two cSHAKE
// computations on same input with different S yield unrelated outputs.
// When N and S are both empty, this is equivalent to NewShake256.
func NewCShake256(N, S []byte) ShakeHash {
	if len(N) == 0 && len(S) == 0 {
		return NewShake256()
	}
	return newCShake(N, S, sfxCShake, SHAKE256)
}

// ShakeSum128 writes an arbitrary-length digest of data into hash.
func ShakeSum128(hash, data []byte) {
	h := NewShake128()
	h.Write(data)
	h.Read(hash)
}

// ShakeSum256 writes an arbitrary-length digest of data into hash.
func ShakeSum256(hash, data []byte) {
	h := NewShake256()
	h.Write(data)
	h.Read(hash)
}
