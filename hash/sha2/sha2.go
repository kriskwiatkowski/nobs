// Package sha2 implements the SM-3 hash algorithm as defined in "SM3 Hash
// function draft-shen-sha2-hash-01" draft
//
package sha2

import (
	"hash"
)

const (
	init0 = 0x6A09E667
	init1 = 0xBB67AE85
	init2 = 0x3C6EF372
	init3 = 0xA54FF53A
	init4 = 0x510E527F
	init5 = 0x9B05688C
	init6 = 0x1F83D9AB
	init7 = 0x5BE0CD19
)

// The size of a SM-3 checksum in bytes.
const Size = 32

// The blocksize of SM-3 in bytes.
const BlockSize int = 64

// digest represents the partial evaluation of a checksum.
type digest struct {
	h   [8]uint32
	len uint64
	b   [BlockSize]byte
}

func New() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Size() int { return Size }

func (d *digest) Init() { d.Reset() }

func (d *digest) Reset() {
	d.h[0] = init0
	d.h[1] = init1
	d.h[2] = init2
	d.h[3] = init3
	d.h[4] = init4
	d.h[5] = init5
	d.h[6] = init6
	d.h[7] = init7
	d.len = 0
}

func (d *digest) Write(input []byte) (nn int, err error) {

	// current possition in the buffer
	idx := int(d.len & uint64((d.BlockSize() - 1)))
	d.len += uint64(len(input))

	if len(input)+idx < d.BlockSize() {
		copy(d.b[idx:], input)
		return
	}

	c := d.BlockSize() - idx
	copy(d.b[idx:], input[:c])
	d.compress(d.b[:], 1)

	input = input[c:]
	nblocks := int(len(input) / d.BlockSize())
	d.compress(input[:], nblocks)

	// this eventually could be done in d.compress
	copy(d.b[:], input[nblocks*d.BlockSize():])
	return len(input), nil
}

func (d *digest) Sum(in []byte) []byte {
	var output [32]byte

	// Copy context so that caller can keep updating
	dc := *d

	dc.Write(in)

	idx := int(dc.len & uint64(dc.BlockSize()-1))
	for i := idx + 1; i < len(dc.b); i++ {
		dc.b[i] = 0
	}
	dc.b[idx] = 0x80
	if idx >= 56 {
		dc.compress(dc.b[:], 1)
		for i := range dc.b {
			dc.b[i] = 0
		}
	}

	// add total bits
	store64Be(dc.b[56:], dc.len*8)

	dc.compress(dc.b[:], 1)
	for i := 0; i < Size/4; i++ {
		store32Be(output[4*i:], dc.h[i])
	}
	return output[:]
}
