// Copyright 2020 Kris Kwiatkowski. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3

import (
	"errors"
	"hash"
)

type spongeDesc struct {
	r    int    // rate
	d    int    // output size of SHA-3
	name string // human readable name of the scheme
}

// Id's of SHA3 instantiations
const (
	SHA3_224 uint8 = iota
	SHA3_256
	SHA3_384
	SHA3_512
	SHAKE128
	SHAKE256
)

const (
	// maximum value for rate used by keccak functions
	maxRate = 168
)

// Statically allocated error message
var ErrWriteAfterRead = errors.New("sha3: can't write after read")

var Sha3Desc = map[uint8]spongeDesc{
	SHA3_224: {r: 144, d: 224 / 8, name: "SHA3-224"},
	SHA3_256: {r: 136, d: 256 / 8, name: "SHA3-256"},
	SHA3_384: {r: 104, d: 384 / 8, name: "SHA3-384"},
	SHA3_512: {r: 72, d: 512 / 8, name: "SHA3-512"},
	SHAKE128: {r: 168, d: 0, name: "SHAKE-128"},
	SHAKE256: {r: 136, d: 0, name: "SHAKE-128"},
}

type state struct {
	// Structure describing the details of hash algorithm
	desc spongeDesc
	// permuation state. 25*64 is a width of the keccak permutation used
	a [25]uint64
	// sfx is a concatenation of "domain separator" as described in FIPS-202,
	// (section 6.1 and 6.2) with first bit of a pad10*1 (see section 5.1).
	sfx byte
	// Temporary data buffer
	data storageBuf
	// Index in the buffer. it points to the next available possition
	// in the data buffer if isSquezing is false. In case it is true
	// it indicates amount of unconsumed data.
	idx int
	// Indicates state of the sponge function. Whether it is absorbing
	// or squezing
	isSquezing bool
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// BlockSize returns block size in bytes. Corresponds to the input
// block size B of the HMAC
func (d *state) BlockSize() int { return d.desc.r }

// Size returns the output size of the hash function in bytes.
func (d *state) Size() int { return d.desc.d }

// Reset clears the internal state by zeroing the sponge state and
// the byte buffer, and setting spongeState to absorbing.
func (d *state) Reset() {
	// Zero the permutation's state.
	for i := range d.a {
		d.a[i] = 0
	}
	for i := range d.data {
		d.data[i] = 0
	}
	d.isSquezing = false
	d.idx = 0
}

// Write consumes data from the user. The data may change state of the
// hash in case caller provided at least "rate" bytes of data. The "rate" value
// for the hash is returned by the BlockSize() function. It may return an
// error if sponge state has changed to "squeezing", meaning - Write was
// called after at least one call to Read() has been done.
func (c *state) Write(in []byte) (nwrite int, err error) {
	if c.isSquezing {
		return 0, ErrWriteAfterRead
	}
	nwrite = len(in)
	rate := c.BlockSize()

	buf := c.data.asBytes()

	processLen := c.idx + len(in)
	if processLen < c.BlockSize() {
		// not enough data to process
		copy(buf[c.idx:], in)
		c.idx = processLen
		return nwrite, nil
	}

	// process first block
	fbLen := rate - c.idx
	copy(buf[c.idx:], in[:fbLen])
	xorIn(c, buf[:])
	keccakF1600(&c.a)

	// process remaining blocks
	in = in[fbLen:]
	for len(in) >= rate {
		xorIn(c, in[:rate])
		keccakF1600(&c.a)
		in = in[rate:]
	}

	// store unprocessed data
	copy(buf[:], in)
	c.idx = len(in)

	return nwrite, nil
}

// Read changes state of the hash if called first time. It will
// return len(out) bytes of data. Never fails.
func (c *state) Read(out []byte) (nread int, err error) {
	buf := c.data.asBytes()[:]
	rate := c.BlockSize()
	nread = len(out)

	if !c.isSquezing {
		// there is at least one byte free, otherise
		// buf would be squezed already
		for i := c.idx + 1; i < rate; i++ {
			buf[i] = 0
		}
		buf[c.idx] = c.sfx
		buf[rate-1] |= 0x80
		xorIn(c, buf[:rate])
		keccakF1600(&c.a)
		copyOut(c, buf[:rate])
		c.idx = rate // now, idx indicates unconsumed amount of data
		c.isSquezing = true
	}

	// Copy-out bytes that are still kept in the buffer
	if c.idx != 0 {
		l := min(c.idx, len(out))
		idx := rate - c.idx
		copy(out, buf[idx:idx+l])
		out = out[l:]
		c.idx -= l
	}

	l := len(out)
	if l == 0 {
		// nothing else todo
		return nread, nil
	}

	// copy out full blocks and squeeze. at this point
	// there is no more data in the buffer.
	nblocks := l / rate
	for i := 0; i < nblocks; i++ {
		keccakF1600(&c.a)
		copyOut(c, out[:rate])
		out = out[rate:]
	}

	// produce more if needed
	l = len(out)
	if l == 0 {
		return nread, nil
	}

	keccakF1600(&c.a)
	copyOut(c, buf)
	copy(out, buf[:l])
	c.idx = rate - l
	return nread, nil
}

// Sum applies padding to the hash state and then squeezes out the desired
// number of output bytes.
func (c *state) Sum(in []byte) []byte {
	l := len(in)
	// create buffer if nil has been provided
	if in == nil {
		in = make([]byte, c.Size())
	}

	// enlarge capacity of the buffer if needed
	if cap(in) < (l + c.Size()) {
		b := make([]byte, l+c.Size()-cap(in))
		in = append(in[:cap(in)], b...)
	}

	in = in[:l+c.Size()]
	c.Read(in[l:])
	return in
}

// New224 creates a new SHA3-224 hash.
// Its generic security strength is 224 bits against preimage attacks,
// and 112 bits against collision attacks.
func New224() hash.Hash {
	return &state{sfx: 0x06, desc: Sha3Desc[SHA3_224]}
}

// New256 creates a new SHA3-256 hash.
// Its generic security strength is 256 bits against preimage attacks,
// and 128 bits against collision attacks.
func New256() hash.Hash {
	return &state{sfx: 0x06, desc: Sha3Desc[SHA3_256]}
}

// New384 creates a new SHA3-384 hash.
// Its generic security strength is 384 bits against preimage attacks,
// and 192 bits against collision attacks.
func New384() hash.Hash {
	return &state{sfx: 0x06, desc: Sha3Desc[SHA3_384]}
}

// New512 creates a new SHA3-512 hash.
// Its generic security strength is 512 bits against preimage attacks,
// and 256 bits against collision attacks.
func New512() hash.Hash {
	return &state{sfx: 0x06, desc: Sha3Desc[SHA3_512]}
}
