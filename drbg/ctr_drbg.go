// This is initial implementation of CTR_DRBG with AES-256. Code is tested
// and functionaly correct. Nevertheless it will be changed
//
// TODO: Following things still need to be done
// * Add other AES key lengts
// * Validate sizes from table 3 of SP800-90A
// * Improve reseeding so that code returns an error when reseed is needed
// * Add case with derivation function (maybe)
// * Code cleanup
// * Implement benchmark
// * Add rest of the test vectors from CAVP

package drbg

import (
	"github.com/henrydcase/nobs/drbg/internal/aes"
	"github.com/henrydcase/nobs/utils"
)

// Constants below correspond to AES-256, which is currently
// the only block cipher supported.
const (
	BlockLen = 16
	KeyLen   = 32
	SeedLen  = BlockLen + KeyLen
)

type CtrDrbg struct {
	v          [BlockLen]byte
	key        [KeyLen]byte
	counter    uint
	strength   uint
	resistance bool
	blockEnc   aes.IAES
	tmpBlk     [3 * BlockLen]byte
}

func NewCtrDrbg() *CtrDrbg {
	if utils.X86.HasAES {
		return &CtrDrbg{blockEnc: &aes.AESAsm{}}
	}
	return &CtrDrbg{blockEnc: &aes.AES{}}
}

func (c *CtrDrbg) inc() {
	for i := BlockLen - 1; i >= 0; i-- {
		if c.v[i] == 0xff {
			c.v[i] = 0x00
		} else {
			c.v[i]++
			break
		}
	}
}

func (c *CtrDrbg) Init(entropy, personalization []byte) bool {
	var lsz int
	var seedBuf [SeedLen]byte

	// Minimum entropy input (SP800-90A, 10.2.1)
	if len(entropy) < int(c.strength/8) {
		return false
	}

	// Security strength for AES-256 as per SP800-57, 5.6.1
	c.strength = 256

	lsz = len(entropy)
	if lsz > SeedLen {
		lsz = SeedLen
	}
	copy(seedBuf[:], entropy[:lsz])

	lsz = len(personalization)
	if lsz > SeedLen {
		lsz = SeedLen
	}

	for i := 0; i < lsz; i++ {
		seedBuf[i] ^= personalization[i]
	}

	c.blockEnc.SetKey(c.key[:])
	c.update(seedBuf[:])
	c.counter = 1
	return true
}

func (c *CtrDrbg) update(data []byte) {
	if len(data) != SeedLen {
		panic("Provided data is not equal to strength/8")
	}

	// deliberatelly not using len(c.tmpBlk)
	for i := 0; i < 3*BlockLen; i += BlockLen {
		c.inc()
		c.blockEnc.SetKey(c.key[:])
		c.blockEnc.Encrypt(c.tmpBlk[i:], c.v[:])
	}

	for i := 0; i < 3*BlockLen; i++ {
		c.tmpBlk[i] ^= data[i]
	}

	copy(c.key[:], c.tmpBlk[:KeyLen])
	copy(c.v[:], c.tmpBlk[KeyLen:])
}

func (c *CtrDrbg) Reseed(entropy, data []byte) {
	var seedBuf [SeedLen]byte
	var lsz int

	lsz = len(entropy)
	if lsz > SeedLen {
		lsz = SeedLen
	}
	copy(seedBuf[:], entropy[:lsz])

	lsz = len(data)
	if lsz > SeedLen {
		lsz = SeedLen
	}

	for i := 0; i < lsz; i++ {
		seedBuf[i] ^= data[i]
	}

	c.update(seedBuf[:])
	c.counter = 1
}

func (c *CtrDrbg) ReadWithAdditionalData(out, ad []byte) (n int, err error) {
	var seedBuf [SeedLen]byte
	// TODO: check reseed_counter > reseed_interval

	if len(ad) > 0 {
		// pad additional data with zeros if needed
		copy(seedBuf[:], ad)
		c.update(seedBuf[:])
	}

	// Number of blocks to write minus last one
	blocks := len(out) / BlockLen
	for i := 0; i < blocks; i++ {
		c.inc()
		c.blockEnc.SetKey(c.key[:])
		c.blockEnc.Encrypt(out[i*BlockLen:], c.v[:])
	}

	// Copy remainder - case for out being not block aligned
	c.blockEnc.Encrypt(c.tmpBlk[:], c.v[:])
	copy(out[blocks*BlockLen:], c.tmpBlk[:len(out)%BlockLen])

	c.update(seedBuf[:])
	c.counter += 1
	return len(out), nil
}

// Read reads data from DRBG. Size of data is determined by
// out buffer.
func (c *CtrDrbg) Read(out []byte) (n int, err error) {
	return c.ReadWithAdditionalData(out, nil)
}
