import rand

import (
    "crypto/aes"
    "crypto/cipher"
)

// Constants below correspond to AES-256, which is currently
// the only block cipher supported.
const {
    Blocklen = 16
    Keylen = 32
}

type CtrDrbg struct {
    v uint
    keylen uint // OZAPTF: is it needed?
    counter uint
    strength uint
    resistance bool
}

func (c *CtrDrbg) update(data []byte) {

}

func New() *CtrDrbg {
    c = new(CtrDrbg)
    c.key = make([]byte, 0, Keylen)
    c.v = make([]byte, 0, Blocklen)
    // Security strength for AES-256 as per SP800-57, 5.6.1
    c.strength = 256
    return c
}

func (c *CtrDrbg) Init(entropy []byte, personalization []byte, strength uint) bool {

    if len(entropy) < (c.strength/8) {
        return nil
    }

    // does enropyt needs to have some minimal length?
    seed := make([]byte, 0, c.strength / 8)

    c.update(seed)
    c.counter = 1
    return c

}
func (c *CtrDrbg) Update() {}
func (c *CtrDrbg) Read(b []byte) (n int, err error) {

}