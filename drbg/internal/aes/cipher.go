// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// +build noasm amd64 arm64 ppc64le riscv64

package aes

import (
	"strconv"
)

// The AES block size in bytes.
const BlockSize = 16

// A cipher is an instance of AES encryption using a particular key.
type AES struct {
	enc    [32 + 28]uint32
	dec    [32 + 28]uint32
	keyLen int
}

// AES interface
type IAES interface {
	SetKey(key []byte) error
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "crypto/aes: invalid key size " + strconv.Itoa(int(k))
}

func NewCipher() *AES {
	return new(AES)
}

// NewCipher creates and returns a new cipher.Block.
// The key argument should be the AES key,
// either 16, 24, or 32 bytes to select
// AES-128, AES-192, or AES-256.
func (c *AES) SetKey(key []byte) error {
	k := len(key)

	switch k {
	default:
		return KeySizeError(k)
	case 16, 24, 32:
		break
	}
	for i, _ := range c.enc {
		c.enc[i] = 0
	}
	for i, _ := range c.dec {
		c.dec[i] = 0
	}
	c.keyLen = k
	expandKeyGo(key, c.enc[:c.keyLen+28], c.dec[:c.keyLen+28])
	return nil
}

func (c *AES) BlockSize() int { return BlockSize }

func (c *AES) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/aes: output not full block")
	}
	if InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("crypto/aes: invalid buffer overlap")
	}
	encryptBlockGo(c.enc[:c.keyLen+28], dst, src)
}

func (c *AES) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/aes: output not full block")
	}
	if InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("crypto/aes: invalid buffer overlap")
	}
	decryptBlockGo(c.dec[:c.keyLen+28], dst, src)
}
