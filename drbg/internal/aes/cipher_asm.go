// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// +build amd64, !noasm

package aes

import (
	"github.com/henrydcase/nobs/utils"
)

// defined in asm_*.s

//go:noescape
func encryptBlockAsm(nr int, xk *uint32, dst, src *byte)

//go:noescape
func decryptBlockAsm(nr int, xk *uint32, dst, src *byte)

//go:noescape
func expandKeyAsm(nr int, key *byte, enc *uint32, dec *uint32)

type AESAsm struct {
	enc [32 + 28]uint32
	dec [32 + 28]uint32
}

func (c *AESAsm) SetKey(key []byte) error {
	var rounds int
	switch len(key) {
	case 128 / 8:
		rounds = 10
	case 192 / 8:
		rounds = 12
	case 256 / 8:
		rounds = 14
	}

	expandKeyAsm(rounds, &key[0], &c.enc[0], &c.dec[0])
	return nil
}

func (c *AESAsm) BlockSize() int { return BlockSize }

func (c *AESAsm) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/aes: output not full block")
	}
	if InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("crypto/aes: invalid buffer overlap")
	}
	encryptBlockAsm(len(c.enc)/4-1, &c.enc[0], &dst[0], &src[0])
}

func (c *AESAsm) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/aes: output not full block")
	}
	if InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("crypto/aes: invalid buffer overlap")
	}
	decryptBlockAsm(len(c.dec)/4-1, &c.dec[0], &dst[0], &src[0])
}

// expandKey is used by BenchmarkExpand to ensure that the asm implementation
// of key expansion is used for the benchmark when it is available.
func expandKey(key []byte, enc, dec []uint32) {
	if utils.X86.HasAES {
		rounds := 10 // rounds needed for AES128
		switch len(key) {
		case 192 / 8:
			rounds = 12
		case 256 / 8:
			rounds = 14
		}
		expandKeyAsm(rounds, &key[0], &enc[0], &dec[0])
	} else {
		expandKeyGo(key, enc, dec)
	}
}
