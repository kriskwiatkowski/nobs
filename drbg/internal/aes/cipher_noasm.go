// +build noasm ppc64le riscv64

package aes

import(
        "errors"
)

type AESAsm struct {
}

func (a *AESAsm) SetKey(key []byte) error {
        panic("NotImplemented")
        return errors.New("ErrNotImplemented")
}

func (a *AESAsm) Encrypt(dst, src []byte) {
        panic("NotImplemented")
}

func (a *AESAsm) Decrypt(dst, src []byte) {
        panic("NotImplemented")
}

func expandKey(key []byte, enc, dec []uint32) {
        expandKeyGo(key, enc, dec)
}
