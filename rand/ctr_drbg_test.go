import rand

import (
    "testing"
    "fmt"
    "io"
    "os"

    "crypto/aes"
    "crypto/cipher"
)

func TestNominal(t* testing.T) {
    block, err := aes.NewCipher(key)
    if err != nil {
        panic(err)
    }

    stream := cipher.NewCTR(block, iv)
    stream.XORKeyStream(pt, ct)
}