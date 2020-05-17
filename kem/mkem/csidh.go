package mkem

import (
	"github.com/henrydcase/nobs/dh/csidh"
	"github.com/henrydcase/nobs/drbg"
	"github.com/henrydcase/nobs/hash/sha3"
)

const (
	SharedSecretSz = 64
	PublicKeySz    = 64
)

// Used for storing cipertext
type ciphertext struct {
	// public key
	U [64]byte
	// private key
	V [64]byte
}

type PKE struct {
	Rng *drbg.CtrDrbg
	H   sha3.ShakeHash
}

type MultiPKE struct {
	PKE
	// stores ephemeral/internal public key
	Ct0 [PublicKeySz]byte
	// stores list of ciphertexts ct[i]
	Cts [][SharedSecretSz]byte
}

// Allocates PKE
func (c *PKE) Allocate(rng *drbg.CtrDrbg) {
	c.Rng = rng

	// Function H used in Algorithm 16 and 18
	c.H = sha3.NewShake128()
}

// Allocates MultiPKE
func (c *MultiPKE) Allocate(recipients_nb uint, rng *drbg.CtrDrbg) {
	c.PKE.Allocate(rng)
	c.Cts = make([][SharedSecretSz]byte, recipients_nb)
}

// PKE encryption
func (c *PKE) Enc(pk *csidh.PublicKey, pt *[16]byte) (ct ciphertext) {
	var ss [64]byte
	var pkA csidh.PublicKey
	var skA csidh.PrivateKey

	csidh.GeneratePrivateKey(&skA, c.Rng)
	csidh.DeriveSecret(&ss, pk, &skA, c.Rng)

	c.H.Reset()
	c.H.Write(ss[:])
	c.H.Read(ss[:16])
	for i := 0; i < 16; i++ {
		ct.V[i] = pt[i] ^ ss[i]
	}

	csidh.GeneratePublicKey(&pkA, &skA, c.Rng)
	pkA.Export(ct.U[:])
	return
}

// PKE decryption
func (c *PKE) Dec(sk *csidh.PrivateKey, ct *ciphertext) (pt [16]byte) {
	var ss [64]byte
	var pk csidh.PublicKey

	pk.Import(ct.U[:])
	csidh.DeriveSecret(&ss, &pk, sk, c.Rng)

	c.H.Reset()
	c.H.Write(ss[:])
	c.H.Read(ss[:16])
	for i := 0; i < 16; i++ {
		pt[i] = ct.V[i] ^ ss[i]
	}
	return
}

// mPKE encryption
func (c *MultiPKE) Encrypt(keys []csidh.PublicKey, pt *[16]byte) {
	var ss [64]byte
	var pkA csidh.PublicKey
	var skA csidh.PrivateKey

	csidh.GeneratePrivateKey(&skA, c.Rng)
	for i, pk := range keys {
		csidh.DeriveSecret(&ss, &pk, &skA, c.Rng)

		c.H.Write(ss[:])
		c.H.Read(ss[:16])
		c.H.Reset()
		for j := 0; j < 16; j++ {
			c.Cts[i][j] = pt[j] ^ ss[j]
		}
	}

	csidh.GeneratePublicKey(&pkA, &skA, c.Rng)
	pkA.Export(c.Ct0[:])
	return
}
