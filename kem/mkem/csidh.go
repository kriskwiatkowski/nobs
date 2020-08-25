package mkem

import (
	"crypto/rand"

	"github.com/henrydcase/nobs/dh/csidh"
	"github.com/henrydcase/nobs/drbg"
	"github.com/henrydcase/nobs/hash/sha3"
)

type keypair struct {
	pk csidh.PublicKey
	sk csidh.PrivateKey
}

type ciphertext struct {
	u [64]byte
	v [64]byte
}

type multi_ciphertext struct {
	u [64]byte
	v [][64]byte
}

type MultiEnc_csidh struct {
}

var rng *drbg.CtrDrbg

// Function H used in Algorithm 16 and 18
var h = sha3.NewShake128()

func init() {
	var tmp [32]byte

	rand.Read(tmp[:])
	rng = drbg.NewCtrDrbg()
	if !rng.Init(tmp[:], nil) {
		panic("Can't initialize DRBG")
	}
}

func (c MultiEnc_csidh) NewKeypair() (kp keypair) {
	csidh.GeneratePrivateKey(&kp.sk, rng)
	csidh.GeneratePublicKey(&kp.pk, &kp.sk, rng)
	return kp
}

func (c MultiEnc_csidh) Enc(pk *csidh.PublicKey, pt *[64]byte) (ct ciphertext) {
	var ss [64]byte

	enc_key := c.NewKeypair()
	csidh.DeriveSecret(&ss, pk, &enc_key.sk, rng)
	h.Write(ss[:])
	h.Read(ss[:64])
	h.Reset()
	for i := 0; i < len(ss); i++ {
		ct.v[i] = pt[i] ^ ss[i]
	}

	enc_key.pk.Export(ct.u[:])
	return
}

func (c MultiEnc_csidh) Dec(sk *csidh.PrivateKey, ct *ciphertext) (pt [64]byte) {
	var ss [64]byte
	var pk csidh.PublicKey

	pk.Import(ct.u[:])
	csidh.DeriveSecret(&ss, &pk, sk, rng)
	h.Write(ss[:])
	h.Read(ss[:64])
	h.Reset()
	for i := 0; i < len(ss); i++ {
		pt[i] = ct.v[i] ^ ss[i]
	}
	return
}

func (c MultiEnc_csidh) Enc_m(keys []keypair, pt *[64]byte, ct *multi_ciphertext) {
	var ss [64]byte

	enc_key := c.NewKeypair()
	for i, key := range keys {
		csidh.DeriveSecret(&ss, &key.pk, &enc_key.sk, rng)

		h.Write(ss[:])
		h.Read(ss[:64])
		h.Reset()
		for j := 0; j < len(ss); j++ {
			ct.v[i][j] = pt[j] ^ ss[j]
		}
	}

	enc_key.pk.Export(ct.u[:])
	return
}
