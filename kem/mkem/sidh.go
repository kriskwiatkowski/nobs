package mkem

import (
	"github.com/henrydcase/nobs/dh/sidh"
)

const (
	// Initiator key type
	InitKeyVariant = sidh.KeyVariantSidhB
	// Key type created by encryption function
	EncKeyVariant = sidh.KeyVariantSidhA
)

type sidh_keypair struct {
	pk sidh.PublicKey
	sk sidh.PrivateKey
}

type sidh_ciphertext struct {
	pk [564]byte
	ct [64]byte
}

type sidh_multi_ciphertext struct {
	pk  [564]byte
	cts [][64]byte
}

type MultiEnc_sidh struct {
	ct       sidh_ciphertext
	ct_multi sidh_multi_ciphertext
	ss       [188]byte
}

func (c MultiEnc_sidh) NewInitKeypair() (kp sidh_keypair) {
	kp.sk.Init(sidh.Fp751, InitKeyVariant)
	kp.pk.Init(sidh.Fp751, InitKeyVariant)
	sidh.GeneratePrivateKey(&kp.sk, rng)
	sidh.GeneratePublicKey(&kp.pk, &kp.sk)
	return kp
}

func (c MultiEnc_sidh) NewEncKeypair() (kp sidh_keypair) {
	kp.sk.Init(sidh.Fp751, EncKeyVariant)
	kp.pk.Init(sidh.Fp751, EncKeyVariant)
	sidh.GeneratePrivateKey(&kp.sk, rng)
	sidh.GeneratePublicKey(&kp.pk, &kp.sk)
	return kp
}

func (c MultiEnc_sidh) Enc(pk *sidh.PublicKey, pt *[64]byte) (out sidh_ciphertext) {
	var digest [64]byte

	enc_key := c.NewEncKeypair()
	sidh.DeriveSecret(c.ss[:], pk, &enc_key.sk)
	h.Reset()
	h.Write(c.ss[:110])
	h.Read(digest[:])
	for i := 0; i < len(digest); i++ {
		out.ct[i] = pt[i] ^ digest[i]
	}

	enc_key.pk.Export(out.pk[:])
	return
}

func (c MultiEnc_sidh) Dec(sk *sidh.PrivateKey, in *sidh_ciphertext) (pt [64]byte) {
	var pk sidh.PublicKey
	var digest [64]byte

	pk.Init(sidh.Fp751, EncKeyVariant)
	if pk.Import(in.pk[:]) != nil {
		panic("Import failed")
	}

	sidh.DeriveSecret(c.ss[:], &pk, sk)
	h.Reset()
	h.Write(c.ss[:110])
	h.Read(digest[:])
	for i := 0; i < len(digest); i++ {
		pt[i] = in.ct[i] ^ digest[i]
	}
	return
}

func (c MultiEnc_sidh) Enc_m(keys []sidh_keypair, pt *[64]byte, out *sidh_multi_ciphertext) {
	var digest [64]byte

	enc_key := c.NewEncKeypair()
	for i, key := range keys {
		sidh.DeriveSecret(c.ss[:], &key.pk, &enc_key.sk)

		h.Reset()
		h.Write(c.ss[:110])
		h.Read(digest[:])
		for j := 0; j < len(digest); j++ {
			out.cts[i][j] = pt[j] ^ digest[j]
		}
	}

	enc_key.pk.Export(out.pk[:])
	return
}
