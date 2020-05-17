package mkem

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/henrydcase/nobs/dh/csidh"
	"github.com/henrydcase/nobs/drbg"
)

var sPKE PKE
var mPKE MultiPKE

var testSKS []csidh.PrivateKey
var testPKS []csidh.PublicKey

// helper
func Ok(t testing.TB, f bool, msg string) {
	t.Helper()
	if !f {
		t.Error(msg)
	}
}

func init() {
	var tmp [32]byte
	var rng *drbg.CtrDrbg

	rand.Read(tmp[:])
	rng = drbg.NewCtrDrbg()
	if !rng.Init(tmp[:], nil) {
		panic("Can't initialize DRBG")
	}

	sPKE.Allocate(rng)
	mPKE.Allocate(10, rng)

	testSKS = make([]csidh.PrivateKey, len(mPKE.Cts))
	testPKS = make([]csidh.PublicKey, len(mPKE.Cts))

	for i, _ := range mPKE.Cts {
		csidh.GeneratePrivateKey(&testSKS[i], mPKE.Rng)
		csidh.GeneratePublicKey(&testPKS[i], &testSKS[i], mPKE.Rng)
	}

}

func getCiphertext(ct *ciphertext, mPKE *MultiPKE, i int) {
	copy(ct.U[:], mPKE.Ct0[:])
	copy(ct.V[:], mPKE.Cts[i][:])
}

func TestSinglePKE(t *testing.T) {
	var pk csidh.PublicKey
	var sk csidh.PrivateKey

	csidh.GeneratePrivateKey(&sk, sPKE.Rng)
	csidh.GeneratePublicKey(&pk, &sk, sPKE.Rng)

	var msg [16]byte
	ct := sPKE.Enc(&pk, &msg)
	pt := sPKE.Dec(&sk, &ct)
	Ok(t, bytes.Equal(pt[:], msg[:]), "Decryption failed")

	// Do it twice to ensure it works with same key pair
	ct = sPKE.Enc(&pk, &msg)
	pt = sPKE.Dec(&sk, &ct)
	Ok(t, bytes.Equal(pt[:], msg[:]),
		"Decryption failed")

}

func TestMultiPKE(t *testing.T) {
	var msg [16]byte
	var ct ciphertext

	pks := make([]csidh.PublicKey, len(mPKE.Cts))
	sks := make([]csidh.PrivateKey, len(mPKE.Cts))

	//	mct.Cts = make([][SharedSecretSz]byte)

	for i, _ := range mPKE.Cts {
		csidh.GeneratePrivateKey(&sks[i], mPKE.Rng)
		csidh.GeneratePublicKey(&pks[i], &sks[i], mPKE.Rng)
	}

	mPKE.Encrypt(pks[:], &msg)
	for i := 0; i < len(mPKE.Cts); i++ {
		getCiphertext(&ct, &mPKE, i)
		pt := sPKE.Dec(&sks[i], &ct)
		Ok(t, bytes.Equal(pt[:], msg[:]),
			"Multi decryption failed")
	}
}

var MessgaeTest [16]byte

func BenchmarkEncrypt_CSIDH_p512(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = sPKE.Enc(&testPKS[0], &MessgaeTest)
	}
}

func BenchmarkMultiEncrypt_CSIDH_100keys(b *testing.B) {
	for i := 0; i < b.N; i++ {
		mPKE.Encrypt(testPKS[:], &MessgaeTest)
	}
}
