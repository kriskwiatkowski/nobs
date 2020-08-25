package mkem

import (
	"bytes"
	"testing"
)

// helper
func Ok(t testing.TB, f bool, msg string) {
	t.Helper()
	if !f {
		t.Error(msg)
	}
}

// helper
func OkE(t testing.TB, f error, msg string) {
	t.Helper()
	if f != nil {
		t.Error(msg)
	}
}

var keys10 [10]keypair
var keys100 [100]keypair
var keys1000 [1000]keypair
var meCsidh MultiEnc_csidh

/*
func init() {
	for i, _ := range keys10 {
		keys10[i] = meCsidh.NewKeypair()
	}

	for i, _ := range keys100 {
		keys100[i] = meCsidh.NewKeypair()
	}
}
*/

func mct_to_ct(ct *ciphertext, mct *multi_ciphertext, idx int) {
	copy(ct.u[:], mct.u[:])
	copy(ct.v[:], mct.v[idx][:])
}

func TestSinglePKE(t *testing.T) {
	k := meCsidh.NewKeypair()
	var msg [64]byte
	ct := meCsidh.Enc(&k.pk, &msg)
	pt := meCsidh.Dec(&k.sk, &ct)
	Ok(t,
		bytes.Equal(pt[:], msg[:]),
		"Decryption failed")

	// Do it twice to ensure it works with same key pair
	ct = meCsidh.Enc(&k.pk, &msg)
	pt = meCsidh.Dec(&k.sk, &ct)
	Ok(t, bytes.Equal(pt[:], msg[:]),
		"Decryption failed")

}

func TestMultiPKE(t *testing.T) {
	const num_keys = 10
	var msg [64]byte
	var keys [num_keys]keypair
	var ct ciphertext
	var mct multi_ciphertext

	mct.v = make([][64]byte, num_keys)

	for i, _ := range keys {
		keys[i] = meCsidh.NewKeypair()
	}

	// Check if it works for SinglePKE
	for i := 0; i < len(keys); i++ {
		ct = meCsidh.Enc(&keys[i].pk, &msg)
		pt := meCsidh.Dec(&keys[i].sk, &ct)
		Ok(t, bytes.Equal(pt[:], msg[:]),
			"SinglePKE decryption failed")
	}

	meCsidh.Enc_m(keys[:], &msg, &mct)
	for i := 0; i < len(keys); i++ {
		mct_to_ct(&ct, &mct, i)
		pt := meCsidh.Dec(&keys[i].sk, &ct)
		Ok(t, bytes.Equal(pt[:], msg[:]),
			"Multi decryption failed")
	}
}

func benchSingleEnc(keys []keypair) {
	var msg [64]byte
	var num = len(keys)
	var ct = make([]ciphertext, num)

	for i := 0; i < num; i++ {
		ct[i] = meCsidh.Enc(&keys[i].pk, &msg)
	}
}

func benchMultiEnc(keys []keypair) {
	var msg [64]byte
	var num = len(keys)
	var mct multi_ciphertext
	mct.v = make([][64]byte, num)

	meCsidh.Enc_m(keys[:], &msg, &mct)
}

func BenchmarkCSIDH_Enc_10keys(b *testing.B) {
	for i := 0; i < b.N; i++ {
		benchSingleEnc(keys10[:])
	}
}

func BenchmarkCSIDH_mEnc_10keys(b *testing.B) {
	for i := 0; i < b.N; i++ {
		benchMultiEnc(keys10[:])
	}
}

func BenchmarkCSIDH_Enc_100keys(b *testing.B) {
	for i := 0; i < b.N; i++ {
		benchSingleEnc(keys100[:])
	}
}

func BenchmarkCSIDH_mEnc_100keys(b *testing.B) {
	for i := 0; i < b.N; i++ {
		benchMultiEnc(keys100[:])
	}
}
