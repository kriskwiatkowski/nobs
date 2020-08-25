package mkem

import (
	"bytes"
	"testing"
)

var sidh_keys10 [10]sidh_keypair
var sidh_keys100 [100]sidh_keypair
var sidh_keys1000 [1000]sidh_keypair
var meSIDH MultiEnc_sidh

func sidh_mct_to_ct(ct *sidh_ciphertext, mct *sidh_multi_ciphertext, idx int) {
	copy(ct.pk[:], mct.pk[:])
	copy(ct.ct[:], mct.cts[idx][:])
}

func init() {
	/*
		for i, _ := range sidh_keys10 {
			sidh_keys10[i] = meSIDH.NewInitKeypair()
		}

		for i, _ := range sidh_keys100 {
			sidh_keys100[i] = meSIDH.NewInitKeypair()
		}
	*/
}

func TestSIDH_PKE(t *testing.T) {
	var msg [64]byte

	k := meSIDH.NewInitKeypair()
	ct := meSIDH.Enc(&k.pk, &msg)
	pt := meSIDH.Dec(&k.sk, &ct)
	Ok(t,
		bytes.Equal(pt[:], msg[:]),
		"Decryption failed")

	// Do it twice to ensure it works with same key pair
	ct = meSIDH.Enc(&k.pk, &msg)
	pt = meSIDH.Dec(&k.sk, &ct)
	Ok(t, bytes.Equal(pt[:], msg[:]),
		"Decryption failed")

}

func TestSIDH_mPKE(t *testing.T) {
	const num_keys = 10
	var msg [64]byte
	var keys [num_keys]sidh_keypair
	var ct sidh_ciphertext
	var mct sidh_multi_ciphertext

	mct.cts = make([][64]byte, num_keys)

	for i, _ := range keys {
		keys[i] = meSIDH.NewInitKeypair()
	}

	meSIDH.Enc_m(keys[:], &msg, &mct)
	for i := 0; i < len(keys); i++ {
		sidh_mct_to_ct(&ct, &mct, i)
		pt := meSIDH.Dec(&keys[i].sk, &ct)
		Ok(t, bytes.Equal(pt[:], msg[:]),
			"Multi decryption failed")
	}
}

func bench_SIDH_Enc(keys []sidh_keypair) {
	var msg [64]byte
	var num = len(keys)
	var ct = make([]sidh_ciphertext, num)

	for i := 0; i < num; i++ {
		ct[i] = meSIDH.Enc(&keys[i].pk, &msg)
	}
}

func bench_SIDH_mEnc(keys []sidh_keypair) {
	var msg [64]byte
	var num = len(keys)
	var mct sidh_multi_ciphertext
	mct.cts = make([][64]byte, num)

	meSIDH.Enc_m(keys[:], &msg, &mct)
}

func Benchmark_SIDH_Enc_10keys(b *testing.B) {
	for i := 0; i < b.N; i++ {
		bench_SIDH_Enc(sidh_keys10[:])
	}
}

func Benchmark_SIDH_mEnc_10keys(b *testing.B) {
	for i := 0; i < b.N; i++ {
		bench_SIDH_mEnc(sidh_keys10[:])
	}
}

func Benchmark_SIDH_Enc_100keys(b *testing.B) {
	for i := 0; i < b.N; i++ {
		bench_SIDH_Enc(sidh_keys100[:])
	}
}

func Benchmark_SIDH_mEnc_100keys(b *testing.B) {
	for i := 0; i < b.N; i++ {
		bench_SIDH_mEnc(sidh_keys100[:])
	}
}
