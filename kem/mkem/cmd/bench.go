package main

import (
	"crypto/rand"
	"fmt"
	"mkem"

	"github.com/dterei/gotsc"
	"github.com/henrydcase/nobs/dh/csidh"
	"github.com/henrydcase/nobs/dh/sidh"
	"github.com/henrydcase/nobs/dh/sidh/common"
	"github.com/henrydcase/nobs/drbg"
)

const (
	// number of recipients in mKEM (number of public keys created in init)
	nRecipients = 10
	// number of loops in bench function. each loop creates nRecipients ciphertexts
	nLoops = 3
)

type benchFunc func(int)

var sPKE mkem.PKE
var mPKE mkem.MultiPKE
var KEMp434 sidh.KEM
var KEMp503 sidh.KEM
var KEMp751 sidh.KEM
var mKEMp434 mkem.MultiKEM
var mKEMp503 mkem.MultiKEM
var mKEMp751 mkem.MultiKEM

var testSKS_csidh []csidh.PrivateKey
var testPKS_csidh []csidh.PublicKey
var testPKS_SIDHp434 []*sidh.PublicKey
var testPKS_SIDHp503 []*sidh.PublicKey
var testPKS_SIDHp751 []*sidh.PublicKey

var MessgaeTest [16]byte
var ct [common.MaxCiphertextBsz]byte
var ss [common.MaxSharedSecretBsz]byte

var rng *drbg.CtrDrbg

func init() {
	var tmp [32]byte

	rand.Read(tmp[:])
	rng = drbg.NewCtrDrbg()
	if !rng.Init(tmp[:], nil) {
		panic("Can't initialize DRBG")
	}

	sPKE.Allocate(rng)
	mPKE.Allocate(nRecipients, rng)

	testSKS_csidh = make([]csidh.PrivateKey, len(mPKE.Cts))
	testPKS_csidh = make([]csidh.PublicKey, len(mPKE.Cts))

	for i, _ := range mPKE.Cts {
		csidh.GeneratePrivateKey(&testSKS_csidh[i], mPKE.Rng)
		csidh.GeneratePublicKey(&testPKS_csidh[i], &testSKS_csidh[i], mPKE.Rng)
	}

	// create public keys for SIKE
	init_sike(common.Fp434, &testPKS_SIDHp434, &KEMp434)
	init_sike(common.Fp503, &testPKS_SIDHp503, &KEMp503)
	init_sike(common.Fp751, &testPKS_SIDHp751, &KEMp751)

	mKEMp434.Allocate(common.Fp434, nRecipients, rng)
	mKEMp503.Allocate(common.Fp503, nRecipients, rng)
	mKEMp751.Allocate(common.Fp751, nRecipients, rng)
}

func init_sike(id uint8, pks *[]*sidh.PublicKey, kem *sidh.KEM) {
	kem.Allocate(id, rng)
	sks := make([]*sidh.PrivateKey, nRecipients)
	*pks = make([]*sidh.PublicKey, nRecipients)
	for i := 0; i < nRecipients; i++ {
		sks[i] = sidh.NewPrivateKey(id, sidh.KeyVariantSike)
		(*pks)[i] = sidh.NewPublicKey(id, sidh.KeyVariantSike)
		_ = sks[i].Generate(rng)
		sks[i].GeneratePublicKey((*pks)[i])
	}
}

func bench_CSIDH_PKE(n int) {
	for i := 0; i < n*nRecipients; i++ {
		_ = sPKE.Enc(&testPKS_csidh[i%nRecipients], &MessgaeTest)
	}
}

func bench_CSIDH_mPKE(n int) {
	for i := 0; i < n; i++ {
		mPKE.Encrypt(testPKS_csidh[:], &MessgaeTest)
	}
}

func bench_SIKE_KEM(KEM *sidh.KEM, pkeys []*sidh.PublicKey, n int) {
	for i := 0; i < n*nRecipients; i++ {
		_ = KEM.Encapsulate(ct[:], ss[:], pkeys[i%nRecipients])
	}
}

func bench_SIKE_mKEM(KEM *mkem.MultiKEM, pkeys []*sidh.PublicKey, n int) {
	for i := 0; i < n; i++ {
		_ = KEM.Encapsulate(ss[:], pkeys)
	}
}

// runs FUT and prints out average cycle count for encryption to N users
func count_cycles(test_name string, f benchFunc, n int) {
	tsc := gotsc.TSCOverhead()
	t0 := gotsc.BenchStart()
	f(n)
	t1 := gotsc.BenchEnd()
	avg := (t1 - t0 - tsc) / uint64(n)
	fmt.Println(test_name+"    |", avg)
}

type alg struct {
	name string
	f    benchFunc
}

func main() {

	bench_SIKEp434_KEM := func(n int) { bench_SIKE_KEM(&KEMp434, testPKS_SIDHp434, n) }

	bench_SIKEp434_mKEM := func(n int) { bench_SIKE_mKEM(&mKEMp434, testPKS_SIDHp434, n) }

	fmt.Println("Test name:                | Cycle count:")
	fmt.Println("--------------------------|--------------")
	algs := []struct {
		name string
		f    benchFunc
	}{
		{"bench_SIKEp434_KEM    ", bench_SIKEp434_KEM},
		{"bench_SIKEp434_mKEM   ", bench_SIKEp434_mKEM},
		{"bench_CSIDH_PKE       ", bench_CSIDH_PKE},
		{"bench_CSIDH_mPKE      ", bench_CSIDH_mPKE},
	}

	// run all algorithms and count CPU cycles for each invocation
	for i := 0; i < len(algs); i++ {
		count_cycles(algs[i].name, algs[i].f, nLoops)
	}
}
