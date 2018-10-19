package csidh

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"

	crand "crypto/rand"
	mrand "math/rand"
	"testing"
)

// Possible values for "Status"
const (
	Valid               = iota // Indicates that shared secret must be agreed correctly
	ValidPublicKey2            // Public key 2 must succeed validation
	InvalidSharedSecret        // Calculated shared secret must be different than test vector
	InvalidPublicKey1          // Public key 1 generated from private key must be different than test vector
	InvalidPublicKey2          // Public key 2 must fail validation
)

var StatusValues = map[int]string{
	Valid:               "valid",
	ValidPublicKey2:     "valid_public_key2",
	InvalidSharedSecret: "invalid_shared_secret",
	InvalidPublicKey1:   "invalid_public_key1",
	InvalidPublicKey2:   "invalid_public_key2",
}

type TestVector struct {
	Id     int    `json:"Id"`
	Pk1    string `json:"Pk1"`
	Pr1    string `json:"Pr1"`
	Pk2    string `json:"Pk2"`
	Ss     string `json:"Ss"`
	Status string `json:"status"`
}

type TestVectors struct {
	Vectors []TestVector `json:"Vectors"`
}

func eq64(x, y []uint64) uint {
	for i, _ := range x {
		if x[i] != y[i] {
			return 0
		}
	}
	return 1
}

func TestCtEq64(t *testing.T) {
	var t1, t2 [8]uint64
	for i := 0; i < kNumIter; i++ {
		for i, _ := range t1 {
			t1[i] = mrand.Uint64()
			t2[i] = mrand.Uint64()
		}

		if ctEq64(t1[:], t2[:]) != eq64(t1[:], t2[:]) {
			t.FailNow()
		}
	}

	var t3 = [8]uint64{1, 2, 3, 4, 5, 6, 7, 8}
	var t4 = [8]uint64{1, 2, 3, 4, 5, 6, 7, 8}
	if ctEq64(t3[:], t4[:]) != eq64(t3[:], t4[:]) {
		t.FailNow()
	}
}

func TestEphemeralKeyExchange(t *testing.T) {
	var pub_bytes1, pub_bytes2 [64]uint8
	var ss1, ss2 [64]byte
	var prv1, prv2 PrivateKey
	var pub1, pub2 PublicKey

	prv_bytes1 := []byte{0xaa, 0x54, 0xe4, 0xd4, 0xd0, 0xbd, 0xee, 0xcb, 0xf4, 0xd0, 0xc2, 0xbc, 0x52, 0x44, 0x11, 0xee, 0xe1, 0x14, 0xd2, 0x24, 0xe5, 0x0, 0xcc, 0xf5, 0xc0, 0xe1, 0x1e, 0xb3, 0x43, 0x52, 0x45, 0xbe, 0xfb, 0x54, 0xc0, 0x55, 0xb2}
	prv_bytes2 := []byte{0xbb, 0x54, 0xe4, 0xd4, 0xd0, 0x1d, 0xee, 0xcb, 0xf4, 0xd0, 0xc2, 0xbc, 0x52, 0x44, 0x11, 0xee, 0xe1, 0x14, 0xd2, 0x24, 0xe5, 0x0, 0xcc, 0xf5, 0xc0, 0xe1, 0x1e, 0xb3, 0x43, 0x52, 0x45, 0xbe, 0xfb, 0x54, 0xc0, 0x55, 0xb2}
	prv1.Import(prv_bytes1)
	pub1.Generate(&prv1)
	pub1.Export(pub_bytes1[:])

	prv2.Import(prv_bytes2)
	pub2.Generate(&prv2)
	pub2.Export(pub_bytes2[:])

	pub1.DeriveSecret(ss1[:], &pub1, &prv2)
	pub2.DeriveSecret(ss2[:], &pub2, &prv1)

	if !bytes.Equal(ss1[:], ss2[:]) {
		t.Error("ss1 != ss2")
	}
}

func TestPrivateKeyExportImport(t *testing.T) {
	var buf [37]uint8
	for i := 0; i < 100; i++ {
		var prv1, prv2 PrivateKey
		prv1.Generate(crand.Reader)
		prv1.Export(buf[:])
		prv2.Import(buf[:])

		for i := 0; i < len(prv1.e); i++ {
			if prv1.e[i] != prv2.e[i] {
				t.Error("Error occured when public key export/import")
			}
		}
	}
}

func TestPublicKeyExportImport(t *testing.T) {
	var buf [64]uint8
	for i := 0; i < 10; i++ {
		var prv PrivateKey
		var pub1, pub2 PublicKey
		prv.Generate(crand.Reader)
		pub1.Generate(&prv)

		pub1.Export(buf[:])
		pub2.Import(buf[:])

		if eq64(pub1.A[:], pub2.A[:]) != 1 {
			t.Error("Error occured when public key export/import")
		}
	}
}

// does processing of
func testProcessTestVectors(t *testing.T) {
	var tests TestVectors

	// Helper checks if e==true and reports an error if not.
	checkExpr := func(e bool, vec *TestVector, t *testing.T, msg string) {
		if !e {
			t.Errorf("[Test ID=%d] "+msg, vec.Id)
		}
	}

	// checkSharedSecret implements nominal case - imports asymmetric keys for
	// both parties, derives secret key and compares it to value in test vector.
	// Comparision must succeed in case status is "Valid" in any other case
	// it must fail.
	checkSharedSecret := func(vec *TestVector, t *testing.T, status int) {
		var prvA PrivateKey
		var pubA, pubB PublicKey
		var ss [SharedSecretSize]byte

		prBuf, err := hex.DecodeString(vec.Pr1)
		if err != nil {
			t.Fatal(err)
		}
		checkExpr(
			prvA.Import(prBuf[:]),
			vec, t, "PrivateKey wrong")

		pkBuf, err := hex.DecodeString(vec.Pk1)
		if err != nil {
			t.Fatal(err)
		}
		checkExpr(
			pubA.Import(pkBuf[:]),
			vec, t, "PublicKey 1 wrong")

		pkBuf, err = hex.DecodeString(vec.Pk2)
		if err != nil {
			t.Fatal(err)
		}
		checkExpr(
			pubB.Import(pkBuf[:]),
			vec, t, "PublicKey 2 wrong")

		checkExpr(
			pubA.DeriveSecret(ss[:], &pubB, &prvA),
			vec, t, "Error when deriving key")

		ssExp, err := hex.DecodeString(vec.Ss)
		if err != nil {
			t.Fatal(err)
		}
		checkExpr(
			bytes.Equal(ss[:], ssExp) == (status == Valid),
			vec, t, "Unexpected value of shared secret")
	}

	// checkPublicKey1 imports public and private key for one party A
	// and tries to generate public key for a private key. After that
	// it compares generated key to a key from test vector. Comparision
	// must fail.
	checkPublicKey1 := func(vec *TestVector, t *testing.T) {
		var prv PrivateKey
		var pub PublicKey
		var pubBytesGot [PublicKeySize]byte

		prBuf, err := hex.DecodeString(vec.Pr1)
		if err != nil {
			t.Fatal(err)
		}

		pubBytesExp, err := hex.DecodeString(vec.Pk1)
		if err != nil {
			t.Fatal(err)
		}

		checkExpr(
			prv.Import(prBuf[:]),
			vec, t, "PrivateKey wrong")

		// Generate public key
		pub.Generate(&prv)
		pub.Export(pubBytesGot[:])

		// pubBytesGot must be different than pubBytesExp
		checkExpr(
			!bytes.Equal(pubBytesGot[:], pubBytesExp),
			vec, t, "Public key generated is the same as public key from the test vector")
	}

	// checkPublicKey2 the goal is to test key validation. Test tries to
	// import public key for B and ensure that import suceeds in case
	// status is "Valid" and fails otherwise.
	checkPublicKey2 := func(vec *TestVector, t *testing.T, status int) {
		var pub PublicKey

		pubBytesExp, err := hex.DecodeString(vec.Pk2)
		if err != nil {
			t.Fatal(err)
		}

		// Import validates an input, so it must fail
		checkExpr(
			pub.Import(pubBytesExp[:]) == (status == Valid || status == ValidPublicKey2),
			vec, t, "PublicKey has been validated correctly")
	}

	// Load test data
	file, err := os.Open("../../etc/csidh_testvectors.dat")
	if err != nil {
		t.Fatal(err.Error())
	}
	err = json.NewDecoder(file).Decode(&tests)
	if err != nil {
		t.Fatal(err.Error())
	}

	// Loop over all test cases
	for _, test := range tests.Vectors {
		switch test.Status {
		case StatusValues[Valid]:
			checkSharedSecret(&test, t, Valid)
			checkPublicKey2(&test, t, Valid)
		case StatusValues[InvalidSharedSecret]:
			checkSharedSecret(&test, t, InvalidSharedSecret)
		case StatusValues[InvalidPublicKey1]:
			checkPublicKey1(&test, t)
		case StatusValues[InvalidPublicKey2]:
			checkPublicKey2(&test, t, InvalidPublicKey2)
		case StatusValues[InvalidPublicKey2]:
			checkPublicKey2(&test, t, InvalidPublicKey2)
		case StatusValues[ValidPublicKey2]:
			checkPublicKey2(&test, t, ValidPublicKey2)
		}
	}

	// TODO: add test vector showing that key
}

func TestProcessTestVectors(t *testing.T) { testProcessTestVectors(t) }

func BenchmarkGeneratePrivate(b *testing.B) {
	var prv PrivateKey
	for n := 0; n < b.N; n++ {
		prv.Generate(crand.Reader)
	}
}

func BenchmarkValidate(b *testing.B) {
	var pub PublicKey
	var prv PrivateKey
	for n := 0; n < b.N; n++ {
		prv.Generate(crand.Reader)
		pub.Generate(&prv)
		pub.Validate()
	}
}

func BenchmarkEphemeralKeyExchange(b *testing.B) {
	var ss [64]uint8
	var prv1, prv2 PrivateKey
	var pub1, pub2 PublicKey
	for n := 0; n < b.N; n++ {
		prv1.Generate(crand.Reader)
		pub1.Generate(&prv1)

		prv2.Generate(crand.Reader)
		pub2.Generate(&prv2)

		pub1.DeriveSecret(ss[:], &pub2, &prv1)
	}
}

func BenchmarkProcessTestVectors(b *testing.B) {
	// This bench won't crash as it's run after all tests are passed
	testProcessTestVectors(nil)
}
