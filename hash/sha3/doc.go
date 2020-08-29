// Copyright 2020 Kris Kwiatkowski. All rights reserved.
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sha3 implements the Keccak-p[1600, 24] permuation.
// The 1600 stands for width of the permutation - number of
// bits that are permuted at a time, and 24 stands for number
// of rounds (iterations) of the permuation.
// Package implementds derivatives of the Keccak permuation,
// like SHA-3 fixed-output-length hash, SHAKE which is an
// extendable-output-functions (XOF) and cSHAKE - a XOF with
// domain separation.
//
// The SHA-3 and SHAKE are documented in FIPS-PUB-202 [1] and
// cSHAKE specification can be found in NIST-SP-800-185 [2].
//
// Implementation was initially based on
// https://godoc.org/golang.org/x/crypto/sha3
package sha3 // import "github.com/henrydcase/nobs/hash/sha3"
