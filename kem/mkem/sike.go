package mkem

import (
	"crypto/subtle"
	"errors"
	"io"

	"github.com/henrydcase/nobs/dh/sidh"
	"github.com/henrydcase/nobs/dh/sidh/common"
	"github.com/henrydcase/nobs/hash/sha3"
)

// SIKE KEM interface.
type KEM struct {
	allocated   bool
	rng         io.Reader
	msg         []byte
	secretBytes []byte
	params      *common.SidhParams
	shake       sha3.ShakeHash
}

// SIKE mKEM interface. Used only for testing. I store some variables
// here, to make sure to avoid heap allocations.
type MultiKEM struct {
	KEM
	// stores ephemeral/internal public key
	ct0 [common.MaxPublicKeySz]byte
	// stores list of ciphertexts ct[i]
	cts [][common.MaxMsgBsz]byte
	// stores j-invariant. kept here to avoid heap allocs
	j [common.MaxSharedSecretBsz]byte
}

// Domain separators for MultiKEM
var (
	G1 = []byte{0x01}
	G2 = []byte{0x02}
	G3 = []byte{0x03}
)

// NewSike434 instantiates SIKE/p434 KEM.
func NewSike434(rng io.Reader) *KEM {
	var c KEM
	c.Allocate(sidh.Fp434, rng)
	return &c
}

// NewSike503 instantiates SIKE/p503 KEM.
func NewSike503(rng io.Reader) *KEM {
	var c KEM
	c.Allocate(sidh.Fp503, rng)
	return &c
}

// NewSike751 instantiates SIKE/p751 KEM.
func NewSike751(rng io.Reader) *KEM {
	var c KEM
	c.Allocate(sidh.Fp751, rng)
	return &c
}

// Allocate allocates KEM object for multiple SIKE operations. The rng
// must be cryptographically secure PRNG.
func (c *KEM) Allocate(id uint8, rng io.Reader) {
	c.rng = rng
	c.params = common.Params(id)
	c.msg = make([]byte, c.params.MsgLen)
	c.secretBytes = make([]byte, c.params.A.SecretByteLen)
	c.shake = sha3.NewShake256()
	c.allocated = true
}

// Allocate allocates multi KEM object for multiple SIKE operations. The rng
// must be cryptographically secure PRNG.
func (c *MultiKEM) Allocate(id uint8, recipients_nb uint, rng io.Reader) {
	c.rng = rng
	c.params = common.Params(id)
	c.msg = make([]byte, c.params.MsgLen)
	c.secretBytes = make([]byte, c.params.A.SecretByteLen)
	c.shake = sha3.NewShake256()
	c.allocated = true
	c.cts = make([][common.MaxMsgBsz]byte, recipients_nb)
}

func (c *MultiKEM) NewPrivateKey() *sidh.PrivateKey {
	return sidh.NewPrivateKey(c.params.ID, sidh.KeyVariantSike)
}

func (c *MultiKEM) NewPublicKey() *sidh.PublicKey {
	return sidh.NewPublicKey(c.params.ID, sidh.KeyVariantSike)
}

func (c *KEM) PublicKeySize() int {
	return c.params.PublicKeySize
}

// Encapsulate receives the public key and generates SIKE ciphertext and shared secret.
// The generated ciphertext is used for authentication.
// Error is returned in case PRNG fails. Function panics in case wrongly formated
// input was provided.
func (c *KEM) Encapsulate(ciphertext, secret []byte, pub *sidh.PublicKey) error {
	if !c.allocated {
		panic("KEM unallocated")
	}

	if sidh.KeyVariantSike != pub.KeyVariant {
		panic("Wrong type of public key")
	}

	if len(secret) < c.SharedSecretSize() {
		panic("shared secret buffer to small")
	}

	if len(ciphertext) < c.CiphertextSize() {
		panic("ciphertext buffer to small")
	}

	// Generate ephemeral value
	_, err := io.ReadFull(c.rng, c.msg[:])
	if err != nil {
		return err
	}

	var buf [3 * common.MaxSharedSecretBsz]byte
	var skA = sidh.PrivateKey{
		Key: sidh.Key{
			Params:     c.params,
			KeyVariant: sidh.KeyVariantSidhA},
		Scalar: c.secretBytes}
	var pkA = sidh.NewPublicKey(c.params.ID, sidh.KeyVariantSidhA)

	pub.Export(buf[:])
	c.shake.Reset()
	_, _ = c.shake.Write(c.msg)
	_, _ = c.shake.Write(buf[:3*c.params.SharedSecretSize])
	_, _ = c.shake.Read(skA.Scalar)

	// Ensure bitlength is not bigger then to 2^e2-1
	skA.Scalar[len(skA.Scalar)-1] &= (1 << (c.params.A.SecretBitLen % 8)) - 1
	skA.GeneratePublicKey(pkA)
	c.generateCiphertext(ciphertext, &skA, pkA, pub, c.msg[:])

	// K = H(msg||(c0||c1))
	c.shake.Reset()
	_, _ = c.shake.Write(c.msg)
	_, _ = c.shake.Write(ciphertext)
	_, _ = c.shake.Read(secret[:c.SharedSecretSize()])
	return nil
}

// Decapsulate given the keypair and ciphertext as inputs, Decapsulate outputs a shared
// secret if plaintext verifies correctly, otherwise function outputs random value.
// Decapsulation may panic in case input is wrongly formated, in particular, size of
// the 'ciphertext' must be exactly equal to c.CiphertextSize().
func (c *KEM) Decapsulate(secret []byte, prv *sidh.PrivateKey, pub *sidh.PublicKey, ciphertext []byte) error {
	if !c.allocated {
		panic("KEM unallocated")
	}

	if sidh.KeyVariantSike != pub.KeyVariant {
		panic("Wrong type of public key")
	}

	if pub.KeyVariant != prv.KeyVariant {
		panic("Public and private key are of different type")
	}

	if len(secret) < c.SharedSecretSize() {
		panic("shared secret buffer to small")
	}

	if len(ciphertext) != c.CiphertextSize() {
		panic("ciphertext buffer to small")
	}

	var m [common.MaxMsgBsz]byte
	var r [common.MaxSidhPrivateKeyBsz]byte
	var pkBytes [3 * common.MaxSharedSecretBsz]byte
	var skA = sidh.PrivateKey{
		Key: sidh.Key{
			Params:     c.params,
			KeyVariant: sidh.KeyVariantSidhA},
		Scalar: c.secretBytes}
	var pkA = sidh.NewPublicKey(c.params.ID, sidh.KeyVariantSidhA)
	c1Len, err := c.decrypt(m[:], prv, ciphertext)
	if err != nil {
		return err
	}

	// r' = G(m'||pub)
	pub.Export(pkBytes[:])
	c.shake.Reset()
	_, _ = c.shake.Write(m[:c1Len])
	_, _ = c.shake.Write(pkBytes[:3*c.params.SharedSecretSize])
	_, _ = c.shake.Read(r[:c.params.A.SecretByteLen])
	// Ensure bitlength is not bigger than 2^e2-1
	r[c.params.A.SecretByteLen-1] &= (1 << (c.params.A.SecretBitLen % 8)) - 1

	err = skA.Import(r[:c.params.A.SecretByteLen])
	if err != nil {
		return err
	}
	skA.GeneratePublicKey(pkA)
	pkA.Export(pkBytes[:])

	// S is chosen at random when generating a key and unknown to other party. It is
	// important that S is unpredictable to the other party.  Without this check, would
	// be possible to recover a secret, by providing series of invalid ciphertexts.
	//
	// See more details in "On the security of supersingular isogeny cryptosystems"
	// (S. Galbraith, et al., 2016, ePrint #859).
	mask := subtle.ConstantTimeCompare(pkBytes[:c.params.PublicKeySize], ciphertext[:pub.Params.PublicKeySize])
	common.Cpick(mask, m[:c1Len], m[:c1Len], prv.S)
	c.shake.Reset()
	_, _ = c.shake.Write(m[:c1Len])
	_, _ = c.shake.Write(ciphertext)
	_, _ = c.shake.Read(secret[:c.SharedSecretSize()])
	return nil
}

// Encapsulate receives the public key and generates single shared secret
// and multiple ciphertexts as described in mKEM paper. The ciphertexts
// are stored in c.cts. Ephemeral public key is stored in ct0.
// Error is returned in case PRNG fails. Function panics in case wrongly formated
// input is provided.
func (c *MultiKEM) Encapsulate(secret []byte, pub []*sidh.PublicKey) error {
	if !c.allocated {
		panic("KEM unallocated")
	}

	if len(secret) < c.SharedSecretSize() {
		panic("shared secret buffer to small")
	}

	// Generate ephemeral value M
	_, err := io.ReadFull(c.rng, c.msg[:])
	if err != nil {
		return err
	}

	var skA = sidh.PrivateKey{
		Key: sidh.Key{
			Params:     c.params,
			KeyVariant: sidh.KeyVariantSidhA},
		Scalar: c.secretBytes}
	var pkA = sidh.NewPublicKey(c.params.ID, sidh.KeyVariantSidhA)

	// mEnc^i
	c.shake.Reset()
	_, _ = c.shake.Write(G1)
	_, _ = c.shake.Write(c.msg[:skA.Params.MsgLen])
	_, _ = c.shake.Read(skA.Scalar)

	// Ensure bitlength is not bigger then to 2^e2-1
	skA.Scalar[len(skA.Scalar)-1] &= (1 << (c.params.A.SecretBitLen % 8)) - 1
	skA.GeneratePublicKey(pkA)

	// pkA -> ct0
	pkA.Export(c.ct0[:])
	for ct_i, pkB := range pub {
		if sidh.KeyVariantSike != pkB.KeyVariant {
			panic("Wrong type of public key")
		}
		skA.DeriveSecret(c.j[:], pkB)
		// H(j)
		c.shake.Reset()
		_, _ = c.shake.Write(G2)
		_, _ = c.shake.Write(c.j[:skA.Params.SharedSecretSize])
		_, _ = c.shake.Read(c.cts[ct_i][:skA.Params.MsgLen])
		for i := 0; i < skA.Params.MsgLen; i++ {
			// ct[i]
			c.cts[ct_i][i] ^= c.msg[i]
		}
	}

	// K = H(msg)
	c.shake.Reset()
	_, _ = c.shake.Write(G3)
	_, _ = c.shake.Write(c.msg)
	_, _ = c.shake.Read(secret[:c.SharedSecretSize()])
	return nil
}

// mKEM Decapsulate - given the keypair and a ciphertext as inputs. Decapsulate outputs
// a shared secret if plaintext verifies correctly, otherwise function outputs random value.
// Decapsulation may panic in case input is wrongly formated, in particular, size of
// the 'ciphertext' must be exactly equal to c.CiphertextSize().
func (c *MultiKEM) Decapsulate(secret []byte, prv *sidh.PrivateKey, pub *sidh.PublicKey, ctext []byte) error {
	var m [common.MaxMsgBsz]byte
	var r [common.MaxPublicKeySz]byte
	var cti [common.MaxMsgBsz]byte

	if !c.allocated {
		panic("KEM unallocated")
	}

	if sidh.KeyVariantSike != pub.KeyVariant {
		panic("Wrong type of public key")
	}

	if pub.KeyVariant != prv.KeyVariant {
		panic("Public and private key are of different type")
	}

	if len(secret) < c.SharedSecretSize() {
		panic("shared secret buffer to small")
	}

	if len(ctext) != c.SharedSecretSize() {
		panic("ciphertext buffer to small")
	}

	//var pkBytes [3 * common.MaxSharedSecretBsz]byte
	var skA = sidh.PrivateKey{
		Key: sidh.Key{
			Params:     c.params,
			KeyVariant: sidh.KeyVariantSidhA},
		Scalar: c.secretBytes}
	var pkA = sidh.NewPublicKey(c.params.ID, sidh.KeyVariantSidhA)
	err := pkA.Import(c.ct0[:c.params.PublicKeySize])
	if err != nil {
		return err
	}
	prv.DeriveSecret(c.j[:], pkA)

	c.shake.Reset()
	_, _ = c.shake.Write(G2)
	_, _ = c.shake.Write(c.j[:prv.Params.SharedSecretSize])
	_, _ = c.shake.Read(m[:prv.Params.MsgLen])
	for i := 0; i < prv.Params.MsgLen; i++ {
		m[i] ^= ctext[i]
	}

	// Re-encrypt
	c.shake.Reset()
	_, _ = c.shake.Write(G1)
	_, _ = c.shake.Write(m[:skA.Params.MsgLen])
	_, _ = c.shake.Read(skA.Scalar)

	// Ensure bitlength is not bigger then to 2^e2-1
	skA.Scalar[len(skA.Scalar)-1] &= (1 << (c.params.A.SecretBitLen % 8)) - 1
	skA.GeneratePublicKey(pkA)
	// ct0' = r
	pkA.Export(r[:c.params.PublicKeySize])

	skA.DeriveSecret(c.j[:], pub)
	c.shake.Reset()
	// H(j)
	_, _ = c.shake.Write(G2)
	_, _ = c.shake.Write(c.j[:skA.Params.SharedSecretSize])
	_, _ = c.shake.Read(cti[:skA.Params.MsgLen])
	for i := 0; i < skA.Params.MsgLen; i++ {
		cti[i] ^= c.msg[i]
	}

	// S is chosen at random when generating a key and unknown to other party. It is
	// important that S is unpredictable to the other party.  Without this check, would
	// be possible to recover a secret, by providing series of invalid ciphertexts.
	//
	// See more details in "On the security of supersingular isogeny cryptosystems"
	// (S. Galbraith, et al., 2016, ePrint #859).
	mask := subtle.ConstantTimeCompare(r[:c.params.PublicKeySize], c.ct0[:c.params.PublicKeySize])
	mask &= subtle.ConstantTimeCompare(ctext[:skA.Params.MsgLen], cti[:skA.Params.MsgLen])
	common.Cpick(mask, m[:c.params.MsgLen], m[:c.params.MsgLen], prv.S)

	c.shake.Reset()
	_, _ = c.shake.Write(G3)
	_, _ = c.shake.Write(m[:c.params.MsgLen])
	_, _ = c.shake.Read(secret[:c.SharedSecretSize()])

	return nil
}

// Resets internal state of KEM. Function should be used
// after Allocate and between subsequent calls to Encapsulate
// and/or Decapsulate.
func (c *KEM) Reset() {
	for i := range c.msg {
		c.msg[i] = 0
	}

	for i := range c.secretBytes {
		c.secretBytes[i] = 0
	}
}

// Returns size of resulting ciphertext.
func (c *KEM) CiphertextSize() int {
	return c.params.CiphertextSize
}

// Returns size of resulting shared secret.
func (c *KEM) SharedSecretSize() int {
	return c.params.KemSize
}

func (c *KEM) KemSize() int {
	return c.params.KemSize
}

func (c *KEM) generateCiphertext(ctext []byte, skA *sidh.PrivateKey, pkA, pkB *sidh.PublicKey, ptext []byte) {
	var n [common.MaxMsgBsz]byte
	var j [common.MaxSharedSecretBsz]byte
	var ptextLen = skA.Params.MsgLen

	skA.DeriveSecret(j[:], pkB)
	c.shake.Reset()
	_, _ = c.shake.Write(j[:skA.Params.SharedSecretSize])
	_, _ = c.shake.Read(n[:ptextLen])
	for i := range ptext {
		n[i] ^= ptext[i]
	}

	pkA.Export(ctext)
	copy(ctext[pkA.Size():], n[:ptextLen])
}

// encrypt uses SIKE public key to encrypt plaintext. Requires cryptographically secure
// PRNG. Returns ciphertext in case encryption succeeds. Returns error in case PRNG fails
// or wrongly formated input was provided.
func (c *KEM) encrypt(ctext []byte, rng io.Reader, pub *sidh.PublicKey, ptext []byte) error {
	var ptextLen = len(ptext)
	// c1 must be security level + 64 bits (see [SIKE] 1.4 and 4.3.3)
	if ptextLen != pub.Params.KemSize {
		return errors.New("unsupported message length")
	}

	skA := sidh.NewPrivateKey(pub.Params.ID, sidh.KeyVariantSidhA)
	pkA := sidh.NewPublicKey(pub.Params.ID, sidh.KeyVariantSidhA)
	err := skA.Generate(rng)
	if err != nil {
		return err
	}

	skA.GeneratePublicKey(pkA)
	c.generateCiphertext(ctext, skA, pkA, pub, ptext)
	return nil
}

// decrypt uses SIKE private key to decrypt ciphertext. Returns plaintext in case
// decryption succeeds or error in case unexptected input was provided.
// Constant time.
func (c *KEM) decrypt(n []byte, prv *sidh.PrivateKey, ctext []byte) (int, error) {
	var c1Len int
	var j [common.MaxSharedSecretBsz]byte
	var pkLen = prv.Params.PublicKeySize

	// ctext is a concatenation of (ciphertext = pubkey_A || c1)
	// it must be security level + 64 bits (see [SIKE] 1.4 and 4.3.3)
	// Lengths has been already checked by Decapsulate()
	c1Len = len(ctext) - pkLen
	c0 := sidh.NewPublicKey(prv.Params.ID, sidh.KeyVariantSidhA)
	err := c0.Import(ctext[:pkLen])
	prv.DeriveSecret(j[:], c0)
	c.shake.Reset()
	_, _ = c.shake.Write(j[:prv.Params.SharedSecretSize])
	_, _ = c.shake.Read(n[:c1Len])
	for i := range n[:c1Len] {
		n[i] ^= ctext[pkLen+i]
	}
	return c1Len, err
}
