package tls

// REALITY server: optional ML-DSA-65 signature of the temporary certificate
// (Xray "mldsa65Seed" / "mldsa65Verify", XTLS/REALITY@4eaf792).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"

	"github.com/metacubex/mldsa"
)

// RealityMldsa65SeedSize is the size of RealityConfig.Mldsa65Seed.
const RealityMldsa65SeedSize = mldsa.PrivateKeySize

type realityMldsa65Key struct {
	seed []byte
	key  *mldsa.PrivateKey
}

func newRealityMldsa65Key(seed []byte) (*mldsa.PrivateKey, error) {
	if len(seed) != RealityMldsa65SeedSize {
		return nil, errors.New("REALITY: ML-DSA-65 seed must be 32 bytes")
	}
	return mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
}

// mldsa65Key returns the ML-DSA-65 private key for Mldsa65Seed, or nil when no
// seed is configured. The expanded key is cached.
func (a *RealityConfig) mldsa65Key() (*mldsa.PrivateKey, error) {
	if len(a.Mldsa65Seed) == 0 {
		return nil, nil
	}
	if k := a.mldsa65.Load(); k != nil && bytes.Equal(k.seed, a.Mldsa65Seed) {
		return k.key, nil
	}
	key, err := newRealityMldsa65Key(a.Mldsa65Seed)
	if err != nil {
		return nil, err
	}
	a.mldsa65.Store(&realityMldsa65Key{seed: append([]byte(nil), a.Mldsa65Seed...), key: key})
	return key, nil
}

// RealityMldsa65Verify returns the ML-DSA-65 public key for seed, the value
// REALITY clients take as "mldsa65Verify". The key is identical to the one
// Xray derives with circl's mldsa65.NewKeyFromSeed.
func RealityMldsa65Verify(seed []byte) ([]byte, error) {
	key, err := newRealityMldsa65Key(seed)
	if err != nil {
		return nil, err
	}
	return key.PublicKey().Bytes(), nil
}

// realityServerCertMldsa65 is the temporary certificate with room for an
// ML-DSA-65 signature: its first extension (OID 0.0) holds a zeroed value of
// the signature size, which is overwritten per connection. offset is the
// position of that value in the DER encoding.
var realityServerCertMldsa65 = onceValues(func() (signedCert []byte, offset int) {
	ed25519Priv, _ := realityServerCert()
	placeholder := make([]byte, mldsa.MLDSA65SignatureSize)
	certificate := x509.Certificate{
		SerialNumber:    &big.Int{},
		ExtraExtensions: []pkix.Extension{{Id: []int{0, 0}, Value: placeholder}},
	}
	signedCert, err := x509.CreateCertificate(rand.Reader, &certificate, &certificate, ed25519.PublicKey(ed25519Priv[32:]), ed25519Priv)
	if err != nil {
		panic("REALITY: ML-DSA-65 certificate: " + err.Error())
	}
	// The value is an OCTET STRING of MLDSA65SignatureSize (0x0ced) bytes.
	size := len(placeholder)
	header := []byte{0x04, 0x82, byte(size >> 8), byte(size)}
	offset = bytes.Index(signedCert, append(header, placeholder...))
	if offset < 0 {
		panic("REALITY: ML-DSA-65 certificate: extension not found")
	}
	return signedCert, offset + len(header)
})
