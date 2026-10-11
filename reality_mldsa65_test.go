package tls

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/metacubex/mldsa"
)

// Vectors generated with github.com/cloudflare/circl v1.6.5, the library Xray
// uses: mldsa65.NewKeyFromSeed(seed) for the key pair, and
// mldsa65.SignTo(key, msg, nil, false, sig) (Xray's REALITY server call) for
// the signature of realityMldsa65TestMessage. Values are SHA-256 digests of
// the public key encoding and of the signature.
var realityMldsa65TestVectors = []struct {
	seed, pub, sig string
}{
	{
		seed: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		pub:  "085ba380ff386dd52e42349c6eb88489d6058ea541a4e3fb0dce9a3fd1f7a911",
		sig:  "4d77d702f9fb2f7ef7820cbf2337babd60fd818edac29381bdf22d7f3250c687",
	},
	{
		seed: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
		pub:  "d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9",
		sig:  "6dba3e963b1daa5ce881cb01246b543fe97eb209a4d8642b8e07b76a271b7841",
	},
	{
		seed: "__jx6uPc1c7HwLmyq6Sdlo-IgXpzbGVeV1BJQjs0LSY",
		pub:  "974764eec574cb14359ba6f2fee2439f5845d440a3c0c8f8d3e6eb7daac864c2",
		sig:  "ca37ee7ae41836483883c777f91752d19a7c55c493ccc78e65eaf1da76c4919e",
	},
}

var realityMldsa65TestMessage = []byte("REALITY ML-DSA-65 test message")

func TestRealityMldsa65MatchesCircl(t *testing.T) {
	for _, v := range realityMldsa65TestVectors {
		seed, err := base64.RawURLEncoding.DecodeString(v.seed)
		if err != nil {
			t.Fatal(err)
		}
		verify, err := RealityMldsa65Verify(seed)
		if err != nil {
			t.Fatal(err)
		}
		if len(verify) != mldsa.MLDSA65PublicKeySize {
			t.Fatalf("public key size %d", len(verify))
		}
		if got := sha256.Sum256(verify); hex.EncodeToString(got[:]) != v.pub {
			t.Errorf("seed %s: public key digest %x, want %s", v.seed, got, v.pub)
		}

		config := &RealityConfig{Mldsa65Seed: seed}
		key, err := config.mldsa65Key()
		if err != nil {
			t.Fatal(err)
		}
		sig, err := key.SignDeterministic(realityMldsa65TestMessage, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := sha256.Sum256(sig); hex.EncodeToString(got[:]) != v.sig {
			t.Errorf("seed %s: signature digest %x, want %s", v.seed, got, v.sig)
		}
		if again, _ := config.mldsa65Key(); again != key {
			t.Error("expanded key is not cached")
		}
	}
}

func TestRealityMldsa65BadSeed(t *testing.T) {
	if _, err := RealityMldsa65Verify(make([]byte, 31)); err == nil {
		t.Fatal("31-byte seed accepted")
	}
	config := &RealityConfig{Mldsa65Seed: make([]byte, 64)}
	if _, err := config.mldsa65Key(); err == nil {
		t.Fatal("64-byte seed accepted")
	}
	if key, err := (&RealityConfig{}).mldsa65Key(); key != nil || err != nil {
		t.Fatalf("no seed: key=%v err=%v", key, err)
	}
}

func TestRealityServerCertMldsa65Layout(t *testing.T) {
	signedCert, offset := realityServerCertMldsa65()
	if offset != 126 { // the fixed location used by XTLS/REALITY
		t.Errorf("signature offset %d, want 126", offset)
	}
	cert := append([]byte(nil), signedCert...)
	marker := bytes.Repeat([]byte{0xa5}, mldsa.MLDSA65SignatureSize)
	copy(cert[offset:], marker)
	parsed, err := x509.ParseCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Extensions) == 0 || !parsed.Extensions[0].Id.Equal([]int{0, 0}) || !bytes.Equal(parsed.Extensions[0].Value, marker) {
		t.Fatalf("Extensions[0] does not hold the signature slot: %+v", parsed.Extensions)
	}
	ed25519Priv, plain := realityServerCert()
	if !ed25519Priv.Public().(ed25519.PublicKey).Equal(parsed.PublicKey) {
		t.Fatal("certificates use different keys")
	}
	if len(plain) >= len(signedCert) {
		t.Fatal("plain certificate is not smaller")
	}
}

// realityTestVerifyMldsa65 is the certificate check of Xray's REALITY client
// (transport/internet/reality.UConn.VerifyPeerCertificate) with
// mldsa65Verify set.
func realityTestVerifyMldsa65(t *testing.T, uconn *UConn, authKey, mldsa65Verify []byte) bool {
	t.Helper()
	if !realityTestIsReality(t, uconn, authKey) {
		return false
	}
	certs := uconn.ConnectionState().PeerCertificates
	if len(certs[0].Extensions) == 0 {
		return false
	}
	h := hmac.New(sha512.New, authKey)
	h.Write(certs[0].PublicKey.(ed25519.PublicKey))
	h.Write(uconn.HandshakeState.Hello.Raw)
	h.Write(uconn.HandshakeState.ServerHello.Raw)
	verify, err := mldsa.NewPublicKey(mldsa.MLDSA65(), mldsa65Verify)
	if err != nil {
		t.Fatal(err)
	}
	return mldsa.Verify(verify, h.Sum(nil), certs[0].Extensions[0].Value, nil) == nil
}

func TestRealityMldsa65Handshake(t *testing.T) {
	tt := realityTestBigTarget(t, 6000)
	config, pub := newRealityTestConfig(t, tt.addr())
	seed, _ := base64.RawURLEncoding.DecodeString(realityMldsa65TestVectors[2].seed)
	config.Mldsa65Seed = seed
	verify, err := RealityMldsa65Verify(seed)
	if err != nil {
		t.Fatal(err)
	}
	otherVerify, _ := RealityMldsa65Verify(make([]byte, 32))
	addr := newRealityTestServer(t, config)

	// (A ClientHello with only X25519MLKEM768 is covered by
	// TestRealityClientPeerPub: the uTLS client requires an X25519 key share.)
	for _, groups := range [][]CurveID{{X25519}, {X25519MLKEM768, X25519}} {
		uconn, authKey := realityTestDialShares(t, addr, pub, groups)
		if !realityTestIsReality(t, uconn, authKey) {
			t.Fatalf("%v: REALITY certificate not recognised", groups)
		}
		if !realityTestVerifyMldsa65(t, uconn, authKey, verify) {
			t.Fatalf("%v: ML-DSA-65 signature rejected", groups)
		}
		if realityTestVerifyMldsa65(t, uconn, authKey, otherVerify) {
			t.Fatalf("%v: ML-DSA-65 signature accepted for a different key", groups)
		}
		realityTestReadMarker(t, uconn)
		uconn.Close()
	}
}

func TestRealityWithoutMldsa65(t *testing.T) {
	tt := realityTestBigTarget(t, 6000)
	config, pub := newRealityTestConfig(t, tt.addr())
	addr := newRealityTestServer(t, config)
	verify, _ := RealityMldsa65Verify(make([]byte, 32))

	uconn, authKey := realityTestDialShares(t, addr, pub, []CurveID{X25519})
	if !realityTestIsReality(t, uconn, authKey) {
		t.Fatal("REALITY certificate not recognised")
	}
	if realityTestVerifyMldsa65(t, uconn, authKey, verify) {
		t.Fatal("client requiring ML-DSA-65 accepted a server without it")
	}
	realityTestReadMarker(t, uconn)
}
