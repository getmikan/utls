package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"
)

// realityTestBigTarget is a target whose certificate chain holds at least
// chainSize bytes of parseable certificates, so its Certificate record can
// hide the REALITY temporary certificate (or fill whole TLS records).
func realityTestBigTarget(t *testing.T, chainSize int) *realityTestTarget {
	config := realityTestTargetConfig(nil, false)
	config.NameToCertificate = nil
	config.CurvePreferences = nil // defaults, X25519MLKEM768 first
	chain := [][]byte{testRSACertificate}
	for size := len(testRSACertificate); size < chainSize; size += len(testRSACertificate) {
		chain = append(chain, testRSACertificate)
	}
	config.Certificates = []Certificate{{Certificate: chain, PrivateKey: testRSAPrivateKey}}
	return newRealityTestTarget(t, config, nil, false)
}

// realityTestDialShares performs a REALITY client handshake offering the given
// key share groups and returns the connection and the auth key.
func realityTestDialShares(t *testing.T, addr string, pub *ecdh.PublicKey, groups []CurveID) (uconn *UConn, authKey []byte) {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	uconn = UClient(raw, &Config{
		ServerName:             realityTestServerName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	}, HelloCustom)
	spec := realityProbeClientHelloSpec(realityPostHandshakeKey{serverName: realityTestServerName, cipherSuite: TLS_AES_128_GCM_SHA256})
	shares := make([]KeyShare, 0, len(groups))
	for _, g := range groups {
		shares = append(shares, KeyShare{Group: g})
	}
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *KeyShareExtension:
			e.KeyShares = shares
		case *SupportedCurvesExtension:
			e.Curves = groups
		}
	}
	if err := uconn.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}

	hello := uconn.HandshakeState.Hello
	for i := range hello.Raw[39 : 39+32] {
		hello.Raw[39+i] = 0
	}
	binary.BigEndian.PutUint64(hello.SessionId, uint64(time.Now().Unix()))
	copy(hello.SessionId[8:], realityTestShortID[:])
	hello.SessionId[0], hello.SessionId[1], hello.SessionId[2] = 1, 8, 2
	keys := uconn.HandshakeState.State13.KeyShareKeys
	ecdhe := keys.Ecdhe
	if ecdhe == nil {
		ecdhe = keys.MlkemEcdhe
	}
	authKey, err = ecdhe.ECDH(pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey); err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(block)
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := uconn.HandshakeContext(ctx); err != nil {
		t.Fatalf("handshake %v: %v", groups, err)
	}
	return uconn, authKey
}

// realityTestIsReality is the certificate check of Xray's REALITY client
// (transport/internet/reality.UConn.VerifyPeerCertificate) without
// mldsa65Verify: it reports whether the peer is the REALITY server.
func realityTestIsReality(t *testing.T, uconn *UConn, authKey []byte) bool {
	t.Helper()
	certs := uconn.ConnectionState().PeerCertificates
	pub, ok := certs[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return false
	}
	h := hmac.New(sha512.New, authKey)
	h.Write(pub)
	return bytes.Equal(h.Sum(nil), certs[0].Signature)
}

func realityTestReadMarker(t *testing.T, uconn *UConn) {
	t.Helper()
	uconn.SetReadDeadline(time.Now().Add(10 * time.Second))
	got := make([]byte, len(realityTestMarker))
	if _, err := io.ReadFull(uconn, got); err != nil {
		t.Fatalf("reading marker: %v", err)
	}
	if !bytes.Equal(got, realityTestMarker) {
		t.Fatalf("marker = %q", got)
	}
}

// A target whose Certificate message fills a whole TLS 1.3 record (16384
// bytes of plaintext, 16406 bytes on the wire) must still be mirrored; with a
// 16 KiB buffer the REALITY server rejected it as too long (XTLS/REALITY#33).
func TestRealityFullSizeTargetRecord(t *testing.T) {
	tt := realityTestBigTarget(t, 17000)

	direct, _, _ := realityTestDial(t, tt.addr(), nil, nil, realityTestSuites)
	direct.Close()

	realityConfig, pub := newRealityTestConfig(t, tt.addr())
	addr := newRealityTestServer(t, realityConfig)
	uconn, authKey := realityTestDialShares(t, addr, pub, []CurveID{X25519})
	if !realityTestIsReality(t, uconn, authKey) {
		t.Fatal("REALITY certificate not recognised")
	}
	realityTestReadMarker(t, uconn)
}
