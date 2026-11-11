package tls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// HPKE identifiers (RFC 9180) for the test ECH config.
const (
	testHPKEKEMX25519     = 0x0020 // DHKEM(X25519, HKDF-SHA256)
	testHPKEKDFSHA256     = 0x0001 // HKDF-SHA256
	testHPKEAEADAES128GCM = 0x0001 // AES-128-GCM
	testHPKEAEADChaCha20  = 0x0003 // ChaCha20Poly1305
)

// testECHConfigList returns an ECHConfigList with a single X25519 config.
func testECHConfigList(t *testing.T, publicName string) []byte {
	t.Helper()
	echKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		builder.AddUint16(extensionEncryptedClientHello)
		builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddUint8(1)
			builder.AddUint16(testHPKEKEMX25519)
			builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
				builder.AddBytes(echKey.PublicKey().Bytes())
			})
			builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
				for _, aeadID := range []uint16{testHPKEAEADAES128GCM, testHPKEAEADChaCha20} {
					builder.AddUint16(testHPKEKDFSHA256)
					builder.AddUint16(aeadID)
				}
			})
			builder.AddUint8(32)
			builder.AddUint8LengthPrefixed(func(builder *cryptobyte.Builder) {
				builder.AddBytes([]byte(publicName))
			})
			builder.AddUint16(0)
		})
	})
	return builder.BytesOrPanic()
}

// A ClientHelloSpec that cannot carry ECH (no ECH extension) must fail the
// handshake on the client before anything is written, instead of silently
// sending an outer ClientHello without a sealed inner one.
func TestUConnECHSpecBuildErrorIsReturned(t *testing.T) {
	const secretName = "secret.example"

	config := &Config{
		ServerName:                     secretName,
		MinVersion:                     VersionTLS13,
		EncryptedClientHelloConfigList: testECHConfigList(t, "public.example"),
	}
	spec := &ClientHelloSpec{
		CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
		CompressionMethods: []byte{compressionNone},
		Extensions: []TLSExtension{
			&SNIExtension{},
			&SupportedCurvesExtension{[]CurveID{X25519}},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{ECDSAWithP256AndSHA256}},
			&KeyShareExtension{[]KeyShare{{Group: X25519}}},
			&SupportedVersionsExtension{[]uint16{VersionTLS13}},
			// No EncryptedClientHelloExtension.
		},
	}

	c, s := net.Pipe()
	defer s.Close()

	received := make(chan []byte, 1)
	go func() {
		var buf bytes.Buffer
		s.SetReadDeadline(time.Now().Add(2 * time.Second))
		io.Copy(&buf, s)
		received <- buf.Bytes()
	}()

	c.SetDeadline(time.Now().Add(3 * time.Second))
	uconn := UClient(c, config, HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		t.Fatalf("ApplyPreset: %v", err)
	}
	err := uconn.Handshake()
	c.Close()
	if err == nil {
		t.Fatal("handshake succeeded without an ECH extension in the spec")
	}

	if wire := <-received; len(wire) != 0 {
		t.Fatalf("client wrote %d bytes after a failed ClientHello build", len(wire))
	}
}
