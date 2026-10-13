package tls

import (
	"bytes"
	"compress/zlib"
	"net"
	"strings"
	"testing"
)

type certDiscardConn struct{ net.Conn }

func (certDiscardConn) Write(b []byte) (int, error) { return len(b), nil }

func newDecompressTestState() *clientHandshakeStateTLS13 {
	c := &Conn{conn: certDiscardConn{}, isClient: true, config: &Config{}}
	uconn := &UConn{Conn: c, certCompressionAlgs: []CertCompressionAlgo{CertCompressionZlib}}
	return &clientHandshakeStateTLS13{c: c, uconn: uconn}
}

// A compressed certificate whose declared uncompressed length is above the
// limit for certificate messages must be rejected before allocating it.
func TestDecompressCertLengthLimit(t *testing.T) {
	var compressed bytes.Buffer
	w := zlib.NewWriter(&compressed)
	w.Write([]byte{0})
	w.Close()

	hs := newDecompressTestState()
	_, err := hs.decompressCert(utlsCompressedCertificateMsg{
		algorithm:                    uint16(CertCompressionZlib),
		uncompressedLength:           1<<24 - 1,
		compressedCertificateMessage: compressed.Bytes(),
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("decompressCert error = %v; want a length limit error", err)
	}
}

// The decompressed data may arrive in several reads; it must still be accepted.
func TestDecompressCertReadsFully(t *testing.T) {
	certMsg := &certificateMsgTLS13{certificate: Certificate{Certificate: [][]byte{bytes.Repeat([]byte{0x42}, 100000)}}}
	raw, err := certMsg.marshal()
	if err != nil {
		t.Fatal(err)
	}
	body := raw[4:]

	var compressed bytes.Buffer
	w := zlib.NewWriter(&compressed)
	w.Write(body)
	w.Close()

	hs := newDecompressTestState()
	got, err := hs.decompressCert(utlsCompressedCertificateMsg{
		algorithm:                    uint16(CertCompressionZlib),
		uncompressedLength:           uint32(len(body)),
		compressedCertificateMessage: compressed.Bytes(),
	})
	if err != nil {
		t.Fatalf("decompressCert: %v", err)
	}
	if len(got.certificate.Certificate) != 1 || len(got.certificate.Certificate[0]) != 100000 {
		t.Fatal("decompressed certificate does not match")
	}
}
