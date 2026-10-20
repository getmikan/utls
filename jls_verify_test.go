package tls

import (
	"bytes"
	"crypto/x509"
	"errors"
	"testing"
)

func TestJLSAuthenticationStillRunsCertificateCallbacks(t *testing.T) {
	for _, reject := range []string{"", "peer", "connection"} {
		t.Run(reject, func(t *testing.T) {
			refusal := errors.New("application refused JLS peer")
			var calls []string
			config := &Config{
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(raw [][]byte, chains [][]*x509.Certificate) error {
					calls = append(calls, "peer")
					if len(raw) != 1 || !bytes.Equal(raw[0], testRSACertificate) {
						t.Fatal("callback received wrong certificate")
					}
					if reject == "peer" {
						return refusal
					}
					return nil
				},
				VerifyConnection: func(state ConnectionState) error {
					calls = append(calls, "connection")
					if len(state.PeerCertificates) != 1 {
						t.Fatal("connection state lacks peer certificate")
					}
					if reject == "connection" {
						return refusal
					}
					return nil
				},
			}
			conn := Client(&bytesConn{Reader: bytes.NewReader(nil)}, config)
			conn.jlsState = jlsStateAuthSuccess
			err := conn.verifyServerCertificate([][]byte{testRSACertificate})
			if reject == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, refusal) {
				t.Fatalf("application verifier bypassed: %v", err)
			}
			want := 2
			if reject == "peer" {
				want = 1
			}
			if len(calls) != want || calls[0] != "peer" {
				t.Fatalf("callback sequence %v", calls)
			}
		})
	}
}
