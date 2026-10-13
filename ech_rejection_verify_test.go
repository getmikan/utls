package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"
)

// EncryptedClientHelloRejectionVerify verifies the ECH provider certificate,
// so the ConnectionState it gets must carry the server's certificates.
func TestECHRejectionVerifySeesPeerCertificates(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"public.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	publicCertDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}

	var gotCerts []*x509.Certificate
	called := false

	clientConfig := &Config{
		ServerName:                     "secret.example",
		MinVersion:                     VersionTLS13,
		EncryptedClientHelloConfigList: testECHConfigList(t, "public.example"),
		EncryptedClientHelloRejectionVerify: func(cs ConnectionState) error {
			called = true
			gotCerts = cs.PeerCertificates
			return nil
		},
	}
	// The server has no ECH keys, so it rejects ECH and answers as
	// public.example.
	serverConfig := &Config{
		MinVersion:   VersionTLS13,
		Certificates: []Certificate{{Certificate: [][]byte{publicCertDER}, PrivateKey: k}},
	}

	c, s := localPipe(t)
	done := make(chan error, 1)
	go func() {
		srv := Server(s, serverConfig)
		err := srv.Handshake()
		s.Close()
		done <- err
	}()

	cli := Client(c, clientConfig)
	err = cli.Handshake()
	c.Close()
	<-done

	var echErr *ECHRejectionError
	if !errors.As(err, &echErr) {
		t.Fatalf("Handshake error = %v; want ECHRejectionError", err)
	}
	if !called {
		t.Fatal("EncryptedClientHelloRejectionVerify was not called")
	}
	if len(gotCerts) != 1 || !gotCerts[0].Equal(mustParseCert(t, publicCertDER)) {
		t.Fatalf("EncryptedClientHelloRejectionVerify got %d peer certificates; want the server's one", len(gotCerts))
	}
}

func mustParseCert(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
