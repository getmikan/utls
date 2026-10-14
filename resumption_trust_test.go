// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

// Regression tests for GO-2026-4337, ported from Go's crypto/tls: resumption
// must re-check the stored verified chains against the current trust policy.

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestHandshakeChainExpiryResumption(t *testing.T) {
	t.Run("TLS1.2", func(t *testing.T) {
		testHandshakeChainExpiryResumption(t, VersionTLS12)
	})
	t.Run("TLS1.3", func(t *testing.T) {
		testHandshakeChainExpiryResumption(t, VersionTLS13)
	})
}

func testHandshakeChainExpiryResumption(t *testing.T, version uint16) {
	now := time.Now()

	createChain := func(leafNotAfter, rootNotAfter time.Time) (leafDER, expiredLeafDER []byte, root *x509.Certificate) {
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "root"},
			NotBefore:             rootNotAfter.Add(-time.Hour * 24),
			NotAfter:              rootNotAfter,
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		rootDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &testECDSAPrivateKey.PublicKey, testECDSAPrivateKey)
		if err != nil {
			t.Fatalf("CreateCertificate: %v", err)
		}
		root, err = x509.ParseCertificate(rootDER)
		if err != nil {
			t.Fatalf("ParseCertificate: %v", err)
		}

		tmpl = &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{},
			DNSNames:     []string{"expired-resume.example.com"},
			NotBefore:    leafNotAfter.Add(-time.Hour * 24),
			NotAfter:     leafNotAfter,
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		leafCertDER, err := x509.CreateCertificate(rand.Reader, tmpl, root, &testECDSAPrivateKey.PublicKey, testECDSAPrivateKey)
		if err != nil {
			t.Fatalf("CreateCertificate: %v", err)
		}
		tmpl.NotBefore, tmpl.NotAfter = leafNotAfter.Add(-time.Hour*24*365), leafNotAfter.Add(-time.Hour*24*364)
		expiredLeafDERCertDER, err := x509.CreateCertificate(rand.Reader, tmpl, root, &testECDSAPrivateKey.PublicKey, testECDSAPrivateKey)
		if err != nil {
			t.Fatalf("CreateCertificate: %v", err)
		}

		return leafCertDER, expiredLeafDERCertDER, root
	}
	testExpiration := func(name string, leafNotAfter, rootNotAfter time.Time) {
		t.Run(name, func(t *testing.T) {
			initialLeafDER, expiredLeafDER, initialRoot := createChain(leafNotAfter, rootNotAfter)

			serverConfig := testConfig.Clone()
			serverConfig.MaxVersion = version
			serverConfig.Certificates = []Certificate{{
				Certificate: [][]byte{initialLeafDER, expiredLeafDER},
				PrivateKey:  testECDSAPrivateKey,
			}}
			serverConfig.ClientCAs = x509.NewCertPool()
			serverConfig.ClientCAs.AddCert(initialRoot)
			serverConfig.ClientAuth = RequireAndVerifyClientCert
			serverConfig.Time = func() time.Time {
				return now
			}
			serverConfig.InsecureSkipVerify = false
			serverConfig.ServerName = "expired-resume.example.com"

			clientConfig := testConfig.Clone()
			clientConfig.MaxVersion = version
			clientConfig.Certificates = []Certificate{{
				Certificate: [][]byte{initialLeafDER, expiredLeafDER},
				PrivateKey:  testECDSAPrivateKey,
			}}
			clientConfig.RootCAs = x509.NewCertPool()
			clientConfig.RootCAs.AddCert(initialRoot)
			clientConfig.ServerName = "expired-resume.example.com"
			clientConfig.ClientSessionCache = NewLRUClientSessionCache(32)
			clientConfig.InsecureSkipVerify = false
			clientConfig.ServerName = "expired-resume.example.com"
			clientConfig.Time = func() time.Time {
				return now
			}

			testResume := func(t *testing.T, sc, cc *Config, expectResume bool) {
				t.Helper()
				ss, cs, err := testHandshake(t, cc, sc)
				if err != nil {
					t.Fatalf("handshake: %v", err)
				}
				if cs.DidResume != expectResume {
					t.Fatalf("DidResume = %v; want %v", cs.DidResume, expectResume)
				}
				if ss.DidResume != expectResume {
					t.Fatalf("DidResume = %v; want %v", cs.DidResume, expectResume)
				}
			}

			testResume(t, serverConfig, clientConfig, false)
			testResume(t, serverConfig, clientConfig, true)

			expiredNow := earliest(leafNotAfter, rootNotAfter).Add(time.Minute)

			freshLeafDER, expiredLeafDER, freshRoot := createChain(expiredNow.Add(time.Hour), expiredNow.Add(time.Hour))
			clientConfig.Certificates = []Certificate{{
				Certificate: [][]byte{freshLeafDER, expiredLeafDER},
				PrivateKey:  testECDSAPrivateKey,
			}}
			serverConfig.Time = func() time.Time {
				return expiredNow
			}
			serverConfig.ClientCAs = x509.NewCertPool()
			serverConfig.ClientCAs.AddCert(freshRoot)

			testResume(t, serverConfig, clientConfig, false)
		})
	}

	testExpiration("LeafExpiresBeforeRoot", now.Add(2*time.Hour), now.Add(3*time.Hour))
	testExpiration("LeafExpiresAfterRoot", now.Add(2*time.Hour), now.Add(time.Hour))
}

func TestHandshakeGetConfigForClientDifferentClientCAs(t *testing.T) {
	t.Run("TLS1.2", func(t *testing.T) {
		testHandshakeGetConfigForClientDifferentClientCAs(t, VersionTLS12)
	})
	t.Run("TLS1.3", func(t *testing.T) {
		testHandshakeGetConfigForClientDifferentClientCAs(t, VersionTLS13)
	})
}

func testHandshakeGetConfigForClientDifferentClientCAs(t *testing.T, version uint16) {
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "root"},
		NotBefore:             now.Add(-time.Hour * 24),
		NotAfter:              now.Add(time.Hour * 24),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &testECDSAPrivateKey.PublicKey, testECDSAPrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	rootA, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	rootDER, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &testRSA2048PrivateKey.PublicKey, testRSA2048PrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	rootB, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	tmpl = &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{},
		DNSNames:     []string{"example.com"},
		NotBefore:    now.Add(-time.Hour * 24),
		NotAfter:     now.Add(time.Hour * 24),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certA, err := x509.CreateCertificate(rand.Reader, tmpl, rootA, &testECDSAPrivateKey.PublicKey, testECDSAPrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certB, err := x509.CreateCertificate(rand.Reader, tmpl, rootB, &testECDSAPrivateKey.PublicKey, testRSA2048PrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	serverConfig := testConfig.Clone()
	serverConfig.MaxVersion = version
	serverConfig.Certificates = []Certificate{{
		Certificate: [][]byte{certA},
		PrivateKey:  testECDSAPrivateKey,
	}}
	serverConfig.Time = func() time.Time {
		return now
	}
	serverConfig.ClientCAs = x509.NewCertPool()
	serverConfig.ClientCAs.AddCert(rootA)
	serverConfig.ClientAuth = RequireAndVerifyClientCert
	switchConfig := false
	serverConfig.GetConfigForClient = func(clientHello *ClientHelloInfo) (*Config, error) {
		if !switchConfig {
			return nil, nil
		}
		cfg := serverConfig.Clone()
		cfg.ClientCAs = x509.NewCertPool()
		cfg.ClientCAs.AddCert(rootB)
		return cfg, nil
	}
	serverConfig.InsecureSkipVerify = false
	serverConfig.ServerName = "example.com"

	clientConfig := testConfig.Clone()
	clientConfig.MaxVersion = version
	clientConfig.Certificates = []Certificate{{
		Certificate: [][]byte{certA},
		PrivateKey:  testECDSAPrivateKey,
	}}
	clientConfig.ClientSessionCache = NewLRUClientSessionCache(32)
	clientConfig.RootCAs = x509.NewCertPool()
	clientConfig.RootCAs.AddCert(rootA)
	clientConfig.Time = func() time.Time {
		return now
	}
	clientConfig.InsecureSkipVerify = false
	clientConfig.ServerName = "example.com"

	testResume := func(t *testing.T, sc, cc *Config, expectResume bool) {
		t.Helper()
		ss, cs, err := testHandshake(t, cc, sc)
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
		if cs.DidResume != expectResume {
			t.Fatalf("DidResume = %v; want %v", cs.DidResume, expectResume)
		}
		if ss.DidResume != expectResume {
			t.Fatalf("DidResume = %v; want %v", cs.DidResume, expectResume)
		}
	}

	testResume(t, serverConfig, clientConfig, false)
	testResume(t, serverConfig, clientConfig, true)

	clientConfig.Certificates[0].Certificate = [][]byte{certB}

	// Cause GetConfigForClient to return a config cloned from the base config,
	// but with a different ClientCAs pool. This should cause resumption to fail.
	switchConfig = true

	testResume(t, serverConfig, clientConfig, false)
	testResume(t, serverConfig, clientConfig, true)
}

func TestHandshakeChangeRootCAsResumption(t *testing.T) {
	t.Run("TLS1.2", func(t *testing.T) {
		testHandshakeChangeRootCAsResumption(t, VersionTLS12)
	})
	t.Run("TLS1.3", func(t *testing.T) {
		testHandshakeChangeRootCAsResumption(t, VersionTLS13)
	})
}

func testHandshakeChangeRootCAsResumption(t *testing.T, version uint16) {
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "root"},
		NotBefore:             now.Add(-time.Hour * 24),
		NotAfter:              now.Add(time.Hour * 24),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &testECDSAPrivateKey.PublicKey, testECDSAPrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	rootA, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	rootDER, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &testRSA2048PrivateKey.PublicKey, testRSA2048PrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	rootB, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	tmpl = &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{},
		DNSNames:     []string{"example.com"},
		NotBefore:    now.Add(-time.Hour * 24),
		NotAfter:     now.Add(time.Hour * 24),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certA, err := x509.CreateCertificate(rand.Reader, tmpl, rootA, &testECDSAPrivateKey.PublicKey, testECDSAPrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certB, err := x509.CreateCertificate(rand.Reader, tmpl, rootB, &testECDSAPrivateKey.PublicKey, testRSA2048PrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	serverConfig := testConfig.Clone()
	serverConfig.MaxVersion = version
	serverConfig.Certificates = []Certificate{{
		Certificate: [][]byte{certA},
		PrivateKey:  testECDSAPrivateKey,
	}}
	serverConfig.Time = func() time.Time {
		return now
	}
	serverConfig.ClientCAs = x509.NewCertPool()
	serverConfig.ClientCAs.AddCert(rootA)
	serverConfig.ClientAuth = RequireAndVerifyClientCert
	serverConfig.InsecureSkipVerify = false
	serverConfig.ServerName = "example.com"

	clientConfig := testConfig.Clone()
	clientConfig.MaxVersion = version
	clientConfig.Certificates = []Certificate{{
		Certificate: [][]byte{certA},
		PrivateKey:  testECDSAPrivateKey,
	}}
	clientConfig.ClientSessionCache = NewLRUClientSessionCache(32)
	clientConfig.RootCAs = x509.NewCertPool()
	clientConfig.RootCAs.AddCert(rootA)
	clientConfig.Time = func() time.Time {
		return now
	}
	clientConfig.InsecureSkipVerify = false
	clientConfig.ServerName = "example.com"

	testResume := func(t *testing.T, sc, cc *Config, expectResume bool) {
		t.Helper()
		ss, cs, err := testHandshake(t, cc, sc)
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
		if cs.DidResume != expectResume {
			t.Fatalf("DidResume = %v; want %v", cs.DidResume, expectResume)
		}
		if ss.DidResume != expectResume {
			t.Fatalf("DidResume = %v; want %v", cs.DidResume, expectResume)
		}
	}

	testResume(t, serverConfig, clientConfig, false)
	testResume(t, serverConfig, clientConfig, true)

	clientConfig = clientConfig.Clone()
	clientConfig.RootCAs = x509.NewCertPool()
	clientConfig.RootCAs.AddCert(rootB)

	serverConfig.Certificates[0].Certificate = [][]byte{certB}

	testResume(t, serverConfig, clientConfig, false)
	testResume(t, serverConfig, clientConfig, true)
}

func earliest(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
