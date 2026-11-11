package tls

import "testing"

// A server with MinVersion unset must default to TLS 1.2, like crypto/tls
// without the tls10server GODEBUG.
func TestServerDefaultMinVersion(t *testing.T) {
	for _, v := range []uint16{VersionTLS10, VersionTLS11} {
		clientConfig := testConfig.Clone()
		clientConfig.MinVersion = v
		clientConfig.MaxVersion = v

		serverConfig := testConfig.Clone()
		serverConfig.MinVersion = 0
		if _, _, err := testHandshake(t, clientConfig, serverConfig); err == nil {
			t.Errorf("server with MinVersion 0 accepted %s", VersionName(v))
		}

		serverConfig.MinVersion = v
		if _, cs, err := testHandshake(t, clientConfig, serverConfig); err != nil {
			t.Errorf("server with MinVersion %s: %v", VersionName(v), err)
		} else if cs.Version != v {
			t.Errorf("negotiated %s; want %s", VersionName(cs.Version), VersionName(v))
		}
	}

	if got := (&Config{}).supportedVersions(roleServer); got[len(got)-1] != VersionTLS12 {
		t.Errorf("server default minimum = %s; want TLS 1.2", VersionName(got[len(got)-1]))
	}
}
