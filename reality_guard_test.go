package tls

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/utls/internal/ratelimit"
	"golang.org/x/crypto/curve25519"
)

func TestRealitySilentHandshakeTimesOut(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelled), func(t *testing.T) {
			client, server := net.Pipe()
			target, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			config := &RealityConfig{HandshakeTimeout: 30 * time.Millisecond, DialContext: func(context.Context, string, string) (net.Conn, error) { return target, nil }}
			done := make(chan error, 1)
			go func() { _, err := RealityServer(ctx, server, config); done <- err }()
			if cancelled {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("silent peer authenticated")
				}
			case <-time.After(time.Second):
				t.Fatal("handshake did not close")
			}
			for _, c := range []net.Conn{client, peer} {
				c.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := c.Read(make([]byte, 1)); err != io.EOF {
					t.Fatalf("socket retained after handshake: %v", err)
				}
			}
		})
	}
}

func TestRealityFallbackOutlivesHandshakeTimeout(t *testing.T) {
	client, server := net.Pipe()
	notifier := &realityHandshakeNotifier{Conn: server}
	target, peer := net.Pipe()
	done := make(chan struct{})
	config := &RealityConfig{HandshakeTimeout: 100 * time.Millisecond, DialContext: func(context.Context, string, string) (net.Conn, error) { return target, nil }}
	go func() { defer close(done); RealityServer(context.Background(), notifier, config) }()
	defer func() { client.Close(); peer.Close(); <-done }()
	go func() {
		defer peer.Close()
		for n := 0; n < 2; n++ {
			var data [5]byte
			if _, err := io.ReadFull(peer, data[:]); err != nil {
				return
			}
			if _, err := peer.Write(data[:]); err != nil {
				return
			}
		}
	}()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	for n := 0; n < 2; n++ {
		if n == 1 {
			time.Sleep(200 * time.Millisecond)
		}
		if _, err := client.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		var data [5]byte
		if _, err := io.ReadFull(client, data[:]); err != nil {
			t.Fatal(err)
		}
		if string(data[:]) != "hello" {
			t.Fatal("fallback changed bytes")
		}
		if notifier.calls.Load() != 1 {
			t.Fatal("fallback did not release the hosting listener's handshake guard exactly once")
		}
	}
}

type realityHandshakeNotifier struct {
	net.Conn
	calls atomic.Int32
}

func (c *realityHandshakeNotifier) HandshakeComplete() { c.calls.Add(1) }

func TestRealityMirrorHonorsReadDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	x, y := net.Pipe()
	defer x.Close()
	defer y.Close()
	m := &realityMirrorConn{Mutex: new(sync.Mutex), Conn: a, Target: x}
	if err := m.SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	m.Lock()
	_, err := m.Read(make([]byte, 1))
	m.Unlock()
	if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("expected timeout, got %v", err)
	}
}

func TestRealityFallbackFreeThresholdIsExact(t *testing.T) {
	raw := &bytesConn{Reader: bytes.NewReader(bytes.Repeat([]byte{'x'}, 32))}
	c := &rateLimitedConn{Conn: raw, After: 3, Bucket: ratelimit.NewBucketWithRate(1e9, 32)}
	buffer := make([]byte, 32)
	if n, err := c.Read(buffer); n != 3 || err != nil {
		t.Fatalf("free read crossed threshold: %d, %v", n, err)
	}
	if c.After != 0 {
		t.Fatal("invalid remaining free budget")
	}
	if n, err := c.Read(buffer); n != 29 || err != nil {
		t.Fatalf("limited read: %d, %v", n, err)
	}
}

type bytesConn struct{ *bytes.Reader }

func (*bytesConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*bytesConn) Close() error                     { return nil }
func (*bytesConn) LocalAddr() net.Addr              { return nil }
func (*bytesConn) RemoteAddr() net.Addr             { return nil }
func (*bytesConn) SetDeadline(time.Time) error      { return nil }
func (*bytesConn) SetReadDeadline(time.Time) error  { return nil }
func (*bytesConn) SetWriteDeadline(time.Time) error { return nil }

func TestRealityPrivateKeyCacheFollowsCloneAndRotation(t *testing.T) {
	c := &RealityConfig{PrivateKey: bytes.Repeat([]byte{1}, 32)}
	first, err := c.realityPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	clone := c.Clone()
	again, err := clone.realityPrivateKey()
	if err != nil || again != first {
		t.Fatal("clone did not share cached key")
	}
	clone.PrivateKey = bytes.Repeat([]byte{2}, 32)
	rotated, err := clone.realityPrivateKey()
	if err != nil || rotated == first {
		t.Fatal("rotated clone retained old key")
	}
	if !bytes.Equal(rotated.Bytes(), clone.PrivateKey) {
		t.Fatal("wrong private key after rotation")
	}
	if original, _ := c.realityPrivateKey(); original != first {
		t.Fatal("rotation changed original config")
	}
}

func TestRealityLogsOmitAuthenticationMaterial(t *testing.T) {
	target := realityTestBigTarget(t, 8000)
	config, pub := newRealityTestConfig(t, target.addr())
	var mu sync.Mutex
	var output strings.Builder
	config.Log = func(format string, args ...any) { mu.Lock(); defer mu.Unlock(); fmt.Fprintf(&output, format, args...) }
	addr := newRealityTestServer(t, config)
	conn, _ := realityTestDialShares(t, addr, pub, []CurveID{X25519MLKEM768, X25519})
	defer conn.Close()
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(output.String(), "AuthKey") || strings.Contains(output.String(), "ClientShortId") {
		t.Fatal("authentication material logged")
	}
}

func BenchmarkRealityECDH(b *testing.B) {
	c := &RealityConfig{PrivateKey: bytes.Repeat([]byte{1}, 32)}
	key, _ := c.realityPrivateKey()
	peerBytes := key.PublicKey().Bytes()
	b.Run("uncached", func(b *testing.B) {
		b.ReportAllocs()
		for n := 0; n < b.N; n++ {
			if _, err := curve25519.X25519(c.PrivateKey, peerBytes); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("cached", func(b *testing.B) {
		b.ReportAllocs()
		for n := 0; n < b.N; n++ {
			k, _ := c.realityPrivateKey()
			peer, err := ecdh.X25519().NewPublicKey(peerBytes)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := k.ECDH(peer); err != nil {
				b.Fatal(err)
			}
		}
	})
}
