package tls

import (
	"context"
	"crypto/ecdh"
	"errors"
	"net"
	"sync"
	"time"
)

var realityBufferPool = sync.Pool{New: func() any { return new([realitySize]byte) }}

type realityECDHKey struct {
	source [32]byte
	key    *ecdh.PrivateKey
}

func (c *RealityConfig) realityPrivateKey() (*ecdh.PrivateKey, error) {
	if len(c.PrivateKey) != 32 {
		return nil, errors.New("REALITY: invalid private key length")
	}
	source := [32]byte(c.PrivateKey)
	if cached := c.ecdhKey.Load(); cached != nil && cached.source == source {
		return cached.key, nil
	}
	key, err := ecdh.X25519().NewPrivateKey(c.PrivateKey)
	if err != nil {
		return nil, err
	}
	c.ecdhKey.Store(&realityECDHKey{source: source, key: key})
	return key, nil
}

func guardRealityHandshake(ctx context.Context, conn, target net.Conn, timeout time.Duration) func() {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	deadline := time.Now().Add(timeout)
	if until, ok := ctx.Deadline(); ok && until.Before(deadline) {
		deadline = until
	}
	_ = conn.SetReadDeadline(deadline)
	stopped := make(chan struct{})
	closePending := func() {
		select {
		case <-stopped:
			return
		default:
		}
		_ = conn.Close()
		_ = target.Close()
	}
	timer := time.AfterFunc(time.Until(deadline), closePending)
	if ctx.Done() != nil {
		go func() {
			select {
			case <-ctx.Done():
				closePending()
			case <-stopped:
			}
		}()
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			close(stopped)
			timer.Stop()
			_ = conn.SetReadDeadline(time.Time{})
			if notifier, ok := conn.(interface{ HandshakeComplete() }); ok {
				notifier.HandshakeComplete()
			}
		})
	}
}
