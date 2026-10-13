package tls

import (
	"io"
	"net"
	"testing"
	"time"
)

// Roller.Dial must close the TCP connection of every failed handshake attempt.
func TestRollerDialClosesFailedConns(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	roller, err := NewRoller()
	if err != nil {
		t.Fatal(err)
	}
	roller.HelloIDs = []ClientHelloID{HelloChrome_Auto, HelloFirefox_Auto}
	roller.TcpDialTimeout = 5 * time.Second
	roller.TlsHandshakeTimeout = 5 * time.Second

	closed := make(chan bool, len(roller.HelloIDs))
	go func() {
		for range roller.HelloIDs {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				// Read the ClientHello, then answer with something that is
				// not TLS so the handshake fails.
				buf := make([]byte, 1<<16)
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				if _, err := conn.Read(buf); err != nil {
					closed <- false
					return
				}
				conn.Write([]byte("HTTP/1.0 400 Bad Request\r\n\r\n"))
				// The client must close its side: expect EOF, not a timeout.
				conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				_, err := io.Copy(io.Discard, conn)
				closed <- err == nil
			}(conn)
		}
	}()

	if _, err := roller.Dial("tcp", ln.Addr().String(), "example.com"); err == nil {
		t.Fatal("Dial succeeded against a non-TLS server")
	}
	for range roller.HelloIDs {
		if !<-closed {
			t.Fatal("Roller.Dial left a failed connection open")
		}
	}
}
