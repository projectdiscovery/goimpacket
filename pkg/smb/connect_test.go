package smb

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/projectdiscovery/goimpacket/pkg/session"
)

func TestConnectContextGivesUpOnStalledServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	// accept and never reply, so negotiation waits on the server forever
	stalled := make(chan net.Conn, 1)
	go func() {
		if conn, err := listener.Accept(); err == nil {
			stalled <- conn
		}
	}()
	t.Cleanup(func() {
		select {
		case conn := <-stalled:
			_ = conn.Close()
		default:
		}
	})

	addr := listener.Addr().(*net.TCPAddr)
	client := NewClient(session.Target{Host: addr.IP.String(), Port: addr.Port}, &session.Credentials{Username: "user", Password: "password"})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.ConnectContext(ctx) }()

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("got %v, want the connect to stop at the context deadline", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ConnectContext ignored its context")
	}
}
