package kerberos_test

import (
	"context"
	"net"
	"testing"

	"github.com/projectdiscovery/goimpacket/pkg/kerberos"
	"github.com/projectdiscovery/goimpacket/pkg/transport"
)

// TestGetTGSWithOptionsHonorsDialer pins the behavior requested in the issue:
// a per-call dialer supplied via TGSOptions must carry the KDC connection, the
// same guarantee GetASREPWithDialer already gives.
//
// The stand-in KDC accepts and closes immediately, so the exchange fails fast;
// we assert only that the dialer was consulted for the KDC address, since that
// is the routed connection under test — not the eventual (expected) error.
func TestGetTGSWithOptionsHonorsDialer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}

			_ = conn.Close()
		}
	}()

	kdc := ln.Addr().String()

	// DialFn runs synchronously inside GetTGSWithOptions on this goroutine, so a
	// plain slice needs no synchronization.
	var dialed []string

	dialer := &transport.Dialer{
		DialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialed = append(dialed, address)

			var d net.Dialer

			return d.DialContext(ctx, network, address)
		},
	}

	// The exchange is expected to fail (the stand-in KDC resets the connection);
	// the dialer must still have carried the KDC connection.
	_, _ = kerberos.GetTGSWithOptions(kerberos.TGSOptions{
		Username:   "user",
		Password:   "pass",
		Domain:     "example.local",
		KDCHost:    kdc,
		TargetUser: "svc",
		SPN:        "MSSQLSvc/db.example.local:1433",
		Dialer:     dialer,
	})

	if len(dialed) == 0 {
		t.Fatal("GetTGSWithOptions ignored TGSOptions.Dialer: the KDC connection did not go through the supplied dialer")
	}

	for _, addr := range dialed {
		if addr != kdc {
			t.Errorf("dialer received addr %q, want the KDC %q", addr, kdc)
		}
	}
}
