package smb2

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	. "github.com/projectdiscovery/goimpacket/pkg/third_party/smb2/internal/erref"
	. "github.com/projectdiscovery/goimpacket/pkg/third_party/smb2/internal/smb2"
)

func negotiateErrorPacket() []byte {
	res := &ErrorResponse{PacketHeader: PacketHeader{
		Command: SMB2_NEGOTIATE,
		Status:  uint32(STATUS_NOT_SUPPORTED),
		Flags:   SMB2_FLAGS_SERVER_TO_REDIR,
	}}
	pkt := make([]byte, res.Size())
	res.Encode(pkt)
	return pkt
}

func TestAcceptTruncatedNegotiateResponse(t *testing.T) {
	pkt := negotiateErrorPacket()
	for n := 0; n < 64; n++ {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			_, err := accept(SMB2_NEGOTIATE, pkt[:n:n])
			var invalid *InvalidResponseError
			if !errors.As(err, &invalid) {
				t.Fatalf("expected InvalidResponseError, got %T: %v", err, err)
			}
		})
	}
}

func TestAcceptPacketHeader(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(PacketCodec)
	}{
		{"valid", func(PacketCodec) {}},
		{"invalid_protocol", func(p PacketCodec) { p[0] = 0xff }},
		{"invalid_structure_size", func(p PacketCodec) { p[4] = 32 }},
		{"unaligned_next_command", func(p PacketCodec) { p.SetNextCommand(1) }},
		{"unexpected_command", func(p PacketCodec) { p.SetCommand(SMB2_SESSION_SETUP) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pkt := negotiateErrorPacket()
			PacketCodec(pkt).SetStatus(uint32(STATUS_SUCCESS))
			tt.mutate(PacketCodec(pkt))
			res, err := accept(SMB2_NEGOTIATE, pkt)
			if tt.name == "valid" {
				if err != nil || !bytes.Equal(res, pkt[64:]) {
					t.Fatalf("expected unchanged response body, got %x, %v", res, err)
				}
				return
			}
			var invalid *InvalidResponseError
			if !errors.As(err, &invalid) {
				t.Fatalf("expected InvalidResponseError, got %T: %v", err, err)
			}
		})
	}
}

func TestDialContextNegotiateResponse(t *testing.T) {
	smb1 := make([]byte, 35)
	copy(smb1, "\xffSMB")
	smb1[4] = 0x72 // SMB_COM_NEGOTIATE
	binary.LittleEndian.PutUint32(smb1[5:9], uint32(STATUS_NOT_SUPPORTED))
	smb1[9] = 0x80                                     // Response flag.
	binary.LittleEndian.PutUint16(smb1[10:12], 0x4000) // NTSTATUS errors.

	badMagic := negotiateErrorPacket()
	badMagic[0] = 0xff
	badSize := negotiateErrorPacket()
	binary.LittleEndian.PutUint16(badSize[4:6], 32)

	compound := make([]byte, 80)
	copy(compound, negotiateErrorPacket())
	PacketCodec(compound).SetStatus(uint32(STATUS_PENDING))
	PacketCodec(compound).SetNextCommand(80)
	compound = append(compound, negotiateErrorPacket()...)
	badCompound := bytes.Clone(compound)
	badCompound[80] = 0xff

	type responseCase struct {
		name    string
		packet  []byte
		invalid bool
	}
	tests := []responseCase{
		{"complete_error", negotiateErrorPacket(), false},
		{"complete_compound_error", compound, false},
		{"truncated_smb2", negotiateErrorPacket()[:35:35], true},
		{"smb1_error", smb1, true},
		{"invalid_protocol", badMagic, true},
		{"invalid_structure_size", badSize, true},
		{"missing_error_body", negotiateErrorPacket()[:64:64], true},
		{"invalid_second_header", badCompound, true},
		{"missing_second_header", compound[:80:80], true},
		{"truncated_second_header", compound[:115:115], true},
	}
	for n := 0; n < 64; n++ {
		tests = append(tests, responseCase{fmt.Sprintf("header_length_%d", n), negotiateErrorPacket()[:n:n], true})
	}
	for _, off := range []uint32{1, 8, 64, 72, 80, 0xfffffff8} {
		pkt := negotiateErrorPacket()
		PacketCodec(pkt).SetNextCommand(off)
		tests = append(tests, responseCase{fmt.Sprintf("next_command_%d", off), pkt, true})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, serverDone := serveNegotiateResponse(t, tt.packet)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			d := Dialer{Initiator: &NTLMInitiator{}}
			s, err := d.DialContext(ctx, client)
			if serverErr := <-serverDone; serverErr != nil {
				t.Fatalf("serve negotiation response: %v", serverErr)
			}
			if s != nil {
				t.Fatal("expected no session")
			}
			if tt.invalid {
				var invalid *InvalidResponseError
				if !errors.As(err, &invalid) {
					t.Fatalf("expected InvalidResponseError, got %T: %v", err, err)
				}
			} else {
				var response *ResponseError
				if !errors.As(err, &response) || response.Code != uint32(STATUS_NOT_SUPPORTED) {
					t.Fatalf("expected STATUS_NOT_SUPPORTED, got %T: %v", err, err)
				}
			}
		})
	}
}

func TestNegotiateValidResponse(t *testing.T) {
	for _, dialect := range clientDialects {
		t.Run(fmt.Sprintf("%x", dialect), func(t *testing.T) {
			res := &NegotiateResponse{
				PacketHeader:    PacketHeader{Flags: SMB2_FLAGS_SERVER_TO_REDIR},
				DialectRevision: dialect,
				SecurityMode:    SMB2_NEGOTIATE_SIGNING_REQUIRED,
				MaxTransactSize: 65536,
				MaxReadSize:     65536,
				MaxWriteSize:    65536,
				SystemTime:      &Filetime{},
				ServerStartTime: &Filetime{},
			}
			if dialect == SMB311 {
				res.Contexts = []Encoder{
					&HashContext{HashAlgorithms: []uint16{SHA512}},
					&CipherContext{Ciphers: []uint16{AES128GCM}},
				}
			}
			pkt := make([]byte, res.Size())
			res.Encode(pkt)
			client, serverDone := serveNegotiateResponse(t, pkt)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			n := Negotiator{SpecifiedDialect: dialect}
			c, err := n.negotiate(direct(client), openAccount(clientMaxCreditBalance), ctx)
			if serverErr := <-serverDone; serverErr != nil {
				t.Fatalf("serve negotiation response: %v", serverErr)
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.dialect != dialect || !c.requireSigning || c.maxReadSize != res.MaxReadSize {
				t.Fatal("negotiated settings do not match the response")
			}
			if dialect == SMB311 && (c.preauthIntegrityHashId != SHA512 || c.cipherId != AES128GCM) {
				t.Fatal("negotiated algorithms do not match the response")
			}
		})
	}
}

func serveNegotiateResponse(t *testing.T, pkt []byte) (net.Conn, <-chan error) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	if err := server.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		tr := direct(server)
		n, err := tr.ReadSize()
		if err == nil {
			_, err = tr.Read(make([]byte, n))
		}
		if err == nil {
			frame := make([]byte, 4+len(pkt))
			binary.BigEndian.PutUint32(frame, uint32(len(pkt)))
			copy(frame[4:], pkt)
			_, err = server.Write(frame)
		}
		done <- err
	}()
	return client, done
}
