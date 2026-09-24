package smb2

import (
	"bytes"
	"context"
	"testing"
)

func TestSessionStatus(t *testing.T) {
	tests := []struct {
		name      string
		flags     uint16
		guest     bool
		anonymous bool
	}{
		{"regular", 0x0000, false, false},
		{"guest", 0x0001, true, false},
		{"anonymous", 0x0002, false, true},
		{"guest and anonymous", 0x0003, true, true},
		{"encryption only", 0x0004, false, false},
		{"guest with encryption", 0x0005, true, false},
		{"anonymous with encryption", 0x0006, false, true},
		{"unrelated flag", 0x8000, false, false},
		{"guest with unrelated flag", 0x8001, true, false},
		{"anonymous with unrelated flag", 0x8002, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Session{s: &session{sessionFlags: tt.flags}}
			for name, s := range map[string]*Session{
				"original":     s,
				"with context": s.WithContext(context.Background()),
			} {
				t.Run(name, func(t *testing.T) {
					if got := s.IsGuest(); got != tt.guest {
						t.Errorf("IsGuest() = %v, want %v (flags %#04x)", got, tt.guest, tt.flags)
					}
					if got := s.IsAnonymous(); got != tt.anonymous {
						t.Errorf("IsAnonymous() = %v, want %v (flags %#04x)", got, tt.anonymous, tt.flags)
					}
				})
			}
		})
	}
}

type partialReader struct {
	buf *bytes.Buffer
}

func (p *partialReader) Read(b []byte) (int, error) {
	if len(b) < 2 {
		return p.buf.Read(b)
	}
	// read partial of b
	return p.buf.Read(b[:len(b)/2])
}

func TestCopyBufferPartialRead(t *testing.T) {
	bufIn := []byte("this is a partial read test data")
	bufR := make([]byte, len(bufIn))
	copy(bufR, bufIn)
	p := &partialReader{
		buf: bytes.NewBuffer(bufR),
	}
	var bufW bytes.Buffer
	n, err := copyBuffer(p, &bufW, make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(bufIn)) {
		t.Fatal("size not equal")
	}
	if !bytes.Equal(bufIn, bufW.Bytes()) {
		t.Fatal("data not equal")
	}
}
