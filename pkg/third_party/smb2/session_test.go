package smb2

import (
	"testing"

	. "github.com/projectdiscovery/goimpacket/pkg/third_party/smb2/internal/smb2"
)

func TestPreauthIntegrityKerberosExcludesSuccessResponse(t *testing.T) {
	seed := [64]byte{1, 2, 3}
	req1 := []byte("session-setup-req-1")
	respSuccess := []byte("session-setup-success")

	kerberos := session{preauthIntegrityHashValue: seed}
	kerberos.updatePreauthIntegrity(SHA512, req1)

	buggy := session{preauthIntegrityHashValue: seed}
	buggy.updatePreauthIntegrity(SHA512, req1)
	buggy.updatePreauthIntegrity(SHA512, respSuccess)
	buggy.updatePreauthIntegrity(SHA512, req1)

	if kerberos.preauthIntegrityHashValue == buggy.preauthIntegrityHashValue {
		t.Fatal("hashing the STATUS_SUCCESS response and re-hashing the request must change the SMB 3.1.1 KDF context")
	}

	ntlm := session{preauthIntegrityHashValue: seed}
	ntlm.updatePreauthIntegrity(SHA512, req1)
	ntlm.updatePreauthIntegrity(SHA512, []byte("more-processing"))
	ntlm.updatePreauthIntegrity(SHA512, []byte("session-setup-req-2"))
	if ntlm.preauthIntegrityHashValue == kerberos.preauthIntegrityHashValue {
		t.Fatal("two-leg NTLM preauth hash must differ from single-leg Kerberos hash")
	}
}
