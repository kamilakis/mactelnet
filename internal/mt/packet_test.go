// SPDX-License-Identifier: GPL-3.0-only

package mt

import (
	"encoding/hex"
	"testing"
)

// Bytes captured from a real RouterOS 7.24.1 device. The MAC addresses have
// been replaced with the IANA documentation range (RFC 7042); everything else
// is exactly as it came off the wire, which is the point of these vectors.
const (
	capturedSessionStart = "010000005e00530200005e005301" + "3a7c" + "0015" + "00000000"
	capturedAck          = "010200005e00530100005e005302" + "0015" + "3a7c" + "00000000"
	capturedControl      = "563412ff01000000" + "10" + "c188ce4887c2e04a605c8fe01abc4184"
)

func TestMarshalHeaderMatchesCapture(t *testing.T) {
	src, _ := ParseMAC("00:00:5E:00:53:02")
	dst, _ := ParseMAC("00:00:5E:00:53:01")
	got := hex.EncodeToString(Header{
		Type: PtSessionStart, Src: src, Dst: dst, SessionKey: 0x3a7c,
	}.Marshal())
	if got != capturedSessionStart {
		t.Errorf("outbound header\n got %s\nwant %s", got, capturedSessionStart)
	}
}

// The inbound layout puts the session key at offset 16, not 14. A symmetric
// parser reports 0x0015 here and the session silently dies.
func TestParseHeaderIsNotSymmetric(t *testing.T) {
	raw, _ := hex.DecodeString(capturedAck)
	h, payload, err := ParseHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.Type != PtAck {
		t.Errorf("type = %d, want %d", h.Type, PtAck)
	}
	if h.SessionKey != 0x3a7c {
		t.Errorf("session key = %#04x, want 0x3a7c (read from offset 16, not 14)", h.SessionKey)
	}
	if h.ServerType != 0x0015 {
		t.Errorf("server type = %#04x, want 0x0015", h.ServerType)
	}
	if h.Src.String() != "00:00:5e:00:53:01" {
		t.Errorf("src = %s", h.Src)
	}
	if len(payload) != 0 {
		t.Errorf("payload = %d bytes, want 0", len(payload))
	}
}

func TestControlRoundTrip(t *testing.T) {
	raw, _ := hex.DecodeString(capturedControl)
	cps, rest := ParseControls(raw)
	if len(cps) != 1 {
		t.Fatalf("got %d control packets, want 1", len(cps))
	}
	if cps[0].Type != CpEncryptionKey {
		t.Errorf("cptype = %d, want %d", cps[0].Type, CpEncryptionKey)
	}
	if len(cps[0].Data) != 16 {
		t.Errorf("payload = %d bytes, want 16", len(cps[0].Data))
	}
	if len(rest) != 0 {
		t.Errorf("trailing = %d bytes, want 0", len(rest))
	}
	if got := hex.EncodeToString(cps[0].Marshal()); got != capturedControl {
		t.Errorf("round trip\n got %s\nwant %s", got, capturedControl)
	}
}

// A DATA payload may carry controls followed by terminal bytes.
func TestParseControlsSplitsTerminalOutput(t *testing.T) {
	raw, _ := hex.DecodeString(capturedControl)
	raw = append(raw, []byte("hello")...)
	cps, rest := ParseControls(raw)
	if len(cps) != 1 || string(rest) != "hello" {
		t.Errorf("got %d controls, rest %q", len(cps), rest)
	}
}

func TestParseMAC(t *testing.T) {
	for _, s := range []string{"00:00:5E:00:53:01", "00-00-5e-00-53-01", "00005e005301"} {
		m, err := ParseMAC(s)
		if err != nil || m.String() != "00:00:5e:00:53:01" {
			t.Errorf("ParseMAC(%q) = %v, %v", s, m, err)
		}
	}
	if _, err := ParseMAC("nonsense"); err == nil {
		t.Error("expected an error for a non-MAC")
	}
}
