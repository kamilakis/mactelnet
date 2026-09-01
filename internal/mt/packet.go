// SPDX-License-Identifier: GPL-3.0-only

// Package mt implements the MikroTik MAC-Telnet protocol: the UDP transport,
// the EC-SRP5 login used by RouterOS 6.43 and later, MNDP discovery, and the
// terminal handling RouterOS expects of a client.
package mt

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

const (
	Port      = 20561 // MAC-Telnet, UDP, broadcast
	MNDPPort  = 5678  // MNDP discovery, UDP, broadcast
	HeaderLen = 22
	cpHdrLen  = 9
	MaxPacket = 1500

	clientType = 0x0015
)

// Packet types.
const (
	PtSessionStart = 0
	PtData         = 1
	PtAck          = 2
	PtPing         = 4
	PtPong         = 5
	PtEnd          = 255
)

// Control packet types.
const (
	CpBeginAuth     = 0
	CpEncryptionKey = 1
	CpPassword      = 2
	CpUsername      = 3
	CpTermType      = 4
	CpTermWidth     = 5
	CpTermHeight    = 6
	CpPacketError   = 7
	CpEndAuth       = 9
)

var cpMagic = [4]byte{0x56, 0x34, 0x12, 0xff}

// Header is a MAC-Telnet packet header.
//
// The wire layout is ASYMMETRIC, which is the classic trap in this protocol.
// Outbound, offsets 14-17 are the session key then the client type. Inbound
// they are the server type then the session key. Parsing an inbound packet with
// the outbound layout yields a session key of 0x0015 for every packet and
// silently breaks the session.
type Header struct {
	Version    byte
	Type       byte
	Src        net.HardwareAddr
	Dst        net.HardwareAddr
	SessionKey uint16
	ServerType uint16 // inbound only
	Counter    uint32
}

// Marshal renders the header in the outbound layout.
func (h Header) Marshal() []byte {
	b := make([]byte, HeaderLen)
	b[0] = 1
	b[1] = h.Type
	copy(b[2:8], h.Src)
	copy(b[8:14], h.Dst)
	binary.BigEndian.PutUint16(b[14:16], h.SessionKey)
	binary.BigEndian.PutUint16(b[16:18], clientType)
	binary.BigEndian.PutUint32(b[18:22], h.Counter)
	return b
}

// ParseHeader reads the inbound layout, where the two 16-bit fields are swapped
// relative to Marshal. Returns the header and the payload that follows it.
func ParseHeader(b []byte) (Header, []byte, error) {
	if len(b) < HeaderLen {
		return Header{}, nil, fmt.Errorf("short packet: %d bytes", len(b))
	}
	h := Header{
		Version:    b[0],
		Type:       b[1],
		Src:        net.HardwareAddr(append([]byte(nil), b[2:8]...)),
		Dst:        net.HardwareAddr(append([]byte(nil), b[8:14]...)),
		ServerType: binary.BigEndian.Uint16(b[14:16]),
		SessionKey: binary.BigEndian.Uint16(b[16:18]),
		Counter:    binary.BigEndian.Uint32(b[18:22]),
	}
	return h, append([]byte(nil), b[HeaderLen:]...), nil
}

// Control is one control packet inside a DATA payload.
type Control struct {
	Type byte
	Data []byte
}

// Marshal renders a control packet: magic, type, big-endian length, data.
func (c Control) Marshal() []byte {
	b := make([]byte, cpHdrLen+len(c.Data))
	copy(b[0:4], cpMagic[:])
	b[4] = c.Type
	binary.BigEndian.PutUint32(b[5:9], uint32(len(c.Data)))
	copy(b[9:], c.Data)
	return b
}

// ParseControls walks a DATA payload and returns every control packet at its
// head, plus the remaining bytes, which are terminal output. A payload that is
// pure terminal output yields no controls.
func ParseControls(p []byte) ([]Control, []byte) {
	var out []Control
	i := 0
	for i+cpHdrLen <= len(p) {
		if !hasMagic(p[i:]) {
			break
		}
		n := int(binary.BigEndian.Uint32(p[i+5 : i+9]))
		if n < 0 || i+cpHdrLen+n > len(p) {
			break
		}
		out = append(out, Control{
			Type: p[i+4],
			Data: append([]byte(nil), p[i+cpHdrLen:i+cpHdrLen+n]...),
		})
		i += cpHdrLen + n
	}
	return out, p[i:]
}

func hasMagic(p []byte) bool {
	return len(p) >= 4 && p[0] == cpMagic[0] && p[1] == cpMagic[1] &&
		p[2] == cpMagic[2] && p[3] == cpMagic[3]
}

// ParseMAC accepts the usual separators, or none: "00:00:5E:00:53:01",
// "00-00-5e-00-53-01", "00005e005301".
func ParseMAC(s string) (net.HardwareAddr, error) {
	clean := strings.Map(func(r rune) rune {
		if strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return r
		}
		return -1
	}, s)
	if len(clean) != 12 {
		return nil, fmt.Errorf("not a MAC address: %q", s)
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("not a MAC address: %q", s)
	}
	return net.HardwareAddr(b), nil
}
