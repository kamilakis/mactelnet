// SPDX-License-Identifier: GPL-3.0-only

package mt

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Device is one MNDP reply.
type Device struct {
	From       net.IP
	MAC        net.HardwareAddr
	Identity   string
	Version    string
	Platform   string
	Board      string
	Interface  string
	SoftwareID string
	IPv4       net.IP
	Uptime     time.Duration
}

func (d Device) String() string {
	parts := []string{d.Identity}
	if d.Board != "" {
		parts = append(parts, d.Board)
	}
	if d.Version != "" {
		parts = append(parts, d.Version)
	}
	return strings.Join(parts, "  ")
}

// Discover broadcasts an MNDP probe and collects replies for the given window.
// Results are sorted by identity so output is stable.
func Discover(local net.IP, broadcast string, window time.Duration) ([]Device, error) {
	// Bind INADDR_ANY, not the chosen address: on Linux a socket bound to a
	// specific unicast IP never receives broadcast-destined packets, and MNDP
	// replies are broadcast. Windows is laxer, so binding the local IP appears
	// to work there and fails here. `local` is still used to send from the right
	// interface and to discard our own probe.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: MNDPPort})
	if err != nil {
		return nil, fmt.Errorf("bind udp/%d: %w", MNDPPort, err)
	}
	defer conn.Close()

	dst := &net.UDPAddr{IP: net.ParseIP(broadcast), Port: MNDPPort}
	if _, err := conn.WriteToUDP(make([]byte, 4), dst); err != nil {
		return nil, fmt.Errorf("send probe: %w", err)
	}

	seen := map[string]Device{}
	conn.SetReadDeadline(time.Now().Add(window))
	buf := make([]byte, MaxPacket)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			break // deadline
		}
		// A socket bound to the broadcast port hears its own probe.
		if from.IP.Equal(local) || n <= 4 {
			continue
		}
		d := parseMNDP(buf[:n], from.IP)
		key := d.MAC.String()
		if key == "" {
			key = d.From.String()
		}
		if _, dup := seen[key]; !dup {
			seen[key] = d
		}
	}

	out := make([]Device, 0, len(seen))
	for _, d := range seen {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity < out[j].Identity })
	return out, nil
}

// MNDP is a 4-byte header followed by type/length/value triples, big-endian.
func parseMNDP(b []byte, from net.IP) Device {
	d := Device{From: from}
	for i := 4; i+4 <= len(b); {
		typ := binary.BigEndian.Uint16(b[i : i+2])
		n := int(binary.BigEndian.Uint16(b[i+2 : i+4]))
		i += 4
		if i+n > len(b) {
			break
		}
		v := b[i : i+n]
		i += n

		switch typ {
		case 1:
			if n == 6 {
				d.MAC = net.HardwareAddr(append([]byte(nil), v...))
			}
		case 5:
			d.Identity = string(v)
		case 7:
			d.Version = string(v)
		case 8:
			d.Platform = string(v)
		case 10:
			if n >= 4 {
				d.Uptime = time.Duration(binary.LittleEndian.Uint32(v)) * time.Second
			}
		case 11:
			d.SoftwareID = string(v)
		case 12:
			d.Board = string(v)
		case 16:
			d.Interface = string(v)
		case 17:
			if n >= 4 {
				d.IPv4 = net.IP(append([]byte(nil), v...))
			}
		}
	}
	return d
}
