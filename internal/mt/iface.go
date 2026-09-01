// SPDX-License-Identifier: GPL-3.0-only

package mt

import (
	"fmt"
	"net"
	"strings"
)

// Iface pairs a local IPv4 address with the MAC of the interface it belongs to,
// so the source MAC in the header always matches the NIC the packet leaves by.
type Iface struct {
	Name string
	IP   net.IP
	MAC  net.HardwareAddr
}

func (i Iface) String() string { return fmt.Sprintf("%s (%s, %s)", i.Name, i.IP, i.MAC) }

// Interfaces lists usable IPv4 interfaces: up, not loopback, with a MAC.
func Interfaces() ([]Iface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Iface
	for _, n := range ifs {
		if n.Flags&net.FlagUp == 0 || n.Flags&net.FlagLoopback != 0 || len(n.HardwareAddr) != 6 {
			continue
		}
		addrs, err := n.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			out = append(out, Iface{Name: n.Name, IP: ipn.IP.To4(), MAC: n.HardwareAddr})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable IPv4 interface")
	}
	return out, nil
}

// PickIface selects by name or IP; with no hint it takes the first, which on a
// multi-homed host (Hyper-V, VPNs) may not be the one facing the device.
func PickIface(hint string) (Iface, error) {
	all, err := Interfaces()
	if err != nil {
		return Iface{}, err
	}
	if hint == "" {
		return all[0], nil
	}
	for _, i := range all {
		if strings.EqualFold(i.Name, hint) || i.IP.String() == hint {
			return i, nil
		}
	}
	var names []string
	for _, i := range all {
		names = append(names, i.String())
	}
	return Iface{}, fmt.Errorf("no interface matches %q; available:\n  %s", hint, strings.Join(names, "\n  "))
}
