// SPDX-License-Identifier: GPL-3.0-only

// Command mactelnet is a MAC-Telnet client for MikroTik devices: it reaches a
// RouterOS box over Layer 2, by MAC address, when its IP management plane is
// unreachable. It behaves like ssh or telnet -- run it with a MAC for an
// interactive session, or with -c to run commands and exit.
//
//	mactelnet -d                                 discover devices
//	mactelnet -u admin 00:00:5E:00:53:01         interactive session
//	mactelnet -u admin -c '/system identity print' 00:00:5E:00:53:01
//
// It needs no privileges: MAC-Telnet's broadcast mode requires no raw sockets.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/kamilakis/mactelnet/internal/mt"
)

var version = "dev"

type commands []string

func (c *commands) String() string     { return strings.Join(*c, ", ") }
func (c *commands) Set(s string) error { *c = append(*c, s); return nil }

func main() {
	var (
		user      = flag.String("u", "admin", "RouterOS username")
		pass      = flag.String("p", "", "password (default: $MACTELNET_PASSWORD, else prompt)")
		iface     = flag.String("i", "", "interface name or local IP to send from")
		discover  = flag.Bool("d", false, "discover devices with MNDP and exit")
		cmds      commands
		broadcast = flag.String("b", "255.255.255.255", "broadcast address")
		timeout   = flag.Duration("t", 10*time.Second, "network timeout")
		width     = flag.Int("w", 250, "terminal width to declare")
		height    = flag.Int("H", 200, "terminal height to declare")
		trace     = flag.Bool("v", false, "trace every packet")
		showVer   = flag.Bool("version", false, "print version and exit")
	)
	flag.Var(&cmds, "c", "run a command and exit; repeat for several")
	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Println("mactelnet", version)
		return
	}

	if err := run(opts{
		user: *user, pass: *pass, iface: *iface, discover: *discover,
		cmds: cmds, broadcast: *broadcast, timeout: *timeout,
		width: *width, height: *height, trace: *trace, target: flag.Arg(0),
	}); err != nil {
		fmt.Fprintln(os.Stderr, "mactelnet:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `mactelnet - MAC-Telnet client for MikroTik devices

Reaches a RouterOS box over Layer 2 by MAC address, for when its IP management
plane is unreachable. Requires no privileges and must run on a host that shares
an Ethernet segment with the target.

usage:
  mactelnet -d                                    discover devices
  mactelnet [flags] <MAC>                         interactive session
  mactelnet [flags] -c '<command>' <MAC>          run commands and exit

flags:
`)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
The password comes from -p, else $MACTELNET_PASSWORD, else a prompt.
A MAC may be written 00:00:5E:00:53:01, 00-00-5e-00-53-01 or 00005e005301.
`)
}

type opts struct {
	user, pass, iface, broadcast, target string
	discover, trace                      bool
	cmds                                 []string
	timeout                              time.Duration
	width, height                        int
}

func run(o opts) error {
	nic, err := mt.PickIface(o.iface)
	if err != nil {
		return err
	}

	if o.discover {
		devices, err := mt.Discover(nic.IP, o.broadcast, maxDur(o.timeout, 3*time.Second))
		if err != nil {
			return err
		}
		if len(devices) == 0 {
			return fmt.Errorf("no MNDP replies on %s -- nothing MikroTik on this segment, or discovery is disabled", nic)
		}
		for _, d := range devices {
			fmt.Printf("%s  %s\n", d.MAC, d.Identity)
			fmt.Printf("    board     %s\n", d.Board)
			fmt.Printf("    version   %s\n", d.Version)
			fmt.Printf("    address   %s (replies from %s)\n", d.IPv4, d.From)
			fmt.Printf("    interface %s\n", d.Interface)
			if d.Uptime > 0 {
				fmt.Printf("    uptime    %s\n", d.Uptime)
			}
		}
		return nil
	}

	if o.target == "" {
		flag.Usage()
		return errors.New("no MAC address given")
	}
	dst, err := mt.ParseMAC(o.target)
	if err != nil {
		return err
	}

	pass, err := password(o.pass, o.user, o.target)
	if err != nil {
		return err
	}

	s, err := mt.Dial(nic.IP, nic.MAC, dst, o.broadcast)
	if err != nil {
		return err
	}
	defer s.Close()

	if o.trace {
		s.Trace = func(dir string, h mt.Header, payload []byte) {
			fmt.Fprintf(os.Stderr, "%s %-12s counter=%-6d len=%d\n", dir, ptypeName(h.Type), h.Counter, len(payload))
		}
	}

	if err := s.Start(o.timeout); err != nil {
		return err
	}
	term := "dumb"
	if len(o.cmds) == 0 {
		term = envOr("TERM", "vt100")
	}
	if err := s.Login(o.user, pass, term, o.width, o.height, o.timeout); err != nil {
		return err
	}

	if len(o.cmds) > 0 {
		return runCommands(s, o)
	}
	return interactive(s, o)
}

// runCommands drives the session headlessly.
//
// RouterOS sends nothing at all after login until the client speaks: no banner,
// no prompt, just retransmitted END_AUTH. So knock once, absorb the size probe
// and the banner, and only then issue commands -- otherwise the first command is
// swallowed by the setup and its output never appears.
func runCommands(s *mt.Session, o opts) error {
	if err := s.Write([]byte("\r\n")); err != nil {
		return err
	}
	raw, err := s.Settle(mt.PromptRe, o.width, o.height, 500*time.Millisecond, o.timeout)
	if err != nil {
		return authError(raw, err)
	}

	for _, c := range o.cmds {
		if err := s.Write([]byte(c + "\r\n")); err != nil {
			return err
		}
		raw, err := s.Settle(mt.PromptRe, o.width, o.height, 500*time.Millisecond, o.timeout)
		if err != nil {
			return authError(raw, err)
		}
		if len(o.cmds) > 1 {
			fmt.Printf("=== %s\n", c)
		}
		fmt.Println(clean(string(mt.StripANSI(raw)), c))
	}
	s.Write([]byte("/quit\r\n"))
	return nil
}

// clean strips the command echo and the trailing prompt. RouterOS echoes each
// command twice -- once as typed, once in the prompt it redraws afterwards --
// so walk the leading block and drop through the last echo.
func clean(text, cmd string) string {
	lines := strings.Split(text, "\n")
	echo := -1
	for i, l := range lines {
		t := strings.TrimRight(l, " \t")
		if strings.HasSuffix(t, strings.TrimSpace(cmd)) {
			echo = i
			continue
		}
		if strings.TrimSpace(t) == "" {
			continue
		}
		break
	}
	if echo >= 0 {
		lines = lines[echo+1:]
	}
	for len(lines) > 0 {
		last := lines[len(lines)-1]
		if strings.TrimSpace(last) == "" || mt.PromptRe.MatchString(last) {
			lines = lines[:len(lines)-1]
			continue
		}
		break
	}
	// Trim newlines only: RouterOS aligns output with leading spaces.
	return strings.Trim(strings.Join(lines, "\n"), "\r\n")
}

// interactive relays the session to the local terminal, like telnet. In raw mode
// the terminal answers RouterOS's size probes itself, so nothing is interpreted
// here -- bytes go through untouched in both directions.
func interactive(s *mt.Session, o opts) error {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		state, err := term.MakeRaw(fd)
		if err != nil {
			return fmt.Errorf("raw mode: %w", err)
		}
		defer term.Restore(fd, state)

		if w, h, err := term.GetSize(fd); err == nil && w > 0 {
			o.width, o.height = w, h
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)

	// Knock, so RouterOS starts its terminal.
	if err := s.Write([]byte("\r\n")); err != nil {
		return err
	}

	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				if err := s.Write(append([]byte(nil), buf[:n]...)); err != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	for {
		select {
		case b := <-s.Output():
			// Answer the size probe in case the local terminal will not.
			s.AnswerProbes(b, o.width, o.height)
			if _, err := os.Stdout.Write(b); err != nil {
				return err
			}
		case <-s.Controls():
		case <-sig:
			s.Write([]byte{0x03}) // pass Ctrl-C to the device
		case <-s.Done():
			fmt.Fprintln(os.Stderr, "\r\nconnection closed by the device")
			return nil
		}
	}
}

// authError turns the device's own words into a useful message. RouterOS sends
// CP_END_AUTHENTICATION even when it is about to reject the credentials, so the
// only reliable signal of a bad password is the banner it prints just before
// closing the session.
func authError(raw []byte, err error) error {
	if bytes.Contains(raw, []byte("Login failed")) ||
		bytes.Contains(raw, []byte("incorrect username or password")) {
		return errors.New("login failed: incorrect username or password, " +
			"or the user's group lacks the telnet policy")
	}
	return err
}

func password(given, user, target string) (string, error) {
	if given != "" {
		return given, nil
	}
	if p, ok := os.LookupEnv("MACTELNET_PASSWORD"); ok {
		return p, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("no password: pass -p, set $MACTELNET_PASSWORD, or run on a terminal")
	}
	fmt.Fprintf(os.Stderr, "Password for %s@%s: ", user, target)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil && err != io.EOF {
		return "", err
	}
	return string(b), nil
}

func ptypeName(t byte) string {
	switch t {
	case mt.PtSessionStart:
		return "SESSIONSTART"
	case mt.PtData:
		return "DATA"
	case mt.PtAck:
		return "ACK"
	case mt.PtPing:
		return "PING"
	case mt.PtPong:
		return "PONG"
	case mt.PtEnd:
		return "END"
	}
	return fmt.Sprintf("type%d", t)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func maxDur(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
