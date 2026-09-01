// SPDX-License-Identifier: GPL-3.0-only

package mt

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"
)

// The reference client's retransmit ladder.
var retransmit = []time.Duration{
	15 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond,
	50 * time.Millisecond, 90 * time.Millisecond, 170 * time.Millisecond,
	330 * time.Millisecond, 660 * time.Millisecond, 1000 * time.Millisecond,
}

// ErrClosed is returned once the device has ended the session.
var ErrClosed = errors.New("device closed the session")

// Session is one MAC-Telnet conversation. Terminal output arrives on Output();
// Write sends keystrokes or commands. Safe for one reader and one writer.
type Session struct {
	conn   *net.UDPConn
	remote *net.UDPAddr
	src    net.HardwareAddr
	dst    net.HardwareAddr
	key    uint16

	mu         sync.Mutex
	outCounter uint32
	inCounter  uint32
	lastAck    int64
	closed     bool

	out      chan []byte // terminal bytes
	controls chan Control
	acked    chan struct{} // pinged whenever lastAck advances
	done     chan struct{}
	closeOne sync.Once

	Trace func(dir string, h Header, payload []byte)
}

// Dial opens a session to dst. It binds the MAC-Telnet port on the chosen local
// address and talks to the broadcast address, which is how the reference client
// works and needs no raw sockets and no privileges.
func Dial(local net.IP, localMAC, dst net.HardwareAddr, broadcast string) (*Session, error) {
	// INADDR_ANY, for the same reason as MNDP: the device answers to the
	// broadcast address, and on Linux a socket bound to a specific unicast IP
	// never sees those. See the note in Discover.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: Port})
	if err != nil {
		return nil, fmt.Errorf("bind udp/%d: %w", Port, err)
	}
	s := &Session{
		conn:     conn,
		remote:   &net.UDPAddr{IP: net.ParseIP(broadcast), Port: Port},
		src:      localMAC,
		dst:      dst,
		key:      uint16(rand.Intn(65534) + 1),
		lastAck:  -1,
		out:      make(chan []byte, 256),
		controls: make(chan Control, 64),
		acked:    make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
	go s.readLoop()
	return s, nil
}

// Output carries terminal bytes from the device. Control packets are filtered
// out of it and delivered on Controls instead.
func (s *Session) Output() <-chan []byte    { return s.out }
func (s *Session) Controls() <-chan Control { return s.controls }
func (s *Session) Done() <-chan struct{}    { return s.done }
func (s *Session) Key() uint16              { return s.key }

func (s *Session) send(ptype byte, payload []byte, counter uint32) error {
	h := Header{Type: ptype, Src: s.src, Dst: s.dst, SessionKey: s.key, Counter: counter}
	pkt := append(h.Marshal(), payload...)
	if s.Trace != nil {
		s.Trace("->", h, payload)
	}
	_, err := s.conn.WriteToUDP(pkt, s.remote)
	return err
}

// readLoop does all the protocol bookkeeping: ACK every DATA at once (an
// un-ACKed packet triggers the device's retransmit ladder and you drown in
// duplicates), answer PING, note END, and drop duplicates by counter.
func (s *Session) readLoop() {
	buf := make([]byte, MaxPacket)
	for {
		n, _, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			s.shutdown()
			return
		}
		h, payload, err := ParseHeader(buf[:n])
		if err != nil || h.Version != 1 {
			continue
		}
		// Filter on the header, not the source IP: a socket bound to the
		// broadcast port hears its own broadcasts, and other sessions' too.
		if h.SessionKey != s.key ||
			h.Dst.String() != s.src.String() ||
			h.Src.String() == s.src.String() {
			continue
		}
		if s.Trace != nil {
			s.Trace("<-", h, payload)
		}

		switch h.Type {
		case PtAck:
			s.noteAck(int64(h.Counter))
		case PtPing:
			s.send(PtPong, payload, h.Counter)
		case PtEnd:
			s.shutdown()
			return
		case PtData:
			s.send(PtAck, nil, h.Counter+uint32(len(payload)))
			if !s.freshen(h.Counter, len(payload)) {
				continue // retransmit: ACKed above, not re-read
			}
			controls, rest := ParseControls(payload)
			for _, c := range controls {
				select {
				case s.controls <- c:
				default:
				}
			}
			if len(rest) > 0 {
				select {
				case s.out <- rest:
				case <-s.done:
					return
				}
			}
		}
	}
}

func (s *Session) noteAck(c int64) {
	s.mu.Lock()
	if c > s.lastAck {
		s.lastAck = c
	}
	s.mu.Unlock()
	select {
	case s.acked <- struct{}{}:
	default:
	}
}

func (s *Session) freshen(counter uint32, n int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if counter < s.inCounter {
		return false
	}
	s.inCounter = counter + uint32(n)
	return true
}

func (s *Session) shutdown() {
	s.closeOne.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		close(s.done)
	})
}

// Start sends SESSIONSTART and waits for the ACK.
func (s *Session) Start(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for i := 0; ; i++ {
		if err := s.send(PtSessionStart, nil, 0); err != nil {
			return err
		}
		select {
		case <-s.acked:
			return nil
		case <-s.done:
			return ErrClosed
		case <-time.After(retransmit[min(i, len(retransmit)-1)]):
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no SESSIONSTART ack from %s after %s -- nothing answered, so no password was sent. "+
				"Check the MAC (try discovery), that mac-server is enabled, and that this host is on the device's L2 segment",
				s.dst, timeout)
		}
	}
}

// Write sends a DATA packet and walks the retransmit ladder until the device
// acknowledges past it.
func (s *Session) Write(payload []byte) error {
	s.mu.Lock()
	start := s.outCounter
	s.mu.Unlock()
	want := int64(start) + int64(len(payload))

	deadline := time.Now().Add(10 * time.Second)
	for i := 0; ; i++ {
		if err := s.send(PtData, payload, start); err != nil {
			return err
		}
		select {
		case <-s.acked:
		case <-s.done:
			return ErrClosed
		case <-time.After(retransmit[min(i, len(retransmit)-1)]):
		}
		s.mu.Lock()
		got := s.lastAck
		s.mu.Unlock()
		if got >= want {
			s.mu.Lock()
			s.outCounter = uint32(want)
			s.mu.Unlock()
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("no ack for a data packet -- device stopped answering")
		}
	}
}

// Close ends the session politely and releases the socket.
func (s *Session) Close() error {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if !closed {
		s.send(PtEnd, nil, s.outCounter)
	}
	s.shutdown()
	return s.conn.Close()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
