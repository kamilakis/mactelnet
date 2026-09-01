// SPDX-License-Identifier: GPL-3.0-only

package mt

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Login performs the EC-SRP5 exchange:
//
//	client -> CP_BEGIN_AUTHENTICATION (empty)
//	          CP_ENCRYPTION_KEY  username || 0x00 || pubkey(32) || parity(1)
//	server -> CP_ENCRYPTION_KEY  server_pubkey(32) || parity(1) || salt(16)
//	client -> CP_PASSWORD confirmation(32), CP_USERNAME, terminal geometry
//	server -> CP_END_AUTHENTICATION
//
// The username must travel in that first packet. Without it the device cannot
// look up a salt and answers with a short random blob, which is what made this
// protocol look like a legacy MD5 challenge for so long.
func (s *Session) Login(user, pass, term string, width, height int, timeout time.Duration) error {
	priv, err := NewPrivateKey()
	if err != nil {
		return err
	}
	pub, parity := PublicKey(priv)

	keyData := append([]byte(user), 0)
	keyData = append(keyData, pub...)
	keyData = append(keyData, byte(parity))

	hello := append(
		Control{Type: CpBeginAuth}.Marshal(),
		Control{Type: CpEncryptionKey, Data: keyData}.Marshal()...,
	)
	if err := s.Write(hello); err != nil {
		return fmt.Errorf("key exchange: %w", err)
	}

	reply, err := s.awaitControl(CpEncryptionKey, timeout)
	if err != nil {
		return fmt.Errorf("no key exchange reply: %w", err)
	}
	if len(reply) < 49 {
		return fmt.Errorf("device answered the key exchange with %d bytes, not 49: that is its "+
			"'no such user' reply, so check the username %q (a device still speaking the dead MD5 "+
			"scheme also lands here)", len(reply), user)
	}
	serverPub, serverParity, salt := reply[:32], int(reply[32]), reply[33:49]

	confirmation, err := Confirmation(user, pass, salt, priv, pub, serverPub, serverParity)
	if err != nil {
		return err
	}

	w := make([]byte, 2)
	h := make([]byte, 2)
	binary.LittleEndian.PutUint16(w, uint16(width))
	binary.LittleEndian.PutUint16(h, uint16(height))

	var auth []byte
	for _, c := range []Control{
		{Type: CpPassword, Data: confirmation},
		{Type: CpUsername, Data: []byte(user)},
		{Type: CpTermType, Data: []byte(term)},
		{Type: CpTermWidth, Data: w},
		{Type: CpTermHeight, Data: h},
	} {
		auth = append(auth, c.Marshal()...)
	}
	if err := s.Write(auth); err != nil {
		return fmt.Errorf("sending credentials: %w", err)
	}

	if _, err := s.awaitControl(CpEndAuth, timeout); err != nil {
		return fmt.Errorf("login failed: the device rejected the proof (wrong password), or closed the session")
	}
	return nil
}

// awaitControl waits for one control packet of the given type, buffering any
// terminal output that arrives meanwhile.
func (s *Session) awaitControl(want byte, timeout time.Duration) ([]byte, error) {
	deadline := time.After(timeout)
	var seen strings.Builder
	for {
		select {
		case c := <-s.controls:
			if c.Type == want {
				return c.Data, nil
			}
		case b := <-s.out:
			seen.Write(b)
			if strings.Contains(seen.String(), "Login failed") {
				return nil, fmt.Errorf("device said: Login failed")
			}
		case <-s.done:
			if strings.Contains(seen.String(), "Login failed") {
				return nil, fmt.Errorf("device said: Login failed")
			}
			return nil, ErrClosed
		case <-deadline:
			return nil, fmt.Errorf("timed out after %s", timeout)
		}
	}
}
