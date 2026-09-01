// SPDX-License-Identifier: GPL-3.0-only

package mt

import (
	"bytes"
	"fmt"
	"regexp"
	"time"
)

// RouterOS measures the terminal by driving the cursor to the bottom and asking
// where it ended up:
//
//	\r ESC[9999B \r ESC[9999B ESC Z  "  " ESC[6n
//
// Interactively the user's terminal emulator answers and the client just relays
// the reply. Headless there is nobody to answer, so the device waits forever and
// retransmits -- which looks exactly like a protocol bug. We answer for it.
//
// Two details found by packet trace: RouterOS takes the reported COLUMN as the
// terminal width (report 1 and it wraps every character; report 3 and it wraps
// every three), ignoring CP_TERM_WIDTH. And it uses the single-byte CSI 0x9b as
// well as ESC[, so both forms must be recognised.
var (
	dsrRe   = regexp.MustCompile(`\x1b\[6n`)
	daRe    = regexp.MustCompile(`\x1bZ|\x1b\[c`)
	ansiRe  = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-Z\\-_]`)
	pagerRe = regexp.MustCompile(`--\s*\[Q quit\|D dump\|up\|down\]`)
	// [user@identity] > , at the end of the buffer
	PromptRe = regexp.MustCompile(`\[[^\]\r\n]+@[^\]\r\n]+\]\s*>\s*$`)
)

// normalizeCSI rewrites the single-byte CSI 0x9b as ESC[, which is what it
// means. Go regexps are UTF-8: a raw 0x9b can neither appear in a pattern nor
// survive matching, so normalising once here lets every pattern above stay
// simple. The same byte caused the equivalent bug in the PowerShell client,
// where UTF-8 decoding silently replaced it with U+FFFD and hid every escape
// sequence RouterOS sends.
func normalizeCSI(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte{0x9b}, []byte{0x1b, '['})
}

// AnswerProbes replies to any terminal queries in b. Returns true if it did.
func (s *Session) AnswerProbes(b []byte, width, height int) (bool, error) {
	b = normalizeCSI(b)
	answered := false
	for range dsrRe.FindAll(b, -1) {
		if err := s.Write([]byte(fmt.Sprintf("\x1b[%d;%dR", height, width))); err != nil {
			return answered, err
		}
		answered = true
	}
	for range daRe.FindAll(b, -1) {
		if err := s.Write([]byte("\x1b[?1;2c")); err != nil {
			return answered, err
		}
		answered = true
	}
	return answered, nil
}

// StripANSI removes escape sequences and stray control bytes, leaving readable
// text. Used for -c output only; interactive sessions relay bytes untouched.
func StripANSI(b []byte) []byte {
	out := ansiRe.ReplaceAll(normalizeCSI(b), nil)
	out = bytes.ReplaceAll(out, []byte("\r\n"), []byte("\n"))
	out = bytes.ReplaceAll(out, []byte("\r"), []byte("\n"))
	return bytes.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || (r >= 0x20 && r < 0x7f) || r > 0x9f {
			return r
		}
		return -1
	}, out)
}

// Settle reads until the buffer matches re and then stays quiet for the settle
// period, answering terminal probes throughout.
//
// The quiet period is not optional: RouterOS redraws the prompt the instant you
// press Enter, before running the command, so matching the prompt alone returns
// an empty result.
func (s *Session) Settle(re *regexp.Regexp, width, height int, quiet, timeout time.Duration) ([]byte, error) {
	var buf []byte
	overall := time.After(timeout)
	for {
		var wait <-chan time.Time
		if re == nil || re.Match(StripANSI(buf)) {
			wait = time.After(quiet)
		}
		select {
		case b := <-s.out:
			buf = append(buf, b...)
			if _, err := s.AnswerProbes(b, width, height); err != nil {
				return buf, err
			}
			if pagerRe.Match(normalizeCSI(b)) {
				if err := s.Write([]byte(" ")); err != nil {
					return buf, err
				}
			}
		case <-s.controls:
			// control packets after login are noise for the terminal
		case <-wait:
			return buf, nil
		case <-s.done:
			return buf, ErrClosed
		case <-overall:
			return buf, fmt.Errorf("timed out after %s waiting for the device", timeout)
		}
	}
}
