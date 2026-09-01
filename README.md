# mactelnet

A MAC-Telnet client for MikroTik devices — reach a RouterOS box over Layer 2, by
MAC address, when its IP management plane is unreachable. Discovery, an
interactive session, or one-shot commands.

It speaks **EC-SRP5**, the login RouterOS 6.43 and later actually require. As far
as I can tell this is the only client that does so and behaves like a normal
command-line tool. The widely used clients implement the legacy MD5 challenge,
which **cannot log in to a modern RouterOS at all** — see
[Why MD5 clients fail](#why-md5-clients-fail).

```console
$ mactelnet -d
00:00:5e:00:53:01  gateway
    board     RB2011UiAS
    version   7.24.1 (stable)
    address   10.0.0.1

$ mactelnet -u admin 00:00:5E:00:53:01
Password for admin@00:00:5E:00:53:01:

  MMM      MMM       KKK                          TTTTTTTTTTT      KKK
  MikroTik RouterOS 7.24.1 (c) 1999-2026    https://www.mikrotik.com/

[admin@gateway] > /system identity print
  name: gateway
```

## Install

```bash
go install github.com/kamilakis/mactelnet/cmd/mactelnet@latest
```

Or build it, including for a machine you are not on:

```bash
go build ./cmd/mactelnet
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o mactelnet.exe ./cmd/mactelnet
```

The result is a dependency-free static binary of about 2.8 MB.

## Use

```bash
mactelnet -d                                        # discover devices
mactelnet -u admin 00:00:5E:00:53:01                # interactive session
mactelnet -u admin -c '/system identity print' \
          -c '/ip address print' 00:00:5E:00:53:01  # run commands and exit
mactelnet -v ...                                    # packet trace on stderr
```

The password comes from `-p`, else `$MACTELNET_PASSWORD`, else an unechoed
prompt. A MAC may be written `00:00:5E:00:53:01`, `00-00-5e-00-53-01` or
`00005e005301`.

Two constraints worth knowing:

- **It must run on a host sharing an Ethernet segment with the target.**
  MAC-Telnet is a Layer-2 broadcast protocol; it cannot cross a routed tunnel.
- **Pass `-i` on a multi-homed host.** Hyper-V, WSL and VPN adapters present
  themselves as ordinary interfaces and the client will happily bind one that
  cannot see the device. `-i` takes an interface name or a local IP.

It needs no privileges: broadcast mode requires no raw sockets.

## Why MD5 clients fail

RouterOS still performs the legacy handshake, and then rejects every answer to
it. Since 6.43 it stores passwords only as an SRP verifier, and
`MD5(0x00 || password || salt)` cannot be derived from a verifier — so the device
has nothing to compare against and fails the login by construction. It looks
exactly like a wrong password, which is what makes it so confusing.

The trap that hides this: ask for a key exchange **without naming a user** and
the device answers with 16 bytes, which looks precisely like the legacy MD5
challenge. It is not. The real exchange must carry the username:

```
client -> CP_BEGIN_AUTHENTICATION (empty)
          CP_ENCRYPTION_KEY  username || 0x00 || client_pubkey(32) || parity(1)
server -> CP_ENCRYPTION_KEY  server_pubkey(32) || parity(1) || salt(16)
client -> CP_PASSWORD confirmation(32), CP_USERNAME, terminal geometry
server -> CP_END_AUTHENTICATION
```

Probe it twice and the difference is unmistakable: the server's public key is
ephemeral per session, while the salt is **stable per user** — a stored SRP salt,
with a deterministic decoy for users that do not exist so the protocol cannot be
used to enumerate accounts. A challenge nonce behaves in exactly the opposite
way.

Note also that `CP_END_AUTHENTICATION` is **not** proof of a successful login:
the device sends it even when it is about to reject the credentials, print
`Login failed` and close.

## Protocol notes

Things that cost real time to work out, in case they save someone else theirs.

**The header is asymmetric.** Outbound, offsets 14–17 are the session key then
the client type; inbound they are the server type then the session key. Parsing
symmetrically yields a session key of `0x0015` for every packet and silently
breaks the session.

**EC-SRP5 needs less than it sounds like.** Curve25519 in short Weierstrass form:

- `p = 2^255 - 19`, `a = 0x2aaa…984914a144`, `b = 0x7b42…7710c864`, cofactor 8
- the base point is `lift_x(9, even)` — note *even* y, so it is the negation of
  the usual Curve25519 generator
- `validator = sha256(salt || sha256("user:pass"))`
- `confirmation = sha256(H || montgomery_x((v·H + a_priv mod r) · (S + redp1(V))))`,
  where `H = sha256(client_pub || server_pub)`
- the session that follows is **not** encrypted, so a MAC-Telnet client needs no
  AES and no HMAC — only big integers and SHA-256

**The terminal is the other half of the problem.** Authenticating is not enough;
RouterOS will sit in silence until the client behaves like a terminal.

- It sends nothing at all until the client speaks — no banner, no prompt, just a
  retransmitted `END_AUTH`. Knock first with a bare Enter.
- It measures the terminal with `\r ESC[9999B \r ESC[9999B ESC Z "  " ESC[6n` and
  **blocks until answered**. Interactively your terminal emulator answers and the
  client just relays it; headless, nobody does, and the session looks hung.
- It takes the **cursor column from that reply as the terminal width**, ignoring
  `CP_TERM_WIDTH`. Answer column 1 and it wraps every single character.
- It emits the single-byte CSI `0x9b`, not `ESC[`. That byte is invalid UTF-8, so
  a UTF-8 decode silently replaces it with U+FFFD and every escape-stripping
  regex then misses it.
- It redraws the prompt the instant you press Enter, *before* running the
  command, so "read until prompt" finishes early and returns nothing. And it
  echoes each command **twice**: once as typed, once in the redrawn prompt.

## Two implementations

| | |
|---|---|
| `cmd/mactelnet` (Go) | The tool. Interactive, `-c` commands, `-d` discovery. Use this. |
| `MacTelnet.ps1` (PowerShell) | Runs on stock Windows PowerShell 5.1 with nothing installed, and can be streamed over SSH and executed from memory — for a machine you may not install on or write to. Non-interactive. `bin/mactelnet` drives it that way. |

Interactive mode relays bytes untouched with the local terminal in raw mode, so
colour, prefix completion and `Ctrl-C` all behave as they would over telnet.

## Tests

`go test ./...` needs no device. The packet layer is checked against bytes
captured from a real RouterOS 7.24.1 device (MACs replaced with the RFC 7042
documentation range), and EC-SRP5 against vectors generated from the reference
implementation below — including the published Curve25519 base point, which
anchors the curve arithmetic to a value from outside this project.

## Prior art and attribution

This project stands on other people's work.

- **[petrunetworking/MAC-Telnet-Routeros](https://github.com/petrunetworking/MAC-Telnet-Routeros)**
  (GPL-3.0) — the source of the EC-SRP5 login. Its `elliptic_curves.py` and
  `encryption.py` are where the curve parameters, `lift_x`, `redp1`, the
  validator and the confirmation derivation come from; this implementation is a
  port of that logic, and the test vectors here were generated by running it.
  Without it the modern login would have taken far longer to work out.
- **[haakonnessjoen/MAC-Telnet](https://github.com/haakonnessjoen/MAC-Telnet)**
  (GPL-2.0) — the reference implementation and the de facto protocol spec. The
  packet layout, the `ptype`/`cptype` constants, the retransmit ladder and the
  legacy MD5 formula are all documented by its `protocol.c` and `protocol.h`. It
  is Unix-only and speaks only the legacy login, but it is the canonical
  description of the transport.
- **[aouyar/MAC-Telnet](https://github.com/aouyar/MAC-Telnet)** — adds MAC-SSH,
  an extension to the Linux `mactelnetd` server. RouterOS does not implement it.
- **[jow-/mac-ssh-win32](https://github.com/jow-/mac-ssh-win32)** — a Windows
  MAC-SSH client in C. It targets MAC-SSH, so it refuses a standard MAC-Telnet
  auth challenge, but its adapter enumeration and Winsock handling are worth
  reading.

The only runtime dependency is [`golang.org/x/term`](https://pkg.go.dev/golang.org/x/term)
(BSD-3-Clause), for raw mode and the password prompt.

## Licence

GPL-3.0. The EC-SRP5 implementation is derived from
`petrunetworking/MAC-Telnet-Routeros`, which is GPL-3.0, so this project is too.
