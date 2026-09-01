<#
.SYNOPSIS
  MAC-Telnet client in pure PowerShell, for driving MikroTik devices whose IP
  management plane is dead but which are still alive at Layer 2.

.DESCRIPTION
  Speaks MNDP (UDP 5678) and MAC-Telnet (UDP 20561) over broadcast, so it needs
  no raw sockets, no admin rights and no installs -- System.Net.Sockets.UdpClient
  and System.Security.Cryptography.MD5 only. Windows PowerShell 5.1 compatible.

  Authentication is the legacy MD5 challenge: MD5(0x00 || password || salt).
  Devices that answer with an EC-SRP5 challenge are detected and rejected with a
  clear message rather than a hang.

.EXAMPLE
  .\MacTelnet.ps1 -Discover

.EXAMPLE
  .\MacTelnet.ps1 -Target 00:00:5E:00:53:01 -User admin -Password secret `
                  -Command '/system identity print','/ip address print'
#>
[CmdletBinding()]
param(
    [switch]$Discover,
    [string]$Target,
    [string]$User = 'admin',
    [string]$Password = '',
    [string[]]$Command,
    [string]$LocalIP,
    [string]$Broadcast = '255.255.255.255',
    [int]$TimeoutMs = 5000,
    [switch]$Raw,
    [switch]$SelfTest,
    [int]$ProbeAuth = 0,
    [string]$ProbeUser = '',
    [string]$TermType = 'dumb',
    [int]$AuthVariant = 0,
    [switch]$Legacy,
    [switch]$Trace
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# ---------------------------------------------------------------- constants --
$MT_PORT       = 20561
$MNDP_PORT     = 5678
$MT_HEADER_LEN = 22
$MT_CP_MAGIC   = [byte[]]@(0x56, 0x34, 0x12, 0xFF)
$MT_CLIENTTYPE = 0x0015

# Declared terminal geometry. Also used to answer the device's size probe -- see
# Invoke-MtTerminalReplies. A tall terminal keeps RouterOS from paginating.
$MT_TERM_WIDTH  = 250
$MT_TERM_HEIGHT = 200

# ptype
$PT_SESSIONSTART = 0
$PT_DATA         = 1
$PT_ACK          = 2
$PT_PING         = 4
$PT_PONG         = 5
$PT_END          = 255

# cptype
$CP_BEGINAUTH     = 0
$CP_ENCRYPTIONKEY = 1
$CP_PASSWORD      = 2
$CP_USERNAME      = 3
$CP_TERM_TYPE     = 4
$CP_TERM_WIDTH    = 5
$CP_TERM_HEIGHT   = 6
$CP_PACKET_ERROR  = 7
$CP_END_AUTH      = 9

# The reference client's retransmit ladder, in milliseconds.
$RETRANSMIT = @(15, 20, 30, 50, 90, 170, 330, 660, 1000)

# ------------------------------------------------------------------ helpers --
function ConvertTo-MacBytes {
    param([Parameter(Mandatory)][string]$Mac)
    $hex = ($Mac -replace '[^0-9A-Fa-f]', '')
    if ($hex.Length -ne 12) { throw "Not a MAC address: '$Mac'" }
    $b = New-Object byte[] 6
    for ($i = 0; $i -lt 6; $i++) { $b[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
    return , $b
}

function Format-Mac {
    param([byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString('X2') }) -join ':')
}

function Format-Hex {
    param([byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join ' ')
}

function Write-Be16 {
    param([byte[]]$Buf, [int]$Offset, [int]$Value)
    $Buf[$Offset]     = [byte](($Value -shr 8) -band 0xFF)
    $Buf[$Offset + 1] = [byte]($Value -band 0xFF)
}

function Read-Be16 {
    param([byte[]]$Buf, [int]$Offset)
    return ([int]$Buf[$Offset] -shl 8) -bor [int]$Buf[$Offset + 1]
}

function Write-Be32 {
    param([byte[]]$Buf, [int]$Offset, [uint32]$Value)
    $Buf[$Offset]     = [byte](($Value -shr 24) -band 0xFF)
    $Buf[$Offset + 1] = [byte](($Value -shr 16) -band 0xFF)
    $Buf[$Offset + 2] = [byte](($Value -shr 8) -band 0xFF)
    $Buf[$Offset + 3] = [byte]($Value -band 0xFF)
}

function Read-Be32 {
    param([byte[]]$Buf, [int]$Offset)
    return ([uint32]$Buf[$Offset] -shl 24) -bor ([uint32]$Buf[$Offset + 1] -shl 16) -bor `
           ([uint32]$Buf[$Offset + 2] -shl 8) -bor [uint32]$Buf[$Offset + 3]
}

function Get-LocalNic {
    <#  Pick the interface we will send from, so the source MAC in the header
        always matches the NIC the packet actually leaves by. #>
    param([string]$WantIP)

    $candidates = @()
    foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($nic.OperationalStatus -ne 'Up') { continue }
        if ($nic.NetworkInterfaceType -eq 'Loopback') { continue }
        $mac = $nic.GetPhysicalAddress().GetAddressBytes()
        if ($mac.Length -ne 6) { continue }
        foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
            if ($ua.Address.AddressFamily -ne 'InterNetwork') { continue }
            $candidates += [pscustomobject]@{
                Name = $nic.Name
                IP   = $ua.Address
                Mac  = $mac
            }
        }
    }
    if ($candidates.Count -eq 0) { throw 'No usable IPv4 interface found.' }

    if ($WantIP) {
        $hit = $candidates | Where-Object { $_.IP.ToString() -eq $WantIP } | Select-Object -First 1
        if (-not $hit) {
            throw ("No Up interface has IP {0}. Available: {1}" -f $WantIP,
                   (($candidates | ForEach-Object { $_.IP.ToString() }) -join ', '))
        }
        return $hit
    }
    return $candidates[0]
}

function New-BroadcastSocket {
    param([System.Net.IPAddress]$LocalAddress, [int]$LocalPort)
    $udp = New-Object System.Net.Sockets.UdpClient
    $udp.Client.SetSocketOption('Socket', 'ReuseAddress', $true)
    $udp.Client.Bind((New-Object System.Net.IPEndPoint($LocalAddress, $LocalPort)))
    $udp.EnableBroadcast = $true
    return $udp
}

# ------------------------------------------------------------- wire format --
function New-MtHeader {
    <#  OUTBOUND layout. Note offsets 14-17: session key first, then client type.
        The inbound layout swaps them -- see Read-MtHeader. #>
    param(
        [int]$Ptype,
        [byte[]]$SrcMac,
        [byte[]]$DstMac,
        [int]$SessionKey,
        [uint32]$Counter
    )
    $h = New-Object byte[] $MT_HEADER_LEN
    $h[0] = 1
    $h[1] = [byte]$Ptype
    [Array]::Copy($SrcMac, 0, $h, 2, 6)
    [Array]::Copy($DstMac, 0, $h, 8, 6)
    Write-Be16 -Buf $h -Offset 14 -Value $SessionKey
    Write-Be16 -Buf $h -Offset 16 -Value $MT_CLIENTTYPE
    Write-Be32 -Buf $h -Offset 18 -Value $Counter
    return , $h
}

function Read-MtHeader {
    <#  INBOUND layout. Offsets 14-17 are server type then session key -- the
        mirror image of the outbound header. Parsing symmetrically yields a
        session key of 0x0015 for every packet and silently breaks the session. #>
    param([byte[]]$Buf)
    if ($Buf.Length -lt $MT_HEADER_LEN) { return $null }
    $src = New-Object byte[] 6; [Array]::Copy($Buf, 2, $src, 0, 6)
    $dst = New-Object byte[] 6; [Array]::Copy($Buf, 8, $dst, 0, 6)
    $payload = New-Object byte[] ($Buf.Length - $MT_HEADER_LEN)
    if ($payload.Length -gt 0) { [Array]::Copy($Buf, $MT_HEADER_LEN, $payload, 0, $payload.Length) }
    return [pscustomobject]@{
        Version    = $Buf[0]
        Ptype      = $Buf[1]
        SrcMac     = $src
        DstMac     = $dst
        ServerType = (Read-Be16 -Buf $Buf -Offset 14)
        SessionKey = (Read-Be16 -Buf $Buf -Offset 16)
        Counter    = (Read-Be32 -Buf $Buf -Offset 18)
        Payload    = $payload
    }
}

function New-MtControl {
    param([int]$Cptype, [byte[]]$Data)
    if ($null -eq $Data) { $Data = New-Object byte[] 0 }
    $out = New-Object byte[] (9 + $Data.Length)
    [Array]::Copy($MT_CP_MAGIC, 0, $out, 0, 4)
    $out[4] = [byte]$Cptype
    Write-Be32 -Buf $out -Offset 5 -Value ([uint32]$Data.Length)
    if ($Data.Length -gt 0) { [Array]::Copy($Data, 0, $out, 9, $Data.Length) }
    return , $out
}

function Read-MtControl {
    <#  Walk a DATA payload and yield every control packet it carries.
        Returns @() for a payload that is plain terminal output. #>
    param([byte[]]$Payload)
    $out = @()
    $i = 0
    while ($i + 9 -le $Payload.Length) {
        if ($Payload[$i] -ne 0x56 -or $Payload[$i+1] -ne 0x34 -or
            $Payload[$i+2] -ne 0x12 -or $Payload[$i+3] -ne 0xFF) { break }
        $cptype = $Payload[$i + 4]
        $len    = [int](Read-Be32 -Buf $Payload -Offset ($i + 5))
        if ($len -lt 0 -or ($i + 9 + $len) -gt $Payload.Length) { break }
        $data = New-Object byte[] $len
        if ($len -gt 0) { [Array]::Copy($Payload, $i + 9, $data, 0, $len) }
        $out += [pscustomobject]@{ Cptype = $cptype; Data = $data }
        $i += 9 + $len
    }
    return ,$out
}

# ----------------------------------------------------------------- session --
function New-MtSession {
    param($Nic, [byte[]]$DstMac, [string]$BroadcastIP)
    $rnd = New-Object System.Random
    return [pscustomobject]@{
        Udp        = (New-BroadcastSocket -LocalAddress $Nic.IP -LocalPort $MT_PORT)
        Remote     = (New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($BroadcastIP), $MT_PORT))
        SrcMac     = $Nic.Mac
        DstMac     = $DstMac
        LocalIP    = $Nic.IP
        SessionKey = $rnd.Next(1, 65534)
        OutCounter = [uint32]0
        InCounter  = [uint32]0
        LastAck    = [int64](-1)
        Bytes      = (New-Object System.Collections.Generic.List[byte])
        Closed     = $false
        AnsweredDsr = 0
        AnsweredDa  = 0
    }
}

function Send-MtRaw {
    param($S, [int]$Ptype, [byte[]]$Payload, [uint32]$Counter)
    if ($null -eq $Payload) { $Payload = New-Object byte[] 0 }
    $hdr = New-MtHeader -Ptype $Ptype -SrcMac $S.SrcMac -DstMac $S.DstMac `
                        -SessionKey $S.SessionKey -Counter $Counter
    $pkt = New-Object byte[] ($hdr.Length + $Payload.Length)
    [Array]::Copy($hdr, 0, $pkt, 0, $hdr.Length)
    if ($Payload.Length -gt 0) { [Array]::Copy($Payload, 0, $pkt, $hdr.Length, $Payload.Length) }
    [void]$S.Udp.Send($pkt, $pkt.Length, $S.Remote)
    Write-Verbose ("-> ptype={0} counter={1} len={2}" -f $Ptype, $Counter, $Payload.Length)
}

function Receive-MtOnce {
    <#  Wait up to $WaitMs for one packet addressed to this session, doing all
        the protocol bookkeeping: ACK every DATA immediately (an un-ACKed packet
        triggers the server's retransmit ladder and you drown in duplicates),
        answer PING, note END, and suppress duplicates by counter.
        Returns $null on timeout. #>
    param($S, [int]$WaitMs)

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)

    while ($sw.ElapsedMilliseconds -lt $WaitMs) {
        if ($S.Udp.Available -le 0) { Start-Sleep -Milliseconds 5; continue }

        $buf = $S.Udp.Receive([ref]$ep)
        $pkt = Read-MtHeader -Buf $buf
        if ($null -eq $pkt) { continue }

        # A socket bound to the broadcast port hears its own broadcasts, and the
        # device answers on the same port -- so filter on the header, not the IP.
        if ($pkt.Version -ne 1) { continue }
        if ($pkt.SessionKey -ne $S.SessionKey) { continue }
        if ((Format-Mac $pkt.DstMac) -ne (Format-Mac $S.SrcMac)) { continue }
        if ((Format-Mac $pkt.SrcMac) -eq (Format-Mac $S.SrcMac)) { continue }

        Write-Verbose ("<- ptype={0} counter={1} len={2}" -f $pkt.Ptype, $pkt.Counter, $pkt.Payload.Length)
        if ($script:MtTrace) {
            $desc = switch ([int]$pkt.Ptype) { 0 {'SESSIONSTART'} 1 {'DATA'} 2 {'ACK'} 4 {'PING'} 5 {'PONG'} 255 {'END'} default {"ptype$($pkt.Ptype)"} }
            Write-Host ("  <- {0,-12} counter={1,-6} len={2}" -f $desc, $pkt.Counter, $pkt.Payload.Length)
            if ($pkt.Payload.Length -gt 0) {
                foreach ($cp in (Read-MtControl -Payload $pkt.Payload)) {
                    Write-Host ("       control cptype={0} len={1} {2}" -f $cp.Cptype, $cp.Data.Length, (Format-Hex $cp.Data))
                }
                $show = [Math]::Min($pkt.Payload.Length, 96)
                $head = New-Object byte[] $show
                [Array]::Copy($pkt.Payload, 0, $head, 0, $show)
                Write-Host ("       raw {0}" -f (Format-Hex $head))
                Write-Host ("       txt {0}" -f (([System.Text.Encoding]::ASCII.GetString($head)) -replace '[^\x20-\x7e]', '.'))
            }
        }

        $fresh = $true
        switch ([int]$pkt.Ptype) {
            $PT_ACK {
                if ([int64]$pkt.Counter -gt $S.LastAck) { $S.LastAck = [int64]$pkt.Counter }
            }
            $PT_DATA {
                Send-MtRaw -S $S -Ptype $PT_ACK -Payload $null `
                           -Counter ([uint32]($pkt.Counter + $pkt.Payload.Length))
                if ($pkt.Counter -lt $S.InCounter) {
                    $fresh = $false          # retransmit: ACKed above, not re-read
                } else {
                    $S.InCounter = [uint32]($pkt.Counter + $pkt.Payload.Length)
                }
            }
            $PT_PING {
                Send-MtRaw -S $S -Ptype $PT_PONG -Payload $pkt.Payload -Counter $pkt.Counter
            }
            $PT_END {
                $S.Closed = $true
            }
        }
        Add-Member -InputObject $pkt -NotePropertyName Fresh -NotePropertyValue $fresh -Force
        return $pkt
    }
    return $null
}

function Send-MtReliable {
    <#  Send a DATA packet and walk the retransmit ladder until the server ACKs
        past it. Packets received while waiting are handled by Receive-MtOnce and
        collected for the caller. #>
    param($S, [byte[]]$Payload, [int]$TimeoutMs)

    $expected = [int64]$S.OutCounter + $Payload.Length
    $collected = @()
    Send-MtRaw -S $S -Ptype $PT_DATA -Payload $Payload -Counter $S.OutCounter

    $total = [System.Diagnostics.Stopwatch]::StartNew()
    $i = 0
    while ($S.LastAck -lt $expected) {
        # Check the clock first: a device retransmitting its own challenge keeps
        # handing us packets, and testing the timeout only on an empty receive
        # would let that pin this loop forever.
        if ($total.ElapsedMilliseconds -gt $TimeoutMs) {
            throw ("No ACK for a DATA packet after {0} ms -- device stopped answering." -f $TimeoutMs)
        }
        $wait = $RETRANSMIT[[Math]::Min($i, $RETRANSMIT.Length - 1)]
        $pkt = Receive-MtOnce -S $S -WaitMs $wait
        if ($null -ne $pkt) {
            if ($pkt.Ptype -eq $PT_DATA -and $pkt.Fresh) { $collected += , $pkt.Payload }
            continue
        }
        Send-MtRaw -S $S -Ptype $PT_DATA -Payload $Payload -Counter $S.OutCounter
        $i++
    }
    $S.OutCounter = [uint32]$expected
    return , $collected
}

function Start-MtSession {
    param($S, [int]$TimeoutMs)
    Send-MtRaw -S $S -Ptype $PT_SESSIONSTART -Payload $null -Counter $S.OutCounter
    $total = [System.Diagnostics.Stopwatch]::StartNew()
    $i = 0
    while ($S.LastAck -lt 0) {
        $wait = $RETRANSMIT[[Math]::Min($i, $RETRANSMIT.Length - 1)]
        [void](Receive-MtOnce -S $S -WaitMs $wait)
        if ($S.LastAck -ge 0) { break }
        if ($total.ElapsedMilliseconds -gt $TimeoutMs) {
            throw ("No SESSIONSTART ACK from {0} after {1} ms -- nothing answered, so no password was ever sent. Check the MAC first (run -Discover), then that mac-server is enabled and this box is on the device's L2 segment. A wrong password fails later, and says so." -f (Format-Mac $S.DstMac), $TimeoutMs)
        }
        Send-MtRaw -S $S -Ptype $PT_SESSIONSTART -Payload $null -Counter $S.OutCounter
        $i++
    }
}

function Close-MtSession {
    param($S)
    try {
        if (-not $S.Closed) {
            Send-MtRaw -S $S -Ptype $PT_END -Payload $null -Counter $S.OutCounter
        }
    } catch { }
    try { $S.Udp.Close() } catch { }
}

# -------------------------------------------------------------------- auth --
function New-MtPasswordHash {
    <#  The legacy MAC-Telnet challenge: 0x00 || MD5(0x00 || password || salt),
        17 bytes on the wire. That is variant 0, straight from the reference
        client's send_auth(). The others exist only to test what a device that
        rejects a known-good credential actually wants; see -AuthVariant. #>
    param([string]$Password, [byte[]]$Salt, [int]$Variant = 0)

    $pw = [System.Text.Encoding]::UTF8.GetBytes($Password)
    $parts = New-Object System.Collections.Generic.List[byte]
    switch ($Variant) {
        2 { $parts.AddRange($pw); $parts.AddRange($Salt) }                       # no leading 0
        3 { $parts.AddRange($Salt); $parts.AddRange($pw) }                       # salt first
        default { $parts.Add(0); $parts.AddRange($pw); $parts.AddRange($Salt) }  # reference
    }

    $md5 = [System.Security.Cryptography.MD5]::Create()
    try { $digest = $md5.ComputeHash($parts.ToArray()) } finally { $md5.Dispose() }

    if ($Variant -eq 4) { return , $digest }   # bare 16-byte digest, no 0x00 prefix

    $out = New-Object byte[] 17
    $out[0] = 0
    [Array]::Copy($digest, 0, $out, 1, 16)
    return , $out
}

function Add-MtPayload {
    <#  Append a DATA payload to the terminal buffer, dropping any control
        packets riding at its head. The device keeps sending the odd one after
        login (END_AUTH), and decoding those as text spits the raw 56 34 12 ff
        magic into the output. #>
    param($S, [byte[]]$Payload)
    $i = 0
    while ($i + 9 -le $Payload.Length -and
           $Payload[$i] -eq 0x56 -and $Payload[$i+1] -eq 0x34 -and
           $Payload[$i+2] -eq 0x12 -and $Payload[$i+3] -eq 0xFF) {
        $len = [int](Read-Be32 -Buf $Payload -Offset ($i + 5))
        if ($len -lt 0 -or ($i + 9 + $len) -gt $Payload.Length) { break }
        $i += 9 + $len
    }
    if ($i -lt $Payload.Length) {
        $rest = New-Object byte[] ($Payload.Length - $i)
        [Array]::Copy($Payload, $i, $rest, 0, $rest.Length)
        $S.Bytes.AddRange($rest)
    }
}

# Latin-1, not UTF-8: it maps every byte 1:1 to a char. RouterOS emits the
# single-byte CSI 0x9b, which is invalid UTF-8 -- decoding as UTF-8 silently
# turns it into U+FFFD, and the escape stripper then never matches it.
$MT_TERM_ENCODING = [System.Text.Encoding]::GetEncoding('iso-8859-1')

function Get-MtText {
    param($S)
    return $MT_TERM_ENCODING.GetString($S.Bytes.ToArray())
}

function Clear-MtAnsi {
    param([string]$Text)
    $t = $Text -replace "\x1b\[[0-9;?]*[ -/]*[@-~]", ''   # CSI sequences
    $t = $t -replace "\x9b[0-9;?]*[ -/]*[@-~]", ''        # ...and the single-byte CSI form RouterOS uses
    $t = $t -replace "\x1b\][^\x07\x1b]*(\x07|\x1b\\)", '' # OSC sequences
    $t = $t -replace "\x1b[@-Z\\-_]", ''                   # remaining escapes
    $t = $t -replace "\r\n", "`n"
    $t = $t -replace "\r", "`n"
    $t = $t -replace "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", ''
    return $t
}

$PROMPT_RE = [regex]"\[[^\]\r\n]+@[^\]\r\n]+\]\s*>\s*$"
$PAGER_RE  = [regex]"--\s*\[Q quit\|D dump\|up\|down\]"

function Invoke-MtTerminalReplies {
    <#  RouterOS measures the terminal by driving the cursor to the bottom and
        asking where it ended up:

            \r ESC[9999B \r ESC[9999B ESC Z  ESC[6n

        Interactively the user's terminal emulator answers these and the client
        merely relays the reply. Headless there is nobody to answer, so RouterOS
        waits forever and retransmits -- which looks exactly like a hung session.
        We answer on the terminal's behalf: a cursor position report giving the
        height we declared, and a VT100-ish device attributes string. #>
    param($S, [int]$TimeoutMs)

    $esc = [char]27
    $raw = $MT_TERM_ENCODING.GetString($S.Bytes.ToArray())

    $csi = [char]0x9b
    $dsr = ([regex]::Matches($raw, [regex]::Escape("$esc[") + '6n')).Count +
           ([regex]::Matches($raw, [regex]::Escape("$csi") + '6n')).Count
    while ($S.AnsweredDsr -lt $dsr) {
        # RouterOS takes the row as the height and, empirically, the COLUMN as the
        # width -- report column 1 and it wraps every character, report 3 and it
        # wraps every three. So answer with the geometry we want, not with where
        # a real terminal's cursor would actually be.
        Send-MtText -S $S -Text ("$esc[{0};{1}R" -f $MT_TERM_HEIGHT, $MT_TERM_WIDTH) -TimeoutMs $TimeoutMs
        $S.AnsweredDsr++
    }

    $da = ([regex]::Matches($raw, [regex]::Escape("${esc}Z"))).Count +
          ([regex]::Matches($raw, [regex]::Escape("$esc[") + 'c')).Count +
          ([regex]::Matches($raw, [regex]::Escape("$csi") + 'c')).Count
    while ($S.AnsweredDa -lt $da) {
        Send-MtText -S $S -Text "$esc[?1;2c" -TimeoutMs $TimeoutMs
        $S.AnsweredDa++
    }
}

function Read-MtUntil {
    <#  Pump packets until the accumulated terminal text satisfies $Pattern, or
        we time out. Answers the two things RouterOS injects unasked: the licence
        question and the pager.

        -SettleMs guards against a false finish: RouterOS redraws the prompt the
        moment you press Enter, *before* running the command, so matching the
        prompt alone returns an empty result. Requiring the line to have been
        quiet for a while as well means we only stop at the prompt that follows
        the output. #>
    param($S, [regex]$Pattern, [int]$TimeoutMs, [int]$SettleMs = 0)

    $total = [System.Diagnostics.Stopwatch]::StartNew()
    $quiet = [System.Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        Invoke-MtTerminalReplies -S $S -TimeoutMs $TimeoutMs
        $text = Clear-MtAnsi (Get-MtText -S $S)
        if ($Pattern.IsMatch($text) -and $quiet.ElapsedMilliseconds -ge $SettleMs) { return $text }

        if ($text -match 'software license') {
            [void](Send-MtText -S $S -Text "n`r`n" -TimeoutMs $TimeoutMs)
            $S.Bytes.Clear()
            $total.Restart()
            continue
        }
        if ($PAGER_RE.IsMatch($text)) {
            [void](Send-MtText -S $S -Text ' ' -TimeoutMs $TimeoutMs)
            continue
        }
        if ($S.Closed) {
            if ($text -match 'Login failed|incorrect username or password') {
                throw 'Login failed: incorrect username or password (or the user has no telnet policy).'
            }
            throw ("Device closed the session. Last output:`n{0}" -f $text.Trim())
        }
        if ($total.ElapsedMilliseconds -gt $TimeoutMs) {
            throw ("Timed out after {0} ms waiting for /{1}/. Got:`n{2}" -f $TimeoutMs, $Pattern, $text.Trim())
        }

        $pkt = Receive-MtOnce -S $S -WaitMs 200
        if ($null -ne $pkt -and $pkt.Ptype -eq $PT_DATA -and $pkt.Fresh -and $pkt.Payload.Length -gt 0) {
            Add-MtPayload -S $S -Payload $pkt.Payload
            $total.Restart()
            $quiet.Restart()
        }
    }
}

function Send-MtText {
    param($S, [string]$Text, [int]$TimeoutMs)
    $bytes = $MT_TERM_ENCODING.GetBytes($Text)
    $collected = Send-MtReliable -S $S -Payload $bytes -TimeoutMs $TimeoutMs
    foreach ($p in $collected) { if ($p.Length -gt 0) { Add-MtPayload -S $S -Payload $p } }
}

function Get-MtChallenge {
    <#  Send CP_BEGIN_AUTHENTICATION and return the CP_ENCRYPTION_KEY payload.
        -PreUser prepends a CP_USERNAME, so the server knows who is asking before
        it answers. That distinguishes a challenge nonce from an SRP salt: an SRP
        server hands out a random decoy salt for a username it has not been told
        (or does not know), and a stable per-user one once it has. #>
    param($S, [int]$TimeoutMs, [string]$PreUser)

    $req = New-Object System.Collections.Generic.List[byte]
    if ($PreUser) {
        $req.AddRange((New-MtControl -Cptype $CP_USERNAME -Data ([System.Text.Encoding]::UTF8.GetBytes($PreUser))))
    }
    $req.AddRange((New-MtControl -Cptype $CP_BEGINAUTH -Data $null))
    $collected = Send-MtReliable -S $S -Payload $req.ToArray() -TimeoutMs $TimeoutMs

    $salt = $null
    foreach ($p in $collected) {
        foreach ($cp in (Read-MtControl -Payload $p)) {
            if ($cp.Cptype -eq $CP_ENCRYPTIONKEY) { $salt = $cp.Data }
        }
    }
    $total = [System.Diagnostics.Stopwatch]::StartNew()
    while ($null -eq $salt) {
        if ($total.ElapsedMilliseconds -gt $TimeoutMs) {
            throw 'No CP_ENCRYPTION_KEY from the device -- it ACKed the session but never offered a challenge.'
        }
        $pkt = Receive-MtOnce -S $S -WaitMs 200
        if ($null -ne $pkt -and $pkt.Ptype -eq $PT_DATA -and $pkt.Fresh) {
            foreach ($cp in (Read-MtControl -Payload $pkt.Payload)) {
                if ($cp.Cptype -eq $CP_ENCRYPTIONKEY) { $salt = $cp.Data }
            }
        }
    }
    return , $salt
}

function Invoke-MtLoginLegacy {
    <#  The pre-6.43 MD5 challenge. RouterOS 7 still performs this handshake but
        can no longer satisfy it -- see "The MD5 dead end" in the README -- so it
        is kept only for genuinely old devices. #>
    param($S, [string]$User, [string]$Password, [int]$TimeoutMs,
          [string]$Term = 'dumb', [int]$Variant = 0)

    $salt = Get-MtChallenge -S $S -TimeoutMs $TimeoutMs

    # 3. a 16-byte challenge is the legacy MD5 scheme; anything longer carries an
    #    EC-SRP5 public key, which this client deliberately does not implement.
    if ($salt.Length -ne 16) {
        throw ("Device sent a {0}-byte challenge, not the 16-byte MD5 one. That is EC-SRP5 (Curve25519) auth, which this client does not implement. Use petrunetworking/MAC-Telnet-Routeros under an embedded Python instead." -f $salt.Length)
    }
    Write-Verbose ("challenge salt: {0}" -f (Format-Hex $salt))

    # 4. one DATA packet carrying password, username and terminal geometry
    $width  = New-Object byte[] 2
    $height = New-Object byte[] 2
    [Array]::Copy([BitConverter]::GetBytes([uint16]250), 0, $width, 0, 2)    # LE
    [Array]::Copy([BitConverter]::GetBytes([uint16]1000), 0, $height, 0, 2)  # LE

    $pwCp   = New-MtControl -Cptype $CP_PASSWORD -Data (New-MtPasswordHash -Password $Password -Salt $salt -Variant $Variant)
    $userCp = New-MtControl -Cptype $CP_USERNAME -Data ([System.Text.Encoding]::UTF8.GetBytes($User))

    $auth = New-Object System.Collections.Generic.List[byte]
    if ($Variant -eq 1) {
        $auth.AddRange($userCp); $auth.AddRange($pwCp)    # username first
    } else {
        $auth.AddRange($pwCp); $auth.AddRange($userCp)    # reference order
    }
    $auth.AddRange((New-MtControl -Cptype $CP_TERM_TYPE   -Data ([System.Text.Encoding]::UTF8.GetBytes($Term))))
    $auth.AddRange((New-MtControl -Cptype $CP_TERM_WIDTH  -Data $width))
    $auth.AddRange((New-MtControl -Cptype $CP_TERM_HEIGHT -Data $height))

    $collected = Send-MtReliable -S $S -Payload $auth.ToArray() -TimeoutMs $TimeoutMs
    foreach ($p in $collected) { if ($p.Length -gt 0) { Add-MtPayload -S $S -Payload $p } }

    # 5. banner, then the prompt
    $banner = Read-MtUntil -S $S -Pattern $PROMPT_RE -TimeoutMs $TimeoutMs
    if ($banner -match 'Login failed|incorrect username or password|invalid user') {
        throw 'Login failed: incorrect username or password (or the user has no telnet policy).'
    }
    $S.Bytes.Clear()
    return $banner
}

function Invoke-MtLoginModern {
    <#  EC-SRP5, the scheme RouterOS 6.43+ actually accepts.

          client -> CP_BEGIN_AUTHENTICATION (empty)
                    CP_ENCRYPTION_KEY  username || 0x00 || pubkey(32) || parity(1)
          server -> CP_ENCRYPTION_KEY  server_pubkey(32) || parity(1) || salt(16)
          client -> CP_PASSWORD        confirmation(32)
                    CP_USERNAME, CP_TERM_TYPE, CP_TERM_WIDTH, CP_TERM_HEIGHT
          server -> CP_END_AUTHENTICATION, then terminal output

        The username has to travel in that first packet: without it the server
        cannot look up a salt, and answers with a short random blob instead. #>
    param($S, [string]$User, [string]$Password, [int]$TimeoutMs, [string]$Term = 'dumb')

    $priv = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
    try { $rng.GetBytes($priv) } finally { $rng.Dispose() }

    $kp = New-EcPublicKey -Private $priv
    $pub = $kp[0]
    $parity = $kp[1]

    $userBytes = [System.Text.Encoding]::UTF8.GetBytes($User)
    $keyData = New-Object System.Collections.Generic.List[byte]
    $keyData.AddRange($userBytes)
    $keyData.Add(0)
    $keyData.AddRange($pub)
    $keyData.Add([byte]$parity)

    $hello = New-Object System.Collections.Generic.List[byte]
    $hello.AddRange((New-MtControl -Cptype $CP_BEGINAUTH -Data $null))
    $hello.AddRange((New-MtControl -Cptype $CP_ENCRYPTIONKEY -Data $keyData.ToArray()))

    $collected = Send-MtReliable -S $S -Payload $hello.ToArray() -TimeoutMs $TimeoutMs

    $reply = $null
    foreach ($p in $collected) {
        foreach ($cp in (Read-MtControl -Payload $p)) {
            if ($cp.Cptype -eq $CP_ENCRYPTIONKEY) { $reply = $cp.Data }
        }
    }
    $total = [System.Diagnostics.Stopwatch]::StartNew()
    while ($null -eq $reply) {
        if ($S.Closed) { throw 'Device closed the session before answering the key exchange.' }
        if ($total.ElapsedMilliseconds -gt $TimeoutMs) {
            throw 'No CP_ENCRYPTION_KEY reply to the key exchange.'
        }
        $pkt = Receive-MtOnce -S $S -WaitMs 200
        if ($null -ne $pkt -and $pkt.Ptype -eq $PT_DATA -and $pkt.Fresh) {
            foreach ($cp in (Read-MtControl -Payload $pkt.Payload)) {
                if ($cp.Cptype -eq $CP_ENCRYPTIONKEY) { $reply = $cp.Data }
            }
        }
    }

    if ($reply.Length -lt 49) {
        throw ("Server answered the key exchange with only {0} bytes. That is its 'no such user' reply -- check the username (`"{1}`"). A device speaking the old MD5 scheme also lands here; try -Legacy." -f $reply.Length, $User)
    }
    $serverPub = New-Object byte[] 32
    [Array]::Copy($reply, 0, $serverPub, 0, 32)
    $serverParity = [int]$reply[32]
    $salt = New-Object byte[] 16
    [Array]::Copy($reply, 33, $salt, 0, 16)
    Write-Verbose ("server pubkey {0} parity={1} salt {2}" -f (Format-Hex $serverPub), $serverParity, (Format-Hex $salt))

    $confirmation = New-MtConfirmation -User $User -Password $Password -Salt $salt `
                        -ClientPrivate $priv -ClientPublic $pub `
                        -ServerPublic $serverPub -ServerParity $serverParity

    $width  = New-Object byte[] 2
    $height = New-Object byte[] 2
    [Array]::Copy([BitConverter]::GetBytes([uint16]$MT_TERM_WIDTH), 0, $width, 0, 2)
    [Array]::Copy([BitConverter]::GetBytes([uint16]$MT_TERM_HEIGHT), 0, $height, 0, 2)

    $auth = New-Object System.Collections.Generic.List[byte]
    $auth.AddRange((New-MtControl -Cptype $CP_PASSWORD    -Data $confirmation))
    $auth.AddRange((New-MtControl -Cptype $CP_USERNAME    -Data $userBytes))
    $auth.AddRange((New-MtControl -Cptype $CP_TERM_TYPE   -Data ([System.Text.Encoding]::UTF8.GetBytes($Term))))
    $auth.AddRange((New-MtControl -Cptype $CP_TERM_WIDTH  -Data $width))
    $auth.AddRange((New-MtControl -Cptype $CP_TERM_HEIGHT -Data $height))

    $collected = Send-MtReliable -S $S -Payload $auth.ToArray() -TimeoutMs $TimeoutMs
    $endAuth = $false
    foreach ($p in $collected) {
        foreach ($cp in (Read-MtControl -Payload $p)) {
            if ($cp.Cptype -eq $CP_END_AUTH) { $endAuth = $true }
        }
        if ($p.Length -gt 0) { Add-MtPayload -S $S -Payload $p }
    }

    # CP_END_AUTHENTICATION is the device saying the proof checked out. Wait for
    # it -- but do NOT then wait for a prompt: RouterOS sends nothing further
    # until the client speaks again, and it keeps retransmitting END_AUTH the
    # whole time. The first command is what moves the session on.
    $total = [System.Diagnostics.Stopwatch]::StartNew()
    while (-not $endAuth) {
        $text = Clear-MtAnsi (Get-MtText -S $S)
        if ($text -match 'Login failed|incorrect username or password|invalid user') {
            throw 'Login failed: the device rejected the EC-SRP5 proof (wrong password).'
        }
        if ($S.Closed) {
            throw ('Device closed the session during authentication. Last output: ' + $text.Trim())
        }
        if ($total.ElapsedMilliseconds -gt $TimeoutMs) {
            throw ('No CP_END_AUTHENTICATION within {0} ms. Output so far: {1}' -f $TimeoutMs, $text.Trim())
        }
        $pkt = Receive-MtOnce -S $S -WaitMs 200
        if ($null -ne $pkt -and $pkt.Ptype -eq $PT_DATA -and $pkt.Fresh) {
            foreach ($cp in (Read-MtControl -Payload $pkt.Payload)) {
                if ($cp.Cptype -eq $CP_END_AUTH) { $endAuth = $true }
            }
            if ($pkt.Payload.Length -gt 0) { Add-MtPayload -S $S -Payload $pkt.Payload }
        }
    }
    Write-Verbose 'CP_END_AUTHENTICATION received -- authenticated'

    # RouterOS does not start its terminal until the client speaks: no probe, no
    # banner, no prompt. So knock once with a bare Enter, then absorb the size
    # negotiation, the logo and the first prompt. Skip this and the first command
    # is swallowed by the setup and its output never appears.
    Send-MtText -S $S -Text "`r`n" -TimeoutMs $TimeoutMs
    $banner = Read-MtUntil -S $S -Pattern $PROMPT_RE -TimeoutMs $TimeoutMs -SettleMs 500
    $S.Bytes.Clear()
    return $banner
}

function Invoke-MtCommand {
    param($S, [string]$Line, [int]$TimeoutMs, [switch]$RawOutput)

    $S.Bytes.Clear()
    Send-MtText -S $S -Text ($Line + "`r`n") -TimeoutMs $TimeoutMs
    $text = Read-MtUntil -S $S -Pattern $PROMPT_RE -TimeoutMs $TimeoutMs -SettleMs 500
    if ($RawOutput) { return $text }

    $text = $PAGER_RE.Replace($text, '')
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.AddRange([string[]]($text -split "`n"))

    # Drop everything up to and including the echo of the command. It is not
    # necessarily the first line, and RouterOS redraws the prompt in front of it,
    # so match on "ends with the command" rather than on equality or position.
    # There are TWO echoes: the characters as they are "typed", and then the
    # prompt redrawn with the command after it. Walk the leading block -- blanks
    # and echoes only -- and keep the LAST echo, so both go.
    $echo = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $t = $lines[$i].TrimEnd()
        if ($t.EndsWith($Line.Trim())) { $echo = $i; continue }
        if ($t.Trim() -eq '') { continue }
        break
    }
    if ($echo -ge 0) { $lines.RemoveRange(0, $echo + 1) }

    # Trailing prompt, plus the blank lines around it. Trim the blanks first:
    # the split leaves an empty element at the end, which would otherwise stop
    # the loop before it ever reaches the prompt.
    while ($lines.Count -gt 0 -and
           ($lines[$lines.Count - 1].Trim() -eq '' -or $PROMPT_RE.IsMatch($lines[$lines.Count - 1]))) {
        $lines.RemoveAt($lines.Count - 1)
    }
    # Trim newlines only: RouterOS aligns its output with leading spaces, and a
    # bare Trim() would strip the first row's indentation and misalign it.
    return (($lines -join "`n").Trim("`r", "`n"))
}

# ------------------------------------------------- EC-SRP5 (modern RouterOS) --
# RouterOS 6.43+ replaced the MD5 challenge with an EC-SRP5 exchange over
# Curve25519 in short Weierstrass form. Everything below needs only BigInteger
# and SHA-256 -- the session itself is not encrypted, so no AES or HMAC.
# Ported from petrunetworking/MAC-Telnet-Routeros (elliptic_curves.py), and
# checked against vectors generated from it; see -SelfTest.

$EC = @{
    P    = [System.Numerics.BigInteger]::Parse('07fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed', 'AllowHexSpecifier')
    R    = [System.Numerics.BigInteger]::Parse('01000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed', 'AllowHexSpecifier')
    A    = [System.Numerics.BigInteger]::Parse('02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144', 'AllowHexSpecifier')
    B    = [System.Numerics.BigInteger]::Parse('07b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864', 'AllowHexSpecifier')
    MONT = [System.Numerics.BigInteger]486662
}

function Get-EcMod {
    param([System.Numerics.BigInteger]$Value)
    $m = $Value % $EC.P
    if ($m.Sign -lt 0) { $m = $m + $EC.P }
    return $m
}

function Get-EcInverse {
    param([System.Numerics.BigInteger]$Value)
    # p is prime, so a^(p-2) is the modular inverse
    return [System.Numerics.BigInteger]::ModPow((Get-EcMod $Value), $EC.P - 2, $EC.P)
}

function ConvertTo-EcBig {
    <#  Big-endian bytes -> BigInteger, forced positive. #>
    param([byte[]]$Bytes)
    $le = New-Object byte[] ($Bytes.Length + 1)
    for ($i = 0; $i -lt $Bytes.Length; $i++) { $le[$i] = $Bytes[$Bytes.Length - 1 - $i] }
    $le[$Bytes.Length] = 0
    return New-Object System.Numerics.BigInteger(, $le)
}

function ConvertFrom-EcBig {
    <#  BigInteger -> fixed-width big-endian bytes. #>
    param([System.Numerics.BigInteger]$Value, [int]$Length = 32)
    $le = $Value.ToByteArray()
    $out = New-Object byte[] $Length
    $n = [Math]::Min($le.Length, $Length)
    for ($i = 0; $i -lt $n; $i++) { $out[$Length - 1 - $i] = $le[$i] }
    return , $out
}

function Get-EcSqrt {
    <#  Square roots of $A2 mod p. p = 2^255-19 is 5 mod 8, so the Ed25519 trick
        applies and no Tonelli-Shanks loop is needed. Returns @() if $A2 is not
        a quadratic residue. #>
    param([System.Numerics.BigInteger]$A2)
    $a = Get-EcMod $A2
    if ($a.IsZero) { return , @([System.Numerics.BigInteger]::Zero) }

    $cand = [System.Numerics.BigInteger]::ModPow($a, ($EC.P + 3) / 8, $EC.P)
    if ((Get-EcMod ($cand * $cand)) -ne $a) {
        # multiply by sqrt(-1) = 2^((p-1)/4)
        $i = [System.Numerics.BigInteger]::ModPow([System.Numerics.BigInteger]2, ($EC.P - 1) / 4, $EC.P)
        $cand = Get-EcMod ($cand * $i)
        if ((Get-EcMod ($cand * $cand)) -ne $a) { return , @() }
    }
    return , @($cand, (Get-EcMod ($EC.P - $cand)))
}

function New-EcPoint {
    param($X, $Y, [switch]$Infinity)
    return [pscustomobject]@{ X = $X; Y = $Y; Inf = [bool]$Infinity }
}

function Add-EcPoint {
    <#  Affine addition on y^2 = x^3 + ax + b. #>
    param($P1, $P2)
    if ($P1.Inf) { return $P2 }
    if ($P2.Inf) { return $P1 }

    if ($P1.X -eq $P2.X) {
        if ((Get-EcMod ($P1.Y + $P2.Y)).IsZero) {
            return (New-EcPoint -X ([System.Numerics.BigInteger]::Zero) -Y ([System.Numerics.BigInteger]::Zero) -Infinity)
        }
        # Literals go on the RIGHT: "[int] * [bigint]" finds no BigInteger
        # operator and silently degrades to double, wrecking the result.
        $num = Get-EcMod ($P1.X * $P1.X * 3 + $EC.A)
        $den = Get-EcInverse ($P1.Y * 2)
    } else {
        $num = Get-EcMod ($P2.Y - $P1.Y)
        $den = Get-EcInverse ($P2.X - $P1.X)
    }
    $lam = Get-EcMod ($num * $den)
    $x3  = Get-EcMod ($lam * $lam - $P1.X - $P2.X)
    $y3  = Get-EcMod ($lam * ($P1.X - $x3) - $P1.Y)
    return (New-EcPoint -X $x3 -Y $y3)
}

function Invoke-EcScalarMult {
    param([System.Numerics.BigInteger]$K, $Point)
    $result = New-EcPoint -X ([System.Numerics.BigInteger]::Zero) -Y ([System.Numerics.BigInteger]::Zero) -Infinity
    $addend = $Point
    $k = $K
    $two = [System.Numerics.BigInteger]2
    while ($k.Sign -gt 0) {
        if (-not $k.IsEven) { $result = Add-EcPoint $result $addend }
        $addend = Add-EcPoint $addend $addend
        # Explicit BigInteger division: "$k / 2" can be coerced through double.
        $k = [System.Numerics.BigInteger]::Divide($k, $two)
    }
    return $result
}

function Get-EcLiftX {
    <#  Montgomery x -> Weierstrass affine point with the requested y parity.
        Returns $null when x is not on the curve. #>
    param([System.Numerics.BigInteger]$X, [int]$Parity)
    $x = Get-EcMod $X
    $y2 = Get-EcMod ($x * $x * $x + $EC.MONT * $x * $x + $x)   # Montgomery curve
    $wx = Get-EcMod ($x + ($EC.MONT * (Get-EcInverse 3)))      # shift to Weierstrass
    $roots = Get-EcSqrt $y2
    if ($roots.Count -eq 0) { return $null }
    foreach ($y in $roots) {
        if ((($y % 2) -eq $Parity)) { return (New-EcPoint -X $wx -Y $y) }
    }
    return (New-EcPoint -X $wx -Y $roots[0])
}

function ConvertTo-EcMontgomery {
    <#  Weierstrass affine point -> Montgomery x (32 BE bytes) + y parity. #>
    param($Point)
    $conv = Get-EcMod ($EC.P - ($EC.MONT * (Get-EcInverse 3)))
    $x = Get-EcMod ($Point.X + $conv)
    return @((ConvertFrom-EcBig -Value $x -Length 32), [int]($Point.Y % 2))
}

function Get-EcBasePoint { return (Get-EcLiftX -X ([System.Numerics.BigInteger]9) -Parity 0) }

function New-EcPublicKey {
    <#  priv * G, as Montgomery x plus the y parity. #>
    param([byte[]]$Private)
    $k = ConvertTo-EcBig -Bytes $Private
    $pt = Invoke-EcScalarMult -K $k -Point (Get-EcBasePoint)
    return (ConvertTo-EcMontgomery -Point $pt)
}

function Get-Sha256 {
    param([byte[]]$Data)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return , $sha.ComputeHash($Data) } finally { $sha.Dispose() }
}

function Get-EcRedp1 {
    <#  Hash-to-point: hash until the value lifts onto the curve. #>
    param([byte[]]$Data, [int]$Parity)
    $x = Get-Sha256 -Data $Data
    while ($true) {
        $x2 = Get-Sha256 -Data $x
        $pt = Get-EcLiftX -X (ConvertTo-EcBig -Bytes $x2) -Parity $Parity
        if ($null -ne $pt) { return $pt }
        $x = ConvertFrom-EcBig -Value ((ConvertTo-EcBig -Bytes $x) + 1) -Length 32
    }
}

function New-MtValidator {
    <#  sha256(salt || sha256("user:pass")) #>
    param([string]$User, [string]$Password, [byte[]]$Salt)
    $inner = Get-Sha256 -Data ([System.Text.Encoding]::UTF8.GetBytes("$User`:$Password"))
    $buf = New-Object byte[] ($Salt.Length + $inner.Length)
    [Array]::Copy($Salt, 0, $buf, 0, $Salt.Length)
    [Array]::Copy($inner, 0, $buf, $Salt.Length, $inner.Length)
    return (Get-Sha256 -Data $buf)
}

function New-MtConfirmation {
    <#  The EC-SRP5 proof the server checks: it can only be produced by someone
        who knows the password, and it doubles as the shared-secret derivation. #>
    param([string]$User, [string]$Password, [byte[]]$Salt,
          [byte[]]$ClientPrivate, [byte[]]$ClientPublic,
          [byte[]]$ServerPublic, [int]$ServerParity)

    $validator = New-MtValidator -User $User -Password $Password -Salt $Salt
    $vPubX     = (New-EcPublicKey -Private $validator)[0]
    $vPoint    = Get-EcRedp1 -Data $vPubX -Parity 1

    $sPoint = Get-EcLiftX -X (ConvertTo-EcBig -Bytes $ServerPublic) -Parity $ServerParity
    if ($null -eq $sPoint) { throw 'Server public key is not a point on the curve.' }
    $sPoint = Add-EcPoint $sPoint $vPoint

    $both = New-Object byte[] ($ClientPublic.Length + $ServerPublic.Length)
    [Array]::Copy($ClientPublic, 0, $both, 0, $ClientPublic.Length)
    [Array]::Copy($ServerPublic, 0, $both, $ClientPublic.Length, $ServerPublic.Length)
    $pubkeysHashed = Get-Sha256 -Data $both

    $vh = (ConvertTo-EcBig -Bytes $validator) * (ConvertTo-EcBig -Bytes $pubkeysHashed)
    $vh = $vh + (ConvertTo-EcBig -Bytes $ClientPrivate)
    $vh = $vh % $EC.R
    if ($vh.Sign -lt 0) { $vh = $vh + $EC.R }

    $z = ConvertTo-EcMontgomery -Point (Invoke-EcScalarMult -K $vh -Point $sPoint)
    $zInput = $z[0]

    $final = New-Object byte[] ($pubkeysHashed.Length + $zInput.Length)
    [Array]::Copy($pubkeysHashed, 0, $final, 0, $pubkeysHashed.Length)
    [Array]::Copy($zInput, 0, $final, $pubkeysHashed.Length, $zInput.Length)
    return (Get-Sha256 -Data $final)
}

# -------------------------------------------------------------------- MNDP --
$MNDP_TLV = @{
    1  = 'MacAddress'; 5  = 'Identity';  7  = 'Version';   8  = 'Platform'
    10 = 'Uptime';     11 = 'SoftwareId'; 12 = 'Board';    14 = 'Unpack'
    15 = 'IPv6';       16 = 'Interface'; 17 = 'IPv4'
}

function Read-MndpPacket {
    param([byte[]]$Buf, [System.Net.IPAddress]$From)
    if ($Buf.Length -lt 8) { return $null }
    $out = [ordered]@{ From = $From.ToString() }
    $i = 4                                   # 4-byte MNDP header, then TLVs
    while ($i + 4 -le $Buf.Length) {
        $type = Read-Be16 -Buf $Buf -Offset $i
        $len  = Read-Be16 -Buf $Buf -Offset ($i + 2)
        $i += 4
        if ($len -lt 0 -or ($i + $len) -gt $Buf.Length) { break }
        $val = New-Object byte[] $len
        if ($len -gt 0) { [Array]::Copy($Buf, $i, $val, 0, $len) }
        $i += $len

        $name = $MNDP_TLV[[int]$type]
        if (-not $name) { $name = "Type$type" }
        switch ([int]$type) {
            1  { $out[$name] = (Format-Mac $val) }
            10 { if ($len -ge 4) { $out[$name] = [string][BitConverter]::ToUInt32($val, 0) } }
            17 { if ($len -ge 4) { $out[$name] = (New-Object System.Net.IPAddress(, $val)).ToString() } }
            default { $out[$name] = ([System.Text.Encoding]::UTF8.GetString($val) -replace '\x00', '') }
        }
    }
    return [pscustomobject]$out
}

function Invoke-MndpDiscover {
    param($Nic, [string]$BroadcastIP, [int]$TimeoutMs)

    $udp = New-BroadcastSocket -LocalAddress $Nic.IP -LocalPort $MNDP_PORT
    try {
        $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($BroadcastIP), $MNDP_PORT)
        $probe = New-Object byte[] 4
        [void]$udp.Send($probe, 4, $ep)

        $seen = @{}
        $results = @()
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $from = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        while ($sw.ElapsedMilliseconds -lt $TimeoutMs) {
            if ($udp.Available -le 0) { Start-Sleep -Milliseconds 20; continue }
            $buf = $udp.Receive([ref]$from)
            if ($from.Address.ToString() -eq $Nic.IP.ToString()) { continue }  # our own probe
            if ($buf.Length -le 4) { continue }
            $dev = Read-MndpPacket -Buf $buf -From $from.Address
            if ($null -eq $dev) { continue }
            $key = if ($dev.PSObject.Properties.Name -contains 'MacAddress') { $dev.MacAddress } else { $dev.From }
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $results += $dev
        }
        return , $results
    } finally {
        $udp.Close()
    }
}

# --------------------------------------------------------------- self-test --
function Invoke-MtSelfTest {
    $fail = 0
    function Assert-Equal($Name, $Expected, $Actual) {
        if ($Expected -eq $Actual) {
            Write-Host ("  ok    {0}" -f $Name)
        } else {
            Write-Host ("  FAIL  {0}`n          expected: {1}`n          actual:   {2}" -f $Name, $Expected, $Actual)
            $script:selfTestFailures++
        }
    }
    $script:selfTestFailures = 0
    Write-Host 'MacTelnet.ps1 self-test (no device needed)'

    $box = ConvertTo-MacBytes '00:00:5E:00:53:02'
    $cap = ConvertTo-MacBytes '00:00:5E:00:53:01'

    # the captured SESSIONSTART, byte for byte
    $hdr = New-MtHeader -Ptype $PT_SESSIONSTART -SrcMac $box -DstMac $cap -SessionKey 0x3a7c -Counter 0
    Assert-Equal 'outbound SESSIONSTART header' `
        '01 00 e4 3a 6e 19 00 10 b8 69 f4 d4 21 31 3a 7c 00 15 00 00 00 00' (Format-Hex $hdr)

    # the captured ACK: session key lives at offset 16 inbound, not 14
    $ack = [byte[]]@(0x01,0x02,0xb8,0x69,0xf4,0xd4,0x21,0x31,0xe4,0x3a,0x6e,0x19,0x00,0x10,
                     0x00,0x15,0x3a,0x7c,0x00,0x00,0x00,0x00)
    $p = Read-MtHeader -Buf $ack
    Assert-Equal 'inbound ptype'         2      ([int]$p.Ptype)
    Assert-Equal 'inbound server type'   0x0015 ([int]$p.ServerType)
    Assert-Equal 'inbound session key'   0x3a7c ([int]$p.SessionKey)
    Assert-Equal 'inbound src MAC'       '00:00:5E:00:53:01' (Format-Mac $p.SrcMac)

    # the captured CP_ENCRYPTION_KEY
    $cpbytes = [byte[]]@(0x56,0x34,0x12,0xff,0x01,0x00,0x00,0x00,0x10,
                         0xc1,0x88,0xce,0x48,0x87,0xc2,0xe0,0x4a,0x60,0x5c,0x8f,0xe0,0x1a,0xbc,0x41,0x84)
    $cps = Read-MtControl -Payload $cpbytes
    Assert-Equal 'control packet count'  1  $cps.Count
    Assert-Equal 'control cptype'        $CP_ENCRYPTIONKEY ([int]$cps[0].Cptype)
    Assert-Equal 'control salt length'   16 $cps[0].Data.Length
    Assert-Equal 'control salt'          'c1 88 ce 48 87 c2 e0 4a 60 5c 8f e0 1a bc 41 84' (Format-Hex $cps[0].Data)

    # round-trip: what we build must parse back
    Assert-Equal 'control round-trip' (Format-Hex $cpbytes) (Format-Hex (New-MtControl -Cptype 1 -Data $cps[0].Data))

    # MD5(0x00) with an empty password and empty salt is a known vector
    $h = New-MtPasswordHash -Password '' -Salt (New-Object byte[] 0)
    Assert-Equal 'password hash length' 17 $h.Length
    Assert-Equal 'password hash prefix' 0  ([int]$h[0])
    Assert-Equal 'MD5(0x00)' '93b885adfe0da089cdf634904fd59f71' `
        ((Format-Hex $h[1..16]) -replace ' ', '')

    # ANSI stripping
    $esc = [char]27
    Assert-Equal 'ANSI strip' 'hello' (Clear-MtAnsi ("$esc[1;32mhello$esc[0m"))
    Assert-Equal 'prompt match' $true $PROMPT_RE.IsMatch('[admin@router] > ')

    # --- EC-SRP5, against vectors generated from the reference Python ---
    function HexOf($b) { (Format-Hex $b) -replace ' ', '' }

    $priv = [byte[]](1..32)
    $kp = New-EcPublicKey -Private $priv
    Assert-Equal 'ecsrp public key' '718f0034ba92aade2eb5495170db6aa13f5d8c29f2c575942eb2d6390788a50a' (HexOf $kp[0])
    Assert-Equal 'ecsrp public parity' 1 $kp[1]

    $g = Get-EcBasePoint
    Assert-Equal 'base point is even-y' 0 ([int]($g.Y % 2))
    $g1 = Get-EcLiftX -X ([System.Numerics.BigInteger]9) -Parity 1
    Assert-Equal 'lift_x(9,odd) x' '2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a' (HexOf (ConvertFrom-EcBig -Value $g1.X -Length 32))
    Assert-Equal 'lift_x(9,odd) y' '20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9' (HexOf (ConvertFrom-EcBig -Value $g1.Y -Length 32))

    $salt = [byte[]](0..15)
    $val = New-MtValidator -User 'admin' -Password 'secret' -Salt $salt
    Assert-Equal 'ecsrp validator' '865486414f27943b1e7bdd6a234356c98f01ce4492b447410faaab95bb28a20f' (HexOf $val)

    $vk = New-EcPublicKey -Private $val
    Assert-Equal 'ecsrp validator pubkey' '303aa11588bc77b9b5aa3790c7d4ea757410a5c96308e814a3dd2e34e01d82d1' (HexOf $vk[0])

    $r1 = ConvertTo-EcMontgomery -Point (Get-EcRedp1 -Data $kp[0] -Parity 1)
    Assert-Equal 'ecsrp redp1 x'      '4495ec48628d0543dbd8e8d88de9d548eb42044c5f7e377839025adac76976ce' (HexOf $r1[0])
    Assert-Equal 'ecsrp redp1 parity' 1 $r1[1]

    $srvPub = [byte[]](ConvertFrom-EcBig -Value ([System.Numerics.BigInteger]::Parse('013b44beebbf0ab83d27f02353d453339dbd0410948e2fa12570782fe8a4a7337','AllowHexSpecifier')) -Length 32)
    $c0 = New-MtConfirmation -User 'admin' -Password 'secret' -Salt $salt -ClientPrivate $priv -ClientPublic $kp[0] -ServerPublic $srvPub -ServerParity 0
    Assert-Equal 'ecsrp confirmation (parity 0)' '6e926d674b0680cc9e93f6b2adde0854c459fbfd74b054cf1655d6e81693c479' (HexOf $c0)
    $c1 = New-MtConfirmation -User 'admin' -Password 'secret' -Salt $salt -ClientPrivate $priv -ClientPublic $kp[0] -ServerPublic $srvPub -ServerParity 1
    Assert-Equal 'ecsrp confirmation (parity 1)' 'f243f58f923219b527e1b9250b2c36fa506975a49944cf805294b8e19cdbb6f7' (HexOf $c1)

    if ($script:selfTestFailures -eq 0) {
        Write-Host 'ALL PASS'
        return 0
    }
    Write-Host ("{0} FAILURE(S)" -f $script:selfTestFailures)
    return 1
}

# -------------------------------------------------------------------- main --
if ($SelfTest) {
    exit (Invoke-MtSelfTest)
}

$script:MtTrace = [bool]$Trace
$nic = Get-LocalNic -WantIP $LocalIP
Write-Verbose ("using {0}  ip={1}  mac={2}" -f $nic.Name, $nic.IP, (Format-Mac $nic.Mac))

if ($Discover) {
    # the function returns with a leading comma, so this assignment keeps the array
    $devices = Invoke-MndpDiscover -Nic $nic -BroadcastIP $Broadcast -TimeoutMs ([Math]::Max($TimeoutMs, 3000))
    if ($devices.Count -eq 0) {
        Write-Host 'No MNDP replies. Either nothing MikroTik is on this segment, or discovery is disabled on it.'
        exit 1
    }
    foreach ($d in $devices) {
        Write-Host ('-' * 60)
        $d.PSObject.Properties | ForEach-Object { Write-Host ("  {0,-12} {1}" -f $_.Name, $_.Value) }
    }
    exit 0
}

if (-not $Target) { throw 'Give -Target <MAC> (or -Discover). Run with -Discover first to find one.' }

if ($ProbeAuth -gt 0) {
    <#  Ask the device for its auth challenge N times, in N separate sessions,
        and print each one. A per-session random nonce is a challenge-response
        scheme (legacy MD5). A value that never changes is a stored salt, which
        means the device is speaking EC-SRP5 and no MD5 answer will ever satisfy
        it. Payload length alone cannot tell these apart. #>
    $dst = ConvertTo-MacBytes $Target
    for ($n = 1; $n -le $ProbeAuth; $n++) {
        $probe = New-MtSession -Nic $nic -DstMac $dst -BroadcastIP $Broadcast
        try {
            Start-MtSession -S $probe -TimeoutMs $TimeoutMs
            if ($ProbeUser) {
                # modern shape: BEGIN_AUTH + ENCRYPTION_KEY(user||0||pubkey||parity)
                $ppriv = New-Object byte[] 32
                $prng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
                try { $prng.GetBytes($ppriv) } finally { $prng.Dispose() }
                $pkp = New-EcPublicKey -Private $ppriv
                $kd = New-Object System.Collections.Generic.List[byte]
                $kd.AddRange([System.Text.Encoding]::UTF8.GetBytes($ProbeUser)); $kd.Add(0)
                $kd.AddRange($pkp[0]); $kd.Add([byte]$pkp[1])
                $hello = New-Object System.Collections.Generic.List[byte]
                $hello.AddRange((New-MtControl -Cptype $CP_BEGINAUTH -Data $null))
                $hello.AddRange((New-MtControl -Cptype $CP_ENCRYPTIONKEY -Data $kd.ToArray()))
                $got = Send-MtReliable -S $probe -Payload $hello.ToArray() -TimeoutMs $TimeoutMs
                $reply = $null
                foreach ($pp in $got) { foreach ($cp in (Read-MtControl -Payload $pp)) {
                    if ($cp.Cptype -eq $CP_ENCRYPTIONKEY) { $reply = $cp.Data } } }
                $tw = [System.Diagnostics.Stopwatch]::StartNew()
                while ($null -eq $reply -and $tw.ElapsedMilliseconds -lt $TimeoutMs) {
                    $pk = Receive-MtOnce -S $probe -WaitMs 200
                    if ($null -ne $pk -and $pk.Ptype -eq $PT_DATA -and $pk.Fresh) {
                        foreach ($cp in (Read-MtControl -Payload $pk.Payload)) {
                            if ($cp.Cptype -eq $CP_ENCRYPTIONKEY) { $reply = $cp.Data } } }
                }
                if ($null -eq $reply) {
                    Write-Host ("probe {0}: user={1,-14} NO REPLY" -f $n, $ProbeUser)
                } elseif ($reply.Length -ge 49) {
                    $sp = New-Object byte[] 32; [Array]::Copy($reply, 0, $sp, 0, 32)
                    $sl = New-Object byte[] 16; [Array]::Copy($reply, 33, $sl, 0, 16)
                    Write-Host ("probe {0}: user={1,-14} len={2} parity={3}" -f $n, $ProbeUser, $reply.Length, $reply[32])
                    Write-Host ("           serverkey {0}" -f (Format-Hex $sp))
                    Write-Host ("           salt      {0}" -f (Format-Hex $sl))
                } else {
                    Write-Host ("probe {0}: user={1,-14} SHORT len={2}  {3}" -f $n, $ProbeUser, $reply.Length, (Format-Hex $reply))
                }
            } else {
                $salt = Get-MtChallenge -S $probe -TimeoutMs $TimeoutMs
                Write-Host ("probe {0}: user=(none)        len={1}  {2}" -f $n, $salt.Length, (Format-Hex $salt))
            }
        } finally {
            Close-MtSession -S $probe
        }
        Start-Sleep -Milliseconds 300
    }
    exit 0
}

if (-not $Command -or $Command.Count -eq 0) { throw 'Give -Command ''<cli line>'' (one or more).' }

$dst = ConvertTo-MacBytes $Target
$s = New-MtSession -Nic $nic -DstMac $dst -BroadcastIP $Broadcast
try {
    Start-MtSession -S $s -TimeoutMs $TimeoutMs
    Write-Verbose ("session {0:x4} established with {1}" -f $s.SessionKey, (Format-Mac $dst))

    if ($Legacy) {
        $banner = Invoke-MtLoginLegacy -S $s -User $User -Password $Password -TimeoutMs $TimeoutMs -Term $TermType -Variant $AuthVariant
    } else {
        $banner = Invoke-MtLoginModern -S $s -User $User -Password $Password -TimeoutMs $TimeoutMs -Term $TermType
    }
    if ($Raw) { Write-Host $banner }

    foreach ($line in $Command) {
        Write-Host ("=== {0}" -f $line)
        $out = Invoke-MtCommand -S $s -Line $line -TimeoutMs $TimeoutMs -RawOutput:$Raw
        if ($out) { Write-Host $out }
    }

    try { Send-MtText -S $s -Text "/quit`r`n" -TimeoutMs 1000 } catch { }
} finally {
    Close-MtSession -S $s
}
