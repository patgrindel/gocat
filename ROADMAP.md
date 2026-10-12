# GoCat C2 — Roadmap

Improvement items identified during development, organized by priority.

---

## High Priority — Fix Before Heavy Use

1. **Fix SOCKS5 / port forward data relay**
   The biggest gap. Each tunnel needs its own goroutine-based bidirectional relay (`io.Copy` in both directions) running independently of the command channel. Consider a channel multiplexer or a separate data port. Currently only the handshake travels; actual data does not relay.

2. **Clean up unused imports** *(done in this version)*
   Removed blank-identifier hacks (`_ = x509.NewCertPool`, `_ = filepath.Separator`) and restructured imports properly.

3. **TLS cert loading from file**
   Instead of hardcoding PEM in constants, load `cert.pem` / `key.pem` from disk at startup with a `-cert` / `-key` flag. Much cleaner for lab use and removes the need to edit source before each build.

---

## Evasion & Stability

4. **Sleep/jitter on the client between commands**
   Currently jitter only applies to reconnection. Add an optional idle sleep between command polls so beacon traffic looks less regular.

5. **Windows persistence**
   Add a `persist` command that writes a registry run key (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) or creates a scheduled task on Windows targets.

6. **Self-delete on exit**
   Optionally delete the client binary from disk when the server sends `exit`.

---

## Recon

7. **`ifconfig` wrapper**
   A dedicated `ifconfig` command that normalizes `ipconfig` (Windows) and `ifconfig`/`ip addr` (Linux) output into a consistent format.

8. **`drives` command**
   List available drives and mount points — useful for Windows AD targets where loot may be on mapped network drives.

9. **`clipboard` command**
   Read the clipboard on Windows (`Get-Clipboard`) or Linux (`xclip -o`).

10. **`hashdump` stub**
    A placeholder that runs `reg save HKLM\SAM` and `reg save HKLM\SYSTEM` on Windows, saving the hives for offline cracking with hashcat / impacket secretsdump.

---

## Infrastructure

11. **Proper TUI with multiple panes**
    Use a library like `bubbletea` or `tcell` to show all sessions in one pane and active session output in another, without the prompt blocking on a single session at a time.

12. **HTTP/HTTPS transport option**
    Add an alternate transport that wraps messages in HTTP POST requests to blend with web traffic and bypass basic egress firewall rules.

13. **Session reconnect / persistence**
    If a session drops, auto-re-register it when the client reconnects, preserving the session ID and command history.

14. **Encrypted logging**
    Optionally encrypt the log file at rest (e.g., AES-GCM with a passphrase) so loot and command history are not sitting in plaintext on disk.

15. **Config file support**
    Load server defaults (port, TLS paths, log path) from a YAML or TOML file instead of requiring all options to be specified as CLI flags.
