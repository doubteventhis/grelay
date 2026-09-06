package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"github.com/txthinking/socks5"
)

type UserSocksHandler struct {
	user string
}

type Session struct {
	Scheme 		string
	Target 		string
	Port   		int
	User   		string
	Up     		*rawUpstream

	InUse 		atomic.Bool
	Dead  		atomic.Bool

	Data   		map[string][]byte
	Client 		ProtocolClient
}

type ProtocolClient interface {
	Init(*Session) error
	KeepAlive() error
	SkipAuthentication(down net.Conn) error
	Tunnel(down net.Conn) error
	Kill() error
	IsAdmin() (bool, error) // optional
}

// save a new user session and start socks tunnel
func registerSession(scheme, host string, port int, user string, up *rawUpstream, pc ProtocolClient) (*Session, error) {
	now := time.Now().Format("15:04:05")
	// create a new session object
	sess := &Session{
		Scheme: strings.ToUpper(scheme),
		Target: host, 
		Port: port, 
		User: user,
		Up: up, 
		Data: map[string][]byte{}, 
		Client: pc,
	}
	// initializes the protocol for tunneling
	if err := pc.Init(sess); err != nil {
		return nil, err
	}
	// stores session
	sessionsMu.Lock()
	if sessions[host] == nil {
		sessions[host] = map[int]map[string]*Session{}
	}
	if sessions[host][port] == nil {
		sessions[host][port] = map[string]*Session{}
	}
	sessions[host][port][user] = sess
	sessionsMu.Unlock()
	// check if the user already has a socks proxy. if not, assign a new port
	userTunMu.Lock()
	userPort, exists := userTunnels[user]
	if !exists {
		current := atomic.AddInt32(&nextSOCKSPort, 1)
		userPort = fmt.Sprintf("%s:%d", socksIP, socksBasePort+int(current)-1)
		userTunnels[user] = userPort
	}
	userTunMu.Unlock()
	// set up the new tunnel
	if !exists {
		log.Printf("%s%s%s [SOCKS]%s Starting listener for %s:%d on %s as %s%s", Grey, now, Reset, Green, host, port, userPort, user, Reset)
		// start tunnel
		startUserSOCKS(user, userPort)
		// dump config file
		dumpProxychainsConfig(user, userPort)
	} else {
		log.Printf("%s%s%s [SOCKS]%s Registered %s:%d to existing listener on %s as %s%s", Grey, now, Reset, Green, host, port, userPort, user, Reset)
	}
	return sess, nil
}

func isConnClosed(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "connection reset by peer")
}

func (h *UserSocksHandler) TCPHandle(s *socks5.Server, c *net.TCPConn, r *socks5.Request) error {
	if r.Cmd != socks5.CmdConnect {
		return socks5.ErrUnsupportCmd
	}

	var host string
	switch r.Atyp {
	case socks5.ATYPIPv4:
		host = net.IP(r.DstAddr).String()
	case socks5.ATYPDomain:
		host = string(r.DstAddr)
	case socks5.ATYPIPv6:
		return fmt.Errorf("IPv6 not supported")
	default:
		return fmt.Errorf("unsupported address type %d", r.Atyp)
	}

	port := int(binary.BigEndian.Uint16(r.DstPort))

	sess := pickUserSession(h.user, host, port)
	if sess == nil {
		now := time.Now().Format("15:04:05")
		log.Printf("%s%s%s [SOCKS]%s No session found for %s to %s:%d%s", Grey, now, Reset, Red, h.user, host, port, Reset)
		return writeSocksErr(c, socks5.RepHostUnreachable)
	}

	// SMB supports concurrent tunnels (tools often need multiple connections).
	// Other protocols require exclusive access.
	if sess.Scheme == "SMB" {
		sess.InUse.Store(true)
		defer sess.InUse.Store(false)
	} else {
		if !sess.InUse.CompareAndSwap(false, true) {
			return writeSocksErr(c, socks5.RepServerFailure)
		}
		defer sess.InUse.Store(false)
	}

	if err := writeSocksOK(c); err != nil {
		return err
	}
	now := time.Now().Format("15:04:05")
	log.Printf("%s%s%s [SOCKS]%s Tunnel open for %s -> %s:%d%s", Grey, now, Reset, Cyan, h.user, host, port, Reset)

	if err := sess.Client.SkipAuthentication(c); err != nil {
		return err
	}

	if err := sess.Client.Tunnel(c); err != nil {
		if isConnClosed(err) || err == io.EOF {
			now := time.Now().Format("15:04:05")
            log.Printf("%s%s%s [SOCKS]%s Connection closed unexpectedly for %s -> %s:%d%s", Grey, now, Reset, Red, h.user, host, port, Reset)

			sess.Dead.Store(true)
			_ = sess.Client.Kill()
			return nil
		}
		return err
	}
	now = time.Now().Format("15:04:05")
	log.Printf("%s%s%s [SOCKS]%s Tunnel closed for %s -> %s:%d%s", Grey, now, Reset, Cyan, h.user, host, port, Reset)
	return nil
}

func (h *UserSocksHandler) UDPHandle(s *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	return socks5.ErrUnsupportCmd
}

func pickUserSession(user, host string, port int) *Session {
    // First, look up the session
    sessionsMu.RLock()
    byPort, ok := sessions[host]
    if !ok {
        sessionsMu.RUnlock()
        return nil
    }
    byUser, ok := byPort[port]
    if !ok {
        sessionsMu.RUnlock()
        return nil
    }
    sess, ok := byUser[user]
    sessionsMu.RUnlock()

    if !ok {
        return nil
    }
    if sess.Dead.Load() {
        return nil
    }

    // SMB supports concurrent tunnels — return immediately
    if sess.Scheme == "SMB" {
        return sess
    }

    // Other protocols require exclusive access — wait for InUse to clear
    if !sess.InUse.Load() {
        return sess
    }

    timeout := time.After(30 * time.Second)
    ticker := time.NewTicker(100 * time.Millisecond)
    defer ticker.Stop()

    if verbose {
        now := time.Now().Format("15:04:05")
        log.Printf("%s%s%s [SOCKS]%s Session for %s to %s:%d is currently in use, waiting...%s", Grey, now, Reset, Cyan, user, host, port, Reset)
    }

    for {
        select {
        case <-timeout:
            if verbose {
                now := time.Now().Format("15:04:05")
                log.Printf("%s%s%s [SOCKS]%s Timeout waiting for session %s to %s:%d to become available%s", Grey, now, Reset, Red, user, host, port, Reset)
            }
            return nil

        case <-ticker.C:
            if sess.Dead.Load() {
                return nil
            }
            if !sess.InUse.Load() {
                return sess
            }
        }
    }
}

func writeSocksOK(c *net.TCPConn) error {
	rep := socks5.NewReply(socks5.RepSuccess, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
	_, err := rep.WriteTo(c)
	return err
}

func writeSocksErr(c *net.TCPConn, code byte) error {
	rep := socks5.NewReply(code, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
	_, err := rep.WriteTo(c)
	return err
}

func dumpProxychainsConfig(label, addr string) {
	now := time.Now().Format("15:04:05")
	base := strings.ReplaceAll(strings.ReplaceAll(label, "\\", "_"), " ", "_")
	proxyAddr := strings.ReplaceAll(addr, ":", " ")
	path := fmt.Sprintf("./%s.conf", base)

	cfg := fmt.Sprintf(`# generated proxychains config for %s
strict_chain
tcp_read_time_out 15000

[ProxyList]
socks5 %s
`, label, proxyAddr)

	if err := os.WriteFile(path, []byte(cfg), 0644); err != nil {
		log.Printf("%s%s%s [SOCKS]%s write %s: %s%s", Grey, now, Reset, Red, path, err, Reset)
	} else {
		log.Printf("%s%s%s [SOCKS] Writing proxychains conf file, use with 'proxychains -f %s <cmd>'%s", Grey, now, Reset, path, Reset)
	}
}

func startUserSOCKS(user, userPort string) {
    srv, err := socks5.NewClassicServer(userPort, socksIP, "", "", 0, 0)
    if err != nil {
        log.Fatalf("[SOCKS] create failed for %s: %v", user, err)
    }
    srv.SupportedCommands = []byte{socks5.CmdConnect}
    go func() {
        if err := srv.ListenAndServe(&UserSocksHandler{user: user}); err != nil {
            log.Printf("[SOCKS] serve error for %s: %v", user, err)
        }
    }()
}

func dumpSocks() {
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()

	var active []*Session
	for _, byPort := range sessions {
		for _, byUser := range byPort {
			for _, sess := range byUser {
				if !sess.Dead.Load() {
					active = append(active, sess)
				}
			}
		}
	}
	if len(active) == 0 {
		fmt.Println("no active tunnels")
		return
	}

	type entry struct {
		scheme string
		socks  string
		target string
		user   string
		port   int
	}

	parsePort := func(addr string) int {
		i := strings.LastIndex(addr, ":")
		if i < 0 || i+1 >= len(addr) {
			return -1
		}
		p, _ := strconv.Atoi(addr[i+1:])
		return p
	}

	entries := make([]entry, 0, len(active))
	for _, sess := range active {
		target := fmt.Sprintf("%s:%d", sess.Target, sess.Port)
		userTunMu.Lock()
		socks := userTunnels[sess.User]
		userTunMu.Unlock()
		entries = append(entries, entry{
			scheme: sess.Scheme,
			socks:  socks,
			target: target,
			user:   sess.User,
			port:   parsePort(socks),
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].port != entries[j].port {
			return entries[i].port < entries[j].port
		}
		// deterministic tie-breakers
		if entries[i].socks != entries[j].socks {
			return entries[i].socks < entries[j].socks
		}
		if entries[i].scheme != entries[j].scheme {
			return entries[i].scheme < entries[j].scheme
		}
		if entries[i].target != entries[j].target {
			return entries[i].target < entries[j].target
		}
		return entries[i].user < entries[j].user
	})

	fmt.Printf("%-7s %-18s %-22s %-25s\n", "scheme", "socks address", "target address", "domain\\user")
	fmt.Printf("%-7s %-18s %-22s %-25s\n", "------", "-------------", "--------------", "------------")
	for _, e := range entries {
		fmt.Printf("%-7s %-18s %-22s %-25s\n", e.scheme, e.socks, e.target, e.user)
	}
	fmt.Println()
}