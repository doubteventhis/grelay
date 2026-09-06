package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

// MSSQLClient implements ProtocolClient for MSSQL relay sessions.
type MSSQLClient struct {
	sess *Session
}

func (c *MSSQLClient) Init(s *Session) error {
	c.sess = s
	if tc, ok := s.Up.conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(15 * time.Second)
	}
	return nil
}

func (c *MSSQLClient) KeepAlive() error {
	// Send SQL Batch: "SELECT 1" with ALL_HEADERS
	query := utf16LEEncode("SELECT 1")

	// ALL_HEADERS: TotalLength(4) + HeaderLength(4) + HeaderType(2) + TransactionDescriptor(8) + OutstandingRequestCount(4) = 22 bytes
	allHeaders := make([]byte, 22)
	binary.LittleEndian.PutUint32(allHeaders[0:4], 22) // TotalLength
	binary.LittleEndian.PutUint32(allHeaders[4:8], 18) // HeaderLength
	binary.LittleEndian.PutUint16(allHeaders[8:10], 2) // HeaderType: Transaction Descriptor
	binary.LittleEndian.PutUint32(allHeaders[18:22], 1)

	payload := append(allHeaders, query...)
	if err := writeTDSPacket(c.sess.Up.conn, TDS_SQL_BATCH, payload); err != nil {
		return err
	}

	// Read and discard response
	_, _, err := readTDSPacket(c.sess.Up.conn)
	return err
}

func (c *MSSQLClient) SkipAuthentication(_ net.Conn) error { return nil }
func (c *MSSQLClient) Kill() error                         { return c.sess.Up.conn.Close() }
func (c *MSSQLClient) IsAdmin() (bool, error)              { return false, nil }

func (c *MSSQLClient) Tunnel(down net.Conn) error {
	return pumpTDS(down, c.sess.Up.conn)
}

// utf16LEEncode encodes a string as UTF-16LE bytes.
func utf16LEEncode(s string) []byte {
	runes := []rune(s)
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[i*2:], uint16(r))
	}
	return buf
}

// ---------------------------------------------------------------------------
// Synthetic response builders for SOCKS tunnel auth bypass
// ---------------------------------------------------------------------------

// buildSyntheticPreLoginResponse builds a PreLogin response indicating no encryption.
func buildSyntheticPreLoginResponse() []byte {
	// VERSION + ENCRYPTION + TERMINATOR
	const headerLen = 2*5 + 1 // 11
	body := make([]byte, headerLen+6+1)
	off := headerLen

	// VERSION
	body[0] = TDS_PRELOGIN_VERSION
	binary.BigEndian.PutUint16(body[1:3], uint16(off))
	binary.BigEndian.PutUint16(body[3:5], 6)
	body[off] = 0x0F
	body[off+1] = 0x00
	binary.BigEndian.PutUint16(body[off+2:off+4], 4153)
	off += 6

	// ENCRYPTION
	body[5] = TDS_PRELOGIN_ENCRYPTION
	binary.BigEndian.PutUint16(body[6:8], uint16(off))
	binary.BigEndian.PutUint16(body[8:10], 1)
	body[off] = TDS_ENCRYPT_NOT_SUP

	// Terminator
	body[10] = TDS_PRELOGIN_TERMINATOR

	return body
}

// buildSyntheticLoginAckResponse builds a Tabular Result with LOGINACK + DONE tokens.
func buildSyntheticLoginAckResponse() []byte {
	// LOGINACK token
	progName := utf16LEEncode("Microsoft SQL Server")
	loginAckLen := 1 + 4 + 1 + len(progName) + 4 // interface + tdsversion + prognamelen + progname + version
	loginAck := make([]byte, 1+2+loginAckLen)
	loginAck[0] = TDS_TOKEN_LOGINACK
	binary.LittleEndian.PutUint16(loginAck[1:3], uint16(loginAckLen))
	loginAck[3] = 0x01                                          // Interface: SQL
	binary.LittleEndian.PutUint32(loginAck[4:8], 0x74000004)    // TDSVersion 7.4
	loginAck[8] = byte(len(progName) / 2)                       // ProgName length (in chars)
	copy(loginAck[9:9+len(progName)], progName)
	off := 9 + len(progName)
	loginAck[off] = 15    // Major version
	loginAck[off+1] = 0   // Minor version
	binary.LittleEndian.PutUint16(loginAck[off+2:off+4], 4153) // Build

	// DONE token
	done := make([]byte, 13)
	done[0] = TDS_TOKEN_DONE
	// status=0, curcmd=0, rowcount=0 (12 bytes of zeros)

	result := append(loginAck, done...)
	return result
}

// ---------------------------------------------------------------------------
// pumpTDS — bidirectional TDS tunnel with synthetic auth bypass
// ---------------------------------------------------------------------------

// pumpTDS handles SOCKS client authentication bypass then bidirectional forwarding.
func pumpTDS(down net.Conn, up net.Conn) error {
	now := func() string { return time.Now().Format("15:04:05") }

	// Phase 1: Auth bypass — intercept PreLogin, Login7, and SSPI locally
	for {
		pktType, payload, err := readTDSPacket(down)
		if err != nil {
			return err
		}

		switch pktType {
		case TDS_PRELOGIN:
			if debug {
				log.Printf("%s%s%s [MSSQL]%s pumpTDS: PreLogin → synthetic response%s",
					Grey, now(), Reset, Grey, Reset)
			}
			if err := writeTDSPacket(down, TDS_TABULAR, buildSyntheticPreLoginResponse()); err != nil {
				return err
			}

		case TDS_LOGIN7:
			if debug {
				log.Printf("%s%s%s [MSSQL]%s pumpTDS: Login7 → synthetic SSPI challenge%s",
					Grey, now(), Reset, Grey, Reset)
			}
			fakeType2 := buildNTLMType2()
			if err := writeTDSPacket(down, TDS_SSPI, fakeType2); err != nil {
				return err
			}

		case TDS_SSPI:
			if debug {
				log.Printf("%s%s%s [MSSQL]%s pumpTDS: SSPI → synthetic LoginAck%s",
					Grey, now(), Reset, Grey, Reset)
			}
			if err := writeTDSPacket(down, TDS_TABULAR, buildSyntheticLoginAckResponse()); err != nil {
				return err
			}
			goto tunnel

		default:
			// Non-auth packet — forward to upstream and enter tunnel mode
			if debug {
				log.Printf("%s%s%s [MSSQL]%s pumpTDS: packet type 0x%02x → forwarding, entering tunnel%s",
					Grey, now(), Reset, Grey, pktType, Reset)
			}
			if err := writeTDSPacket(up, pktType, payload); err != nil {
				return err
			}
			goto tunnel
		}
	}

tunnel:
	// Phase 2: Bidirectional raw forwarding
	errCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(down, up)
		errCh <- err
	}()

	go func() {
		_, err := io.Copy(up, down)
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
