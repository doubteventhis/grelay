package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// SMBClient implements ProtocolClient for SMB relay sessions.
type SMBClient struct {
	sess            *Session
	upSessionID     uint64
	upNextMsgID     uint64
	upMsgIDMu       sync.Mutex
	upWriteMu       sync.Mutex   // serializes writes to upstream
	dispatch        sync.Map     // upMsgID(uint64) → chan []byte
	upDead          chan struct{} // closed when upstream reader exits
	maxReadSize     uint32
	maxWriteSize    uint32
	maxTransactSize uint32
	serverGUID      [16]byte
}

func (c *SMBClient) Init(s *Session) error {
	c.sess = s
	c.upDead = make(chan struct{})
	// TCP keepalive keeps the connection alive at the OS level.
	// SMB Echo is unreliable due to credit exhaustion after tunnel traffic.
	if tc, ok := s.Up.conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(15 * time.Second)
	}
	go c.readUpstream()
	return nil
}

// readUpstream is the persistent upstream reader goroutine. It runs for the
// lifetime of the session, reading SMB2 responses and dispatching them to
// waiters (pumpSMB tunnels or KeepAlive) by MessageID.
func (c *SMBClient) readUpstream() {
	conn := c.sess.Up.conn
	now := func() string { return time.Now().Format("15:04:05") }

	defer func() {
		close(c.upDead)
		// Wake all waiters by closing their channels
		c.dispatch.Range(func(key, value any) bool {
			close(value.(chan []byte))
			c.dispatch.Delete(key)
			return true
		})
	}()

	for {
		packet, err := readNetBIOSPacket(conn)
		if err != nil {
			if !isConnClosed(err) {
				log.Printf("%s%s%s [SMB]%s readUpstream: %v%s",
					Grey, now(), Reset, Red, err, Reset)
			} else if debug {
				log.Printf("%s%s%s [SMB]%s readUpstream: connection closed%s",
					Grey, now(), Reset, Grey, Reset)
			}
			return
		}
		if len(packet) < 64 {
			continue
		}

		msgID := binary.LittleEndian.Uint64(packet[24:32])
		if ch, ok := c.dispatch.Load(msgID); ok {
			select {
			case ch.(chan []byte) <- packet:
			default:
				// Channel full — drop to avoid blocking the reader
			}
			// Remove entry once the final (non-pending) response arrives
			status := binary.LittleEndian.Uint32(packet[8:12])
			if status != STATUS_PENDING {
				c.dispatch.Delete(msgID)
			}
		} else if debug {
			cmd := binary.LittleEndian.Uint16(packet[12:14])
			log.Printf("%s%s%s [SMB]%s readUpstream: no waiter for msgID=%d cmd=%s%s",
				Grey, now(), Reset, Grey, msgID, smb2CommandName(cmd), Reset)
		}
	}
}

// upstreamSend writes a packet to upstream, serialized across tunnels.
func (c *SMBClient) upstreamSend(data []byte) error {
	c.upWriteMu.Lock()
	defer c.upWriteMu.Unlock()
	return writeNetBIOSPacket(c.sess.Up.conn, data)
}

// KeepAlive is called by the session janitor. TCP keepalive handles the
// connection liveness at the OS level. This just checks if readUpstream
// has detected a dead connection.
func (c *SMBClient) KeepAlive() error {
	select {
	case <-c.upDead:
		return fmt.Errorf("upstream died")
	default:
		return nil
	}
}

func (c *SMBClient) SkipAuthentication(_ net.Conn) error { return nil }
func (c *SMBClient) Kill() error                         { return c.sess.Up.conn.Close() }
func (c *SMBClient) IsAdmin() (bool, error)              { return false, nil }

func (c *SMBClient) Tunnel(down net.Conn) error {
	return pumpSMB(down, c)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeNetBIOSPacket(conn net.Conn, data []byte) error {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(data)))
	if _, err := conn.Write(hdr); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}

func smb2CommandName(cmd uint16) string {
	names := map[uint16]string{
		0x0000: "Negotiate", 0x0001: "SessionSetup", 0x0002: "Logoff",
		0x0003: "TreeConnect", 0x0004: "TreeDisconnect", 0x0005: "Create",
		0x0006: "Close", 0x0007: "Flush", 0x0008: "Read",
		0x0009: "Write", 0x000A: "Lock", 0x000B: "Ioctl",
		0x000C: "Echo", 0x000D: "QueryDirectory", 0x000E: "ChangeNotify",
		0x000F: "QueryInfo", 0x0010: "SetInfo", 0x0011: "OplockBreak",
	}
	if name, ok := names[cmd]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", cmd)
}

// ---------------------------------------------------------------------------
// Synthetic response builders (Negotiate, SessionSetup — handled locally)
// ---------------------------------------------------------------------------

// buildNegotiateSecurityBlob builds a GSS-API SPNEGO NegTokenInit listing NTLMSSP
// as the available authentication mechanism. Used in synthetic Negotiate Responses.
func buildNegotiateSecurityBlob() []byte {
	ntlmsspOID := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}

	mechTypesSeq := append([]byte{0x30}, encodeLength(len(ntlmsspOID))...)
	mechTypesSeq = append(mechTypesSeq, ntlmsspOID...)
	mechTypes := append([]byte{0xa0}, encodeLength(len(mechTypesSeq))...)
	mechTypes = append(mechTypes, mechTypesSeq...)

	seq := append([]byte{0x30}, encodeLength(len(mechTypes))...)
	seq = append(seq, mechTypes...)

	negTokenInit := append([]byte{0xa0}, encodeLength(len(seq))...)
	negTokenInit = append(negTokenInit, seq...)

	spnegoOID := []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}

	appData := append(spnegoOID, negTokenInit...)
	app := append([]byte{0x60}, encodeLength(len(appData))...)
	app = append(app, appData...)

	return app
}

func sendSyntheticNegotiateResponse(down net.Conn, downMsgID uint64, client *SMBClient) error {
	spnegoBlob := buildNegotiateSecurityBlob()

	totalSMB := 64 + 64 + len(spnegoBlob)
	response := make([]byte, 4+totalSMB)
	binary.BigEndian.PutUint32(response[0:4], uint32(totalSMB))

	copy(response[4:8], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(response[8:10], 64)
	binary.LittleEndian.PutUint16(response[10:12], 1)
	binary.LittleEndian.PutUint32(response[12:16], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(response[16:18], SMB2_NEGOTIATE)
	binary.LittleEndian.PutUint16(response[18:20], 256)
	binary.LittleEndian.PutUint32(response[20:24], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(response[28:36], downMsgID)

	binary.LittleEndian.PutUint16(response[68:70], 65)
	binary.LittleEndian.PutUint16(response[70:72], 0x01)
	binary.LittleEndian.PutUint16(response[72:74], SMB2_DIALECT_0210)
	copy(response[76:92], client.serverGUID[:])
	binary.LittleEndian.PutUint32(response[96:100], client.maxTransactSize)
	binary.LittleEndian.PutUint32(response[100:104], client.maxReadSize)
	binary.LittleEndian.PutUint32(response[104:108], client.maxWriteSize)

	winTime := timeToFileTime(time.Now())
	binary.LittleEndian.PutUint64(response[108:116], winTime)
	binary.LittleEndian.PutUint64(response[116:124], winTime)
	binary.LittleEndian.PutUint16(response[124:126], 128)
	binary.LittleEndian.PutUint16(response[126:128], uint16(len(spnegoBlob)))

	copy(response[132:], spnegoBlob)

	_, err := down.Write(response)
	return err
}

func sendSyntheticSessionSetupChallenge(down net.Conn, downMsgID uint64, client *SMBClient) error {
	ntlmChallenge := buildNTLMType2()
	secBlob := buildNegTokenResp(ntlmChallenge)

	response := make([]byte, 4+64+8+len(secBlob))
	binary.BigEndian.PutUint32(response[0:4], uint32(64+8+len(secBlob)))

	copy(response[4:8], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(response[8:10], 64)
	binary.LittleEndian.PutUint16(response[10:12], 1)
	binary.LittleEndian.PutUint32(response[12:16], STATUS_MORE_PROCESSING_REQUIRED)
	binary.LittleEndian.PutUint16(response[16:18], SMB2_SESSION_SETUP)
	binary.LittleEndian.PutUint16(response[18:20], 1)
	binary.LittleEndian.PutUint32(response[20:24], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(response[28:36], downMsgID)
	binary.LittleEndian.PutUint64(response[44:52], client.upSessionID)

	binary.LittleEndian.PutUint16(response[68:70], 9)
	binary.LittleEndian.PutUint16(response[70:72], 0)
	binary.LittleEndian.PutUint16(response[72:74], 72)
	binary.LittleEndian.PutUint16(response[74:76], uint16(len(secBlob)))
	copy(response[76:], secBlob)

	_, err := down.Write(response)
	return err
}

func sendSyntheticSessionSetupAccept(down net.Conn, downMsgID uint64, client *SMBClient) error {
	spnegoAccept := []byte{0xa1, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x0a, 0x01, 0x00}

	response := make([]byte, 4+64+8+len(spnegoAccept))
	binary.BigEndian.PutUint32(response[0:4], uint32(64+8+len(spnegoAccept)))

	copy(response[4:8], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(response[8:10], 64)
	binary.LittleEndian.PutUint16(response[10:12], 1)
	binary.LittleEndian.PutUint32(response[12:16], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(response[16:18], SMB2_SESSION_SETUP)
	binary.LittleEndian.PutUint16(response[18:20], 1)
	binary.LittleEndian.PutUint32(response[20:24], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(response[28:36], downMsgID)
	binary.LittleEndian.PutUint64(response[44:52], client.upSessionID)

	binary.LittleEndian.PutUint16(response[68:70], 9)
	binary.LittleEndian.PutUint16(response[70:72], 0)
	binary.LittleEndian.PutUint16(response[72:74], 72)
	binary.LittleEndian.PutUint16(response[74:76], uint16(len(spnegoAccept)))
	copy(response[76:], spnegoAccept)

	_, err := down.Write(response)
	return err
}

// sendSyntheticSimpleResponse sends a STATUS_SUCCESS response with a 4-byte body.
// Used for Logoff and TreeDisconnect which we handle locally.
func sendSyntheticSimpleResponse(down net.Conn, command uint16, downMsgID uint64, client *SMBClient) error {
	response := make([]byte, 4+64+4)
	binary.BigEndian.PutUint32(response[0:4], 68) // NetBIOS length

	copy(response[4:8], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(response[8:10], 64)
	binary.LittleEndian.PutUint16(response[10:12], 1)
	binary.LittleEndian.PutUint32(response[12:16], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(response[16:18], command)
	binary.LittleEndian.PutUint16(response[18:20], 1)
	binary.LittleEndian.PutUint32(response[20:24], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(response[28:36], downMsgID)
	binary.LittleEndian.PutUint64(response[44:52], client.upSessionID)

	binary.LittleEndian.PutUint16(response[68:70], 4) // StructureSize

	_, err := down.Write(response)
	return err
}

// ---------------------------------------------------------------------------
// pumpSMB — bidirectional SMB tunnel with persistent upstream reader dispatch
// ---------------------------------------------------------------------------

func pumpSMB(down net.Conn, client *SMBClient) error {
	respCh := make(chan []byte, 16)
	errCh := make(chan error, 2)
	done := make(chan struct{})
	var pending sync.Map // upMsgID(uint64) → downMsgID(uint64)

	now := func() string { return time.Now().Format("15:04:05") }

	// Goroutine 1: upstream responses → downstream
	// Reads from respCh (fed by the persistent readUpstream goroutine)
	// and forwards translated responses to the SOCKS client.
	go func() {
		for {
			select {
			case packet, ok := <-respCh:
				if !ok {
					return // channel closed during cleanup
				}
				if len(packet) >= 64 {
					upMsgID := binary.LittleEndian.Uint64(packet[24:32])
					if downMsgID, ok := pending.Load(upMsgID); ok {
						binary.LittleEndian.PutUint64(packet[24:32], downMsgID.(uint64))
						status := binary.LittleEndian.Uint32(packet[8:12])
						if status != STATUS_PENDING {
							pending.Delete(upMsgID)
						}
					}
					if debug {
						cmd := binary.LittleEndian.Uint16(packet[12:14])
						status := binary.LittleEndian.Uint32(packet[8:12])
						log.Printf("%s%s%s [SMB]%s pumpSMB: ← %s status=0x%08x (%d bytes)%s",
							Grey, now(), Reset, Grey, smb2CommandName(cmd), status, len(packet), Reset)
					}
				}
				if err := writeNetBIOSPacket(down, packet); err != nil {
					errCh <- err
					return
				}
			case <-client.upDead:
				errCh <- io.EOF
				return
			case <-done:
				errCh <- nil
				return
			}
		}
	}()

	// Goroutine 2: downstream requests → handle locally or forward upstream
	go func() {
		for {
			packet, err := readNetBIOSPacket(down)
			if err != nil {
				if debug {
					log.Printf("%s%s%s [SMB]%s pumpSMB: downstream read done: %v%s",
						Grey, now(), Reset, Grey, err, Reset)
				}
				errCh <- err
				return
			}
			if len(packet) < 4 {
				continue
			}

			// Handle SMB1 (impacket starts with SMB1 Negotiate)
			if packet[0] == 0xFF && packet[1] == 'S' && packet[2] == 'M' && packet[3] == 'B' {
				if len(packet) >= 5 && packet[4] == 0x72 {
					if debug {
						log.Printf("%s%s%s [SMB]%s pumpSMB: SMB1 Negotiate → SMB2 upgrade%s",
							Grey, now(), Reset, Grey, Reset)
					}
					if err := sendSyntheticNegotiateResponse(down, 0, client); err != nil {
						errCh <- err
						return
					}
				}
				continue
			}

			if packet[0] != 0xFE || len(packet) < 64 {
				continue
			}

			command := binary.LittleEndian.Uint16(packet[12:14])

			switch command {
			case SMB2_NEGOTIATE:
				downMsgID := binary.LittleEndian.Uint64(packet[24:32])
				if debug {
					log.Printf("%s%s%s [SMB]%s pumpSMB: Negotiate (msgID=%d) → synthetic%s",
						Grey, now(), Reset, Grey, downMsgID, Reset)
				}
				if err := sendSyntheticNegotiateResponse(down, downMsgID, client); err != nil {
					errCh <- err
					return
				}
				continue

			case SMB2_SESSION_SETUP:
				downMsgID := binary.LittleEndian.Uint64(packet[24:32])
				ntlmType := 0
				if len(packet) >= 64+16 {
					secOffset := binary.LittleEndian.Uint16(packet[64+12 : 64+14])
					secLength := binary.LittleEndian.Uint16(packet[64+14 : 64+16])
					if secLength > 0 && int(secOffset)+int(secLength) <= len(packet) {
						ntlmType = detectNTLMType(packet[secOffset : secOffset+secLength])
					}
				}
				if debug {
					log.Printf("%s%s%s [SMB]%s pumpSMB: SessionSetup (msgID=%d, ntlmType=%d)%s",
						Grey, now(), Reset, Grey, downMsgID, ntlmType, Reset)
				}
				if ntlmType == 3 {
					if err := sendSyntheticSessionSetupAccept(down, downMsgID, client); err != nil {
						errCh <- err
						return
					}
				} else {
					if err := sendSyntheticSessionSetupChallenge(down, downMsgID, client); err != nil {
						errCh <- err
						return
					}
				}
				continue

			case 0x0002: // Logoff — respond locally, preserve upstream session
				downMsgID := binary.LittleEndian.Uint64(packet[24:32])
				if debug {
					log.Printf("%s%s%s [SMB]%s pumpSMB: Logoff → synthetic response%s",
						Grey, now(), Reset, Grey, Reset)
				}
				if err := sendSyntheticSimpleResponse(down, 0x0002, downMsgID, client); err != nil {
					errCh <- err
					return
				}
				continue

			case 0x0004: // TreeDisconnect — respond locally, keep upstream trees alive
				downMsgID := binary.LittleEndian.Uint64(packet[24:32])
				if debug {
					log.Printf("%s%s%s [SMB]%s pumpSMB: TreeDisconnect → synthetic response%s",
						Grey, now(), Reset, Grey, Reset)
				}
				if err := sendSyntheticSimpleResponse(down, 0x0004, downMsgID, client); err != nil {
					errCh <- err
					return
				}
				continue
			}

			// Forward to upstream with MessageID + SessionID rewriting
			downMsgID := binary.LittleEndian.Uint64(packet[24:32])

			client.upMsgIDMu.Lock()
			upMsgID := client.upNextMsgID
			client.upNextMsgID++
			client.upMsgIDMu.Unlock()

			pending.Store(upMsgID, downMsgID)
			client.dispatch.Store(upMsgID, respCh)

			binary.LittleEndian.PutUint64(packet[40:48], client.upSessionID)
			binary.LittleEndian.PutUint64(packet[24:32], upMsgID)

			if debug {
				log.Printf("%s%s%s [SMB]%s pumpSMB: → %s downMsgID=%d → upMsgID=%d (%d bytes)%s",
					Grey, now(), Reset, Grey, smb2CommandName(command), downMsgID, upMsgID, len(packet), Reset)
			}

			if err := client.upstreamSend(packet); err != nil {
				pending.Delete(upMsgID)
				client.dispatch.Delete(upMsgID)
				errCh <- io.EOF
				return
			}
		}
	}()

	// Wait for first error, then shut down
	<-errCh
	down.Close()

	// Remove dispatch entries for this tunnel's pending requests
	pending.Range(func(key, value any) bool {
		client.dispatch.Delete(key)
		return true
	})
	close(done) // signal response goroutine to exit

	<-errCh // wait for second goroutine

	// If upstream died, propagate so socks.go marks the session dead
	select {
	case <-client.upDead:
		return io.EOF
	default:
		return nil
	}
}
