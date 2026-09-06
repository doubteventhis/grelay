package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
)

// parses a type 3 authentication 
func parseNTLMv2AuthIdentity(raw []byte) (domain, user, workstation string, err error) {
	if len(raw) < 64 || !bytes.Equal(raw[:8], []byte("NTLMSSP\x00")) || binary.LittleEndian.Uint32(raw[8:12]) != 3 {
		return "", "", "", fmt.Errorf("not NTLMSSP Type 3")
	}
	readBuf := func(off int) ([]byte, error) {
		if off+8 > len(raw) {
			return nil, fmt.Errorf("short secbuf hdr")
		}
		l := int(binary.LittleEndian.Uint16(raw[off+0 : off+2]))
		o := int(binary.LittleEndian.Uint32(raw[off+4 : off+8]))
		if o+l > len(raw) {
			return nil, fmt.Errorf("secbuf OOB")
		}
		return raw[o : o+l], nil
	}
	const (
		ofsDomain      = 28
		ofsUser        = 36
		ofsWorkstation = 44
	)
	db, err := readBuf(ofsDomain)
	if err != nil {
		return "", "", "", err
	}
	ub, err := readBuf(ofsUser)
	if err != nil {
		return "", "", "", err
	}
	wb, err := readBuf(ofsWorkstation)
	if err != nil {
		return "", "", "", err
	}
	utf16LEToString := func(b []byte) string {
		u16 := make([]uint16, len(b)/2)
		for i := range u16 {
			u16[i] = binary.LittleEndian.Uint16(b[2*i:])
		}
		r := make([]rune, len(u16))
		for i := range u16 {
			r[i] = rune(u16[i])
		}
		return string(r)
	}
	return utf16LEToString(db), utf16LEToString(ub), utf16LEToString(wb), nil
}

// generates a fake type 2 challenge so we can enumerate the user
func sendFakeType2() string {
    type2 := make([]byte, 40)
    copy(type2[0:8], []byte("NTLMSSP\x00"))              // Identifier
    binary.LittleEndian.PutUint32(type2[8:12], 2)        // Type 2
    binary.LittleEndian.PutUint16(type2[12:14], 0)       // Target Name Len
    binary.LittleEndian.PutUint16(type2[14:16], 0)       // Target Name Max Len
    binary.LittleEndian.PutUint32(type2[16:20], 40)      // Target Name Offset (point to end)
    binary.LittleEndian.PutUint32(type2[20:24], 0x8205)  // Flags: NTLM, Always Sign, Unicode

	nonce := make([]byte, 8)
    rand.Read(nonce)
    copy(type2[24:32], nonce)

	binary.LittleEndian.PutUint32(type2[32:36], 0)       // Context (all zeros)
    binary.LittleEndian.PutUint32(type2[36:40], 40)      // Target Info Offset (point to end)
    return "NTLM " + base64.StdEncoding.EncodeToString(type2)
}

// checks an auth header to check for ntlm auth
func validateAuthHeader(authValue string) (uint32, []byte) {
	parts := strings.SplitN(authValue, " ", 2)
	if len(parts) != 2 {
		return 0, nil
	}
	raw, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, nil
	}
	if len(raw) >= 12 && bytes.Equal(raw[:8], []byte("NTLMSSP\x00")) {
		return binary.LittleEndian.Uint32(raw[8:12]), raw
	}
	return 0, nil
}