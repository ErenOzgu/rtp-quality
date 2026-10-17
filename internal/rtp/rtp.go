// Package rtp parses RTP headers (RFC 3550) and tells RTP apart from the other
// UDP traffic that shares a capture.
package rtp

import "encoding/binary"

// Header is the fixed part of an RTP packet plus what follows it.
type Header struct {
	Marker       bool
	PayloadType  uint8
	Seq          uint16
	Timestamp    uint32
	SSRC         uint32
	HeaderLen    int // fixed header, CSRC list and extension
	PayloadLen   int // payload without padding, as far as the UDP length claims
	PaddingBytes int
}

// Parse decodes an RTP header from the captured part of a UDP payload.
// udpLen is the payload length the UDP header claims, which exceeds len(b)
// when the capture was cut short. It returns false if the bytes are not
// plausibly RTP.
func Parse(b []byte, udpLen int) (Header, bool) {
	if len(b) < 12 || b[0]>>6 != 2 {
		return Header{}, false
	}
	// RTCP packet types 192-223 (RFC 5761) would be payload types 64-95 with the
	// marker bit set; nothing sends RTP there, and they are how RTCP shows up
	// on a muxed port.
	if b[1] >= 192 && b[1] <= 223 {
		return Header{}, false
	}
	h := Header{
		Marker:      b[1]&0x80 != 0,
		PayloadType: b[1] & 0x7f,
		Seq:         binary.BigEndian.Uint16(b[2:4]),
		Timestamp:   binary.BigEndian.Uint32(b[4:8]),
		SSRC:        binary.BigEndian.Uint32(b[8:12]),
	}
	n := 12 + 4*int(b[0]&0x0f)
	if b[0]&0x10 != 0 { // header extension: 16-bit profile, 16-bit length in words
		if len(b) < n+4 {
			return Header{}, false
		}
		n += 4 + 4*int(binary.BigEndian.Uint16(b[n+2:n+4]))
	}
	if udpLen < n {
		return Header{}, false
	}
	h.HeaderLen = n
	h.PayloadLen = udpLen - n
	// Padding: the last byte of the packet counts the padding bytes. When that byte makes no
	// sense (SRTP encrypts it, a cut-short capture lacks it) the padding is simply not
	// subtracted: only the bit rate depends on it.
	if b[0]&0x20 != 0 && len(b) >= udpLen {
		if p := int(b[udpLen-1]); p > 0 && p <= h.PayloadLen {
			h.PaddingBytes = p
			h.PayloadLen -= p
		}
	}
	return h, true
}
