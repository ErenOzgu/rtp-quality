package rtp_test

import (
	"testing"

	"github.com/ErenOzgu/rtp-quality/internal/rtp"
)

func pkt(b0, b1 byte, extra ...byte) []byte {
	h := []byte{b0, b1, 0x12, 0x34, 0, 0, 0x01, 0x00, 0xde, 0xad, 0xbe, 0xef}
	return append(h, extra...)
}

func TestPlainPacket(t *testing.T) {
	b := pkt(0x80, 0x88, make([]byte, 160)...) // marker, PT 8
	h, ok := rtp.Parse(b, len(b))
	if !ok {
		t.Fatal("rejected")
	}
	if !h.Marker || h.PayloadType != 8 || h.Seq != 0x1234 || h.Timestamp != 256 || h.SSRC != 0xdeadbeef {
		t.Errorf("%+v", h)
	}
	if h.HeaderLen != 12 || h.PayloadLen != 160 {
		t.Errorf("header %d payload %d", h.HeaderLen, h.PayloadLen)
	}
}

func TestCSRCAndExtension(t *testing.T) {
	// two CSRCs, an extension of 3 words
	b := pkt(0x92, 0x00)
	b = append(b, make([]byte, 8)...)     // CSRCs
	b = append(b, 0xbe, 0xde, 0x00, 0x03) // extension header: length 3 words
	b = append(b, make([]byte, 12)...)    // extension body
	b = append(b, make([]byte, 100)...)   // payload
	h, ok := rtp.Parse(b, len(b))
	if !ok || h.HeaderLen != 12+8+4+12 || h.PayloadLen != 100 {
		t.Errorf("%+v ok=%v", h, ok)
	}
}

func TestPadding(t *testing.T) {
	b := pkt(0xa0, 0x00, make([]byte, 20)...)
	b[len(b)-1] = 4
	h, ok := rtp.Parse(b, len(b))
	if !ok || h.PayloadLen != 16 || h.PaddingBytes != 4 {
		t.Errorf("%+v ok=%v", h, ok)
	}
	// A count that cannot be right (zero, or more than the payload) is not trusted: SRTP encrypts
	// that byte. The packet is still RTP; it just keeps its full length.
	for _, bad := range []byte{0, 200} {
		b[len(b)-1] = bad
		h, ok := rtp.Parse(b, len(b))
		if !ok || h.PayloadLen != 20 || h.PaddingBytes != 0 {
			t.Errorf("padding byte %d: %+v ok=%v", bad, h, ok)
		}
	}
}

func TestCaptureCutShort(t *testing.T) {
	full := pkt(0x80, 0x00, make([]byte, 160)...)
	h, ok := rtp.Parse(full[:40], len(full))
	if !ok || h.PayloadLen != 160 {
		t.Errorf("snaplen-cut packet: %+v ok=%v", h, ok)
	}
}

func TestNotRTP(t *testing.T) {
	cases := map[string][]byte{
		"empty":         nil,
		"too short":     {0x80, 0, 0, 1},
		"version 1":     pkt(0x40, 0),
		"version 0":     pkt(0x00, 0),
		"STUN":          append([]byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42}, make([]byte, 12)...),
		"RTCP SR":       pkt(0x80, 200),
		"RTCP RR":       pkt(0x81, 201),
		"RTCP BYE":      pkt(0x81, 203),
		"RTCP RTPFB":    pkt(0x81, 205),
		"RTCP XR":       pkt(0x80, 207),
		"extension cut": pkt(0x90, 0),
	}
	for name, b := range cases {
		if _, ok := rtp.Parse(b, len(b)); ok {
			t.Errorf("%s was accepted as RTP", name)
		}
	}
	// the claimed UDP length is shorter than the header it needs
	b := pkt(0x82, 0)
	if _, ok := rtp.Parse(b, 12); ok {
		t.Error("CSRC list longer than the datagram accepted")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(pkt(0x80, 0, make([]byte, 20)...), 32)
	f.Add(pkt(0xb2, 0x88, make([]byte, 40)...), 60)
	f.Fuzz(func(t *testing.T, b []byte, udpLen int) {
		h, ok := rtp.Parse(b, udpLen)
		if !ok {
			return
		}
		if h.HeaderLen < 12 || h.PayloadLen < 0 || h.HeaderLen+h.PayloadLen+h.PaddingBytes != udpLen {
			t.Fatalf("inconsistent lengths for udpLen %d: %+v", udpLen, h)
		}
	})
}
