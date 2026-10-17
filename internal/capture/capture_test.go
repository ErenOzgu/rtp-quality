package capture_test

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/ErenOzgu/rtp-quality/internal/capture"
	"github.com/ErenOzgu/rtp-quality/internal/synth"
)

func samples(v6 bool) []synth.Datagram {
	src := netip.MustParseAddrPort("192.0.2.1:4000")
	dst := netip.MustParseAddrPort("192.0.2.2:5000")
	if v6 {
		src = netip.MustParseAddrPort("[2001:db8::1]:4000")
		dst = netip.MustParseAddrPort("[2001:db8::2]:5000")
	}
	var out []synth.Datagram
	for i := 0; i < 5; i++ {
		out = append(out, synth.Datagram{
			Time: 1_700_000_000_123_456_000 + int64(i)*20_000_000, Src: src, Dst: dst,
			Payload: []byte{0x80, 0, 0, byte(i), 1, 2, 3, 4, 5, 6, 7, 8, 0xaa, byte(i)},
		})
	}
	return out
}

func readAll(t *testing.T, b []byte) ([]capture.Packet, capture.Stats) {
	t.Helper()
	var got []capture.Packet
	st, err := capture.Read(bytes.NewReader(b), func(p capture.Packet) {
		p.Payload = append([]byte(nil), p.Payload...)
		got = append(got, p)
	})
	if err != nil {
		t.Fatal(err)
	}
	return got, st
}

func TestEveryFormatAndLinkLayer(t *testing.T) {
	links := map[string]synth.Link{
		"ethernet": synth.LinkEthernet, "vlan": synth.LinkVLAN, "raw": synth.LinkRaw,
		"null": synth.LinkNull, "sll": synth.LinkSLL, "sll2": synth.LinkSLL2, "ipv4": synth.LinkIPv4,
	}
	for _, format := range []string{"pcap", "pcapng"} {
		for lname, link := range links {
			for _, big := range []bool{false, true} {
				for _, nano := range []bool{false, true} {
					for _, v6 := range []bool{false, true} {
						if v6 && link == synth.LinkIPv4 {
							continue
						}
						name := strings.Join([]string{format, lname, map[bool]string{false: "le", true: "be"}[big], map[bool]string{false: "us", true: "ns"}[nano], map[bool]string{false: "v4", true: "v6"}[v6]}, "/")
						t.Run(name, func(t *testing.T) {
							want := samples(v6)
							var buf bytes.Buffer
							if err := synth.Write(&buf, want, synth.Options{Format: format, Link: link, BigEndian: big, Nano: nano}); err != nil {
								t.Fatal(err)
							}
							got, st := readAll(t, buf.Bytes())
							if st.Format != format || st.UDP != len(want) || st.Frames != len(want) {
								t.Fatalf("stats: %+v", st)
							}
							for i, w := range want {
								g := got[i]
								if g.Src != w.Src || g.Dst != w.Dst || !bytes.Equal(g.Payload, w.Payload) || g.UDPLen != len(w.Payload) {
									t.Fatalf("packet %d: %+v want %+v", i, g, w)
								}
								wantT := w.Time
								if !nano {
									wantT = w.Time / 1000 * 1000
								}
								if g.Time != wantT {
									t.Fatalf("packet %d time %d, want %d", i, g.Time, wantT)
								}
							}
						})
					}
				}
			}
		}
	}
}

func TestNanosecondPrecisionSurvivesPcapng(t *testing.T) {
	// 1.7e18 ns does not fit a float64 mantissa; the reader must not round it.
	d := samples(false)
	d[0].Time = 1_700_000_000_000_000_001
	var buf bytes.Buffer
	if err := synth.Write(&buf, d, synth.Options{Format: "pcapng", Nano: true}); err != nil {
		t.Fatal(err)
	}
	got, _ := readAll(t, buf.Bytes())
	if got[0].Time != d[0].Time {
		t.Errorf("time %d, want %d", got[0].Time, d[0].Time)
	}
}

func TestNotACapture(t *testing.T) {
	for name, in := range map[string]string{"empty": "", "text": "hello, this is not a capture", "short": "\xd4\xc3"} {
		_, err := capture.Read(strings.NewReader(in), func(capture.Packet) {})
		if err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestTruncatedFilesAreTolerated(t *testing.T) {
	var buf bytes.Buffer
	if err := synth.Write(&buf, samples(false), synth.Options{}); err != nil {
		t.Fatal(err)
	}
	full := buf.Bytes()
	for _, cut := range []int{len(full) - 1, len(full) - 20, len(full) - 70} {
		got, _ := readAll(t, full[:cut])
		if len(got) != 4 {
			t.Errorf("cut at %d bytes: %d packets, want the 4 whole ones", cut, len(got))
		}
	}
	buf.Reset()
	if err := synth.Write(&buf, samples(false), synth.Options{Format: "pcapng"}); err != nil {
		t.Fatal(err)
	}
	got, _ := readAll(t, buf.Bytes()[:buf.Len()-5])
	if len(got) != 4 {
		t.Errorf("pcapng cut: %d packets, want 4", len(got))
	}
}

func TestCorruptLengthIsAnError(t *testing.T) {
	var buf bytes.Buffer
	_ = synth.Write(&buf, samples(false), synth.Options{})
	b := buf.Bytes()
	binary.LittleEndian.PutUint32(b[24+8:], 0x7fffffff) // first record's captured length
	if _, err := capture.Read(bytes.NewReader(b), func(capture.Packet) {}); err == nil {
		t.Error("an absurd record length was accepted")
	}
}

func TestSnapLengthCutShowsInUDPLen(t *testing.T) {
	d := samples(false)[0]
	d.Payload = append(d.Payload, make([]byte, 100)...)
	frame := synth.Frame(d, synth.LinkEthernet, binary.LittleEndian)
	cut := frame[:14+20+8+20] // keep only 20 bytes of UDP payload
	var buf bytes.Buffer
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h, 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(h[4:], 2)
	binary.LittleEndian.PutUint16(h[6:], 4)
	binary.LittleEndian.PutUint32(h[16:], 62)
	binary.LittleEndian.PutUint32(h[20:], 1)
	buf.Write(h)
	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[8:], uint32(len(cut)))
	binary.LittleEndian.PutUint32(rec[12:], uint32(len(frame)))
	buf.Write(rec)
	buf.Write(cut)
	got, st := readAll(t, buf.Bytes())
	if len(got) != 1 || len(got[0].Payload) != 20 || got[0].UDPLen != len(d.Payload) {
		t.Fatalf("payload %d bytes, UDPLen %d, stats %+v", len(got[0].Payload), got[0].UDPLen, st)
	}
}

func TestFragmentsAndOtherTrafficAreCountedNotDecoded(t *testing.T) {
	d := samples(false)[0]
	udp := synth.Frame(d, synth.LinkEthernet, binary.LittleEndian)
	frag := append([]byte(nil), udp...)
	frag[14+6] |= 0x20 // more-fragments
	tcp := append([]byte(nil), udp...)
	tcp[14+9] = 6
	arp := append([]byte(nil), udp[:14]...)
	arp[12], arp[13] = 0x08, 0x06
	short := udp[:10]

	var buf bytes.Buffer
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h, 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(h[4:], 2)
	binary.LittleEndian.PutUint16(h[6:], 4)
	binary.LittleEndian.PutUint32(h[16:], 65535)
	binary.LittleEndian.PutUint32(h[20:], 1)
	buf.Write(h)
	for _, f := range [][]byte{udp, frag, tcp, arp, short} {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(f)))
		binary.LittleEndian.PutUint32(rec[12:], uint32(len(f)))
		buf.Write(rec)
		buf.Write(f)
	}
	got, st := readAll(t, buf.Bytes())
	if len(got) != 1 || st.Fragments != 1 || st.Other != 2 || st.Malformed != 1 || st.Frames != 5 {
		t.Errorf("got %d packets, stats %+v", len(got), st)
	}
}

func TestUnsupportedLinkType(t *testing.T) {
	var buf bytes.Buffer
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h, 0xa1b2c3d4)
	binary.LittleEndian.PutUint32(h[20:], 105) // 802.11
	buf.Write(h)
	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[8:], 4)
	binary.LittleEndian.PutUint32(rec[12:], 4)
	buf.Write(rec)
	buf.Write([]byte{1, 2, 3, 4})
	_, st := readAll(t, buf.Bytes())
	if st.Unsupported[105] != 1 {
		t.Errorf("stats %+v", st)
	}
}

func FuzzRead(f *testing.F) {
	for _, o := range []synth.Options{{}, {Format: "pcapng"}, {BigEndian: true, Nano: true}, {Format: "pcapng", BigEndian: true, Nano: true, Link: synth.LinkSLL2}} {
		var buf bytes.Buffer
		_ = synth.Write(&buf, samples(false), o)
		f.Add(buf.Bytes())
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		// Whatever the bytes are, reading must neither panic nor hand out a payload longer than the datagram.
		_, _ = capture.Read(bytes.NewReader(b), func(p capture.Packet) {
			if len(p.Payload) > p.UDPLen {
				t.Fatalf("payload %d bytes but UDP length %d", len(p.Payload), p.UDPLen)
			}
		})
	})
}
