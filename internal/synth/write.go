package synth

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Link is the link layer the frames are written with.
type Link int

// Link layers the writer can produce, so that the reader can be tested against each.
const (
	LinkEthernet Link = iota
	LinkVLAN
	LinkRaw
	LinkNull
	LinkSLL
	LinkSLL2
	LinkIPv4 // LINKTYPE_IPV4 (228); IPv4 frames only
)

// Options choose the file format.
type Options struct {
	Format    string // "pcap" or "pcapng"
	Link      Link
	BigEndian bool
	Nano      bool // nanosecond timestamps (pcap magic variant or if_tsresol 9)
}

func (o Options) order() binary.ByteOrder {
	if o.BigEndian {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

func (l Link) linkType() uint32 {
	switch l {
	case LinkRaw:
		return 101
	case LinkNull:
		return 0
	case LinkSLL:
		return 113
	case LinkSLL2:
		return 276
	case LinkIPv4:
		return 228
	}
	return 1
}

// IPPacket builds the IP and UDP headers around a payload.
func IPPacket(d Datagram) []byte {
	udpLen := 8 + len(d.Payload)
	udp := make([]byte, 8, udpLen)
	binary.BigEndian.PutUint16(udp[0:], d.Src.Port())
	binary.BigEndian.PutUint16(udp[2:], d.Dst.Port())
	binary.BigEndian.PutUint16(udp[4:], uint16(udpLen))
	udp = append(udp, d.Payload...)

	if d.Src.Addr().Is4() {
		ip := make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(20+udpLen))
		ip[8] = 64
		ip[9] = 17
		s, t := d.Src.Addr().As4(), d.Dst.Addr().As4()
		copy(ip[12:], s[:])
		copy(ip[16:], t[:])
		binary.BigEndian.PutUint16(ip[10:], checksum(ip))
		return append(ip, udp...)
	}
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(udpLen))
	ip[6] = 17
	ip[7] = 64
	s, t := d.Src.Addr().As16(), d.Dst.Addr().As16()
	copy(ip[8:], s[:])
	copy(ip[24:], t[:])
	// UDP over IPv6 must carry a checksum (RFC 8200 section 8.1).
	pseudo := append(append(append([]byte(nil), s[:]...), t[:]...), 0, 0, byte(udpLen>>8), byte(udpLen), 0, 0, 0, 17)
	c := checksum(append(pseudo, udp...))
	if c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:], c)
	return append(ip, udp...)
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// Frame wraps an IP packet in the link layer.
func Frame(d Datagram, l Link, bo binary.ByteOrder) []byte {
	ip := IPPacket(d)
	v6 := d.Src.Addr().Is6()
	etype := uint16(0x0800)
	if v6 {
		etype = 0x86dd
	}
	var h []byte
	switch l {
	case LinkEthernet, LinkVLAN:
		h = make([]byte, 14)
		copy(h[0:], []byte{0x02, 0, 0, 0, 0, 2})
		copy(h[6:], []byte{0x02, 0, 0, 0, 0, 1})
		binary.BigEndian.PutUint16(h[12:], etype)
		if l == LinkVLAN {
			binary.BigEndian.PutUint16(h[12:], 0x8100)
			h = append(h, 0, 5, byte(etype>>8), byte(etype))
		}
	case LinkNull:
		h = make([]byte, 4)
		af := uint32(2)
		if v6 {
			af = 10
		}
		bo.PutUint32(h, af)
	case LinkSLL:
		h = make([]byte, 16)
		binary.BigEndian.PutUint16(h[2:], 1)
		binary.BigEndian.PutUint16(h[4:], 6)
		binary.BigEndian.PutUint16(h[14:], etype)
	case LinkSLL2:
		h = make([]byte, 20)
		binary.BigEndian.PutUint16(h[0:], etype)
		binary.BigEndian.PutUint32(h[4:], 1)
		binary.BigEndian.PutUint16(h[8:], 1)
		h[11] = 6
	}
	return append(h, ip...)
}

// Write writes the datagrams as a capture file.
func Write(w io.Writer, pkts []Datagram, o Options) error {
	for _, p := range pkts {
		if p.Src.Addr().Is4() != p.Dst.Addr().Is4() {
			return fmt.Errorf("source %s and destination %s are not the same IP version", p.Src, p.Dst)
		}
		if o.Link == LinkIPv4 && !p.Src.Addr().Is4() {
			return fmt.Errorf("link type IPv4 cannot carry %s", p.Src)
		}
	}
	switch o.Format {
	case "", "pcap":
		return writePcap(w, pkts, o)
	case "pcapng":
		return writePcapng(w, pkts, o)
	}
	return fmt.Errorf("unknown capture format %q", o.Format)
}

func writePcap(w io.Writer, pkts []Datagram, o Options) error {
	bo := o.order()
	var buf bytes.Buffer
	magic := uint32(0xa1b2c3d4)
	if o.Nano {
		magic = 0xa1b23c4d
	}
	h := make([]byte, 24)
	bo.PutUint32(h[0:], magic)
	bo.PutUint16(h[4:], 2)
	bo.PutUint16(h[6:], 4)
	bo.PutUint32(h[16:], 65535)
	bo.PutUint32(h[20:], o.Link.linkType())
	buf.Write(h)
	for _, p := range pkts {
		fr := Frame(p, o.Link, bo)
		rec := make([]byte, 16)
		sec, frac := p.Time/1e9, p.Time%1e9
		if !o.Nano {
			frac /= 1000
		}
		bo.PutUint32(rec[0:], uint32(sec))
		bo.PutUint32(rec[4:], uint32(frac))
		bo.PutUint32(rec[8:], uint32(len(fr)))
		bo.PutUint32(rec[12:], uint32(len(fr)))
		buf.Write(rec)
		buf.Write(fr)
	}
	_, err := w.Write(buf.Bytes())
	return err
}

func pad4(n int) int { return (n + 3) &^ 3 }

func ngBlock(bo binary.ByteOrder, typ uint32, body []byte) []byte {
	total := 12 + pad4(len(body))
	b := make([]byte, total)
	bo.PutUint32(b[0:], typ)
	bo.PutUint32(b[4:], uint32(total))
	copy(b[8:], body)
	bo.PutUint32(b[total-4:], uint32(total))
	return b
}

func writePcapng(w io.Writer, pkts []Datagram, o Options) error {
	bo := o.order()
	var buf bytes.Buffer
	shb := make([]byte, 16)
	bo.PutUint32(shb[0:], 0x1a2b3c4d)
	bo.PutUint16(shb[4:], 1)
	bo.PutUint16(shb[6:], 0)
	bo.PutUint64(shb[8:], ^uint64(0)) // section length unknown
	buf.Write(ngBlock(bo, 0x0a0d0d0a, shb))

	idb := make([]byte, 8)
	bo.PutUint16(idb[0:], uint16(o.Link.linkType()))
	bo.PutUint32(idb[4:], 65535)
	if o.Nano {
		// Option if_tsresol (code 9, one byte, padded to four) = 9: nanosecond ticks.
		opt := make([]byte, 12)
		bo.PutUint16(opt[0:], 9)
		bo.PutUint16(opt[2:], 1)
		opt[4] = 9
		// the last four bytes stay zero: opt_endofopt
		idb = append(idb, opt...)
	}
	buf.Write(ngBlock(bo, 1, idb))

	for _, p := range pkts {
		fr := Frame(p, o.Link, bo)
		ts := uint64(p.Time)
		if !o.Nano {
			ts /= 1000
		}
		body := make([]byte, 20, 20+pad4(len(fr)))
		bo.PutUint32(body[4:], uint32(ts>>32))
		bo.PutUint32(body[8:], uint32(ts))
		bo.PutUint32(body[12:], uint32(len(fr)))
		bo.PutUint32(body[16:], uint32(len(fr)))
		body = append(body, fr...)
		buf.Write(ngBlock(bo, 6, body))
	}
	_, err := w.Write(buf.Bytes())
	return err
}
