package capture

import (
	"encoding/binary"
	"net/netip"
)

// Link types (LINKTYPE_* from the tcpdump.org registry).
const (
	linkNull     = 0
	linkEthernet = 1
	linkRaw      = 101
	linkSLL      = 113
	linkIPv4     = 228
	linkIPv6     = 229
	linkSLL2     = 276
)

// result of decoding a frame
type decoded int

const (
	decUDP decoded = iota
	decOther
	decFragment
	decMalformed
	decUnsupported
)

// decodeFrame finds the UDP datagram in a captured frame.
func decodeFrame(link int, data []byte, ts int64, pkt *Packet) decoded {
	var proto uint16 // ethertype of the network layer, 0 when decided by the version nibble
	var ip []byte
	switch link {
	case linkEthernet:
		if len(data) < 14 {
			return decMalformed
		}
		proto = binary.BigEndian.Uint16(data[12:14])
		off := 14
		for proto == 0x8100 || proto == 0x88a8 || proto == 0x9100 { // VLAN tags, possibly stacked
			if len(data) < off+4 {
				return decMalformed
			}
			proto = binary.BigEndian.Uint16(data[off+2 : off+4])
			off += 4
		}
		ip = data[off:]
	case linkNull:
		if len(data) < 4 {
			return decMalformed
		}
		af := binary.LittleEndian.Uint32(data[:4]) // written in the capturing host's byte order
		if af > 0xff {
			af = binary.BigEndian.Uint32(data[:4])
		}
		switch af {
		case 2:
			proto = 0x0800
		case 10, 24, 28, 30: // AF_INET6 differs between Linux (10) and the BSDs
			proto = 0x86dd
		default:
			return decOther
		}
		ip = data[4:]
	case linkRaw, linkIPv4, linkIPv6:
		ip = data
	case linkSLL:
		if len(data) < 16 {
			return decMalformed
		}
		proto = binary.BigEndian.Uint16(data[14:16])
		ip = data[16:]
	case linkSLL2:
		if len(data) < 20 {
			return decMalformed
		}
		proto = binary.BigEndian.Uint16(data[0:2])
		ip = data[20:]
	default:
		return decUnsupported
	}
	if proto == 0 { // raw IP: the first nibble says which
		if len(ip) < 1 {
			return decMalformed
		}
		switch ip[0] >> 4 {
		case 4:
			proto = 0x0800
		case 6:
			proto = 0x86dd
		default:
			return decMalformed
		}
	}
	switch proto {
	case 0x0800:
		return decodeIPv4(ip, ts, pkt)
	case 0x86dd:
		return decodeIPv6(ip, ts, pkt)
	}
	return decOther
}

func decodeIPv4(b []byte, ts int64, pkt *Packet) decoded {
	if len(b) < 20 || b[0]>>4 != 4 {
		return decMalformed
	}
	ihl := int(b[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if ihl < 20 || len(b) < ihl || total < ihl {
		return decMalformed
	}
	if total < len(b) { // Ethernet pads short frames
		b = b[:total]
	}
	if b[9] != 17 {
		return decOther
	}
	if binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 { // more-fragments flag or a non-zero offset
		return decFragment
	}
	src, _ := netip.AddrFromSlice(b[12:16])
	dst, _ := netip.AddrFromSlice(b[16:20])
	return decodeUDP(b[ihl:], src, dst, ts, pkt)
}

func decodeIPv6(b []byte, ts int64, pkt *Packet) decoded {
	if len(b) < 40 || b[0]>>4 != 6 {
		return decMalformed
	}
	payloadLen := int(binary.BigEndian.Uint16(b[4:6]))
	next := b[6]
	src, _ := netip.AddrFromSlice(b[8:24])
	dst, _ := netip.AddrFromSlice(b[24:40])
	rest := b[40:]
	if payloadLen > 0 && payloadLen < len(rest) {
		rest = rest[:payloadLen]
	}
	for hops := 0; hops < 8; hops++ {
		switch next {
		case 17:
			return decodeUDP(rest, src, dst, ts, pkt)
		case 0, 43, 60: // hop-by-hop, routing, destination options: next header, length in 8-byte units
			if len(rest) < 8 {
				return decMalformed
			}
			n := (int(rest[1]) + 1) * 8
			if len(rest) < n {
				return decMalformed
			}
			next, rest = rest[0], rest[n:]
		case 51: // authentication header: length in 4-byte units
			if len(rest) < 8 {
				return decMalformed
			}
			n := (int(rest[1]) + 2) * 4
			if len(rest) < n {
				return decMalformed
			}
			next, rest = rest[0], rest[n:]
		case 44:
			return decFragment
		default:
			return decOther
		}
	}
	return decMalformed
}

func decodeUDP(b []byte, src, dst netip.Addr, ts int64, pkt *Packet) decoded {
	if len(b) < 8 {
		return decMalformed
	}
	length := int(binary.BigEndian.Uint16(b[4:6]))
	if length < 8 {
		return decMalformed
	}
	payload := b[8:]
	if length-8 < len(payload) {
		payload = payload[:length-8]
	}
	*pkt = Packet{
		Time:    ts,
		Src:     netip.AddrPortFrom(src.Unmap(), binary.BigEndian.Uint16(b[0:2])),
		Dst:     netip.AddrPortFrom(dst.Unmap(), binary.BigEndian.Uint16(b[2:4])),
		Payload: payload,
		UDPLen:  length - 8,
	}
	return decUDP
}

// deliver decodes one frame and updates the statistics.
func deliver(link int, data []byte, ts int64, fn func(Packet), st *Stats) {
	st.Frames++
	var pkt Packet
	switch decodeFrame(link, data, ts, &pkt) {
	case decUDP:
		st.UDP++
		fn(pkt)
	case decOther:
		st.Other++
	case decFragment:
		st.Fragments++
	case decMalformed:
		st.Malformed++
	case decUnsupported:
		st.Unsupported[link]++
	}
}
