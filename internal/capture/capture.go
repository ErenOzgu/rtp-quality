// Package capture reads packet captures (classic pcap and pcapng) and hands
// every UDP datagram to a callback. It understands the link layers real
// captures come with (Ethernet with VLAN tags, Linux "any" cooked captures,
// loopback, raw IP) and IPv4 and IPv6, and it has no dependencies.
package capture

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

// Packet is one UDP datagram.
type Packet struct {
	// Time is the capture timestamp in nanoseconds since the Unix epoch.
	Time int64
	Src  netip.AddrPort
	Dst  netip.AddrPort
	// Payload is the UDP payload as far as it was captured.
	Payload []byte
	// UDPLen is the payload length the UDP header claims. It is larger than
	// len(Payload) when the capture was cut short (snaplen).
	UDPLen int
}

// Stats says what was in the file.
type Stats struct {
	Format      string      // "pcap" or "pcapng"
	Frames      int         // frames read
	UDP         int         // UDP datagrams delivered
	Other       int         // frames that are not UDP over IP (ARP, TCP, ...)
	Fragments   int         // IP fragments, which are skipped
	Malformed   int         // frames too short or inconsistent to decode
	NoTime      int         // pcapng simple packets: no timestamp, skipped
	Unsupported map[int]int // link type -> frames that could not be decoded
}

// ErrFormat means the input is neither pcap nor pcapng.
var ErrFormat = errors.New("not a pcap or pcapng file")

// Read parses a capture from r and calls fn for each UDP datagram in file order.
// The Payload slice is only valid during the call.
func Read(r io.Reader, fn func(Packet)) (Stats, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	magic, err := br.Peek(4)
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return Stats{}, fmt.Errorf("%w: file is shorter than a header", ErrFormat)
		}
		return Stats{}, err
	}
	st := Stats{Unsupported: map[int]int{}}
	switch {
	case isPcapMagic(magic):
		st.Format = "pcap"
		err = readPcap(br, fn, &st)
	case magic[0] == 0x0a && magic[1] == 0x0d && magic[2] == 0x0d && magic[3] == 0x0a:
		st.Format = "pcapng"
		err = readPcapng(br, fn, &st)
	default:
		return st, ErrFormat
	}
	return st, err
}
