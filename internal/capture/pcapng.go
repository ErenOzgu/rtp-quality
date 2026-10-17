package capture

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

const (
	blockSHB = 0x0a0d0d0a
	blockIDB = 0x00000001
	blockSPB = 0x00000003
	blockEPB = 0x00000006

	maxBlock = 1 << 25
)

type ngInterface struct {
	link int
	// unit is the length of one timestamp tick in nanoseconds.
	unit float64
}

// nanos converts timestamp ticks to nanoseconds, exactly when the tick is a whole number of them.
func (i ngInterface) nanos(ticks uint64) int64 {
	if i.unit >= 1 && i.unit == math.Trunc(i.unit) {
		return int64(ticks) * int64(i.unit)
	}
	return int64(float64(ticks) * i.unit)
}

func readPcapng(r *bufio.Reader, fn func(Packet), st *Stats) error {
	var bo binary.ByteOrder = binary.LittleEndian
	var ifaces []ngInterface
	var head [8]byte
	for {
		if _, err := io.ReadFull(r, head[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil
			}
			return err
		}
		// A section header decides the byte order for its section; its type is a palindrome.
		btype := binary.LittleEndian.Uint32(head[:4])
		if btype == blockSHB {
			var m [4]byte
			peek, err := r.Peek(4)
			if err != nil {
				return fmt.Errorf("pcapng section header: %w", err)
			}
			copy(m[:], peek)
			switch binary.LittleEndian.Uint32(m[:]) {
			case 0x1a2b3c4d:
				bo = binary.LittleEndian
			case 0x4d3c2b1a:
				bo = binary.BigEndian
			default:
				return fmt.Errorf("pcapng: bad byte-order magic %#x", m)
			}
			ifaces = ifaces[:0]
		} else {
			btype = bo.Uint32(head[:4])
		}
		total := int(bo.Uint32(head[4:8]))
		if total < 12 || total%4 != 0 || total > maxBlock {
			return fmt.Errorf("pcapng: implausible block length %d (corrupt file?)", total)
		}
		body := make([]byte, total-8)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil // truncated last block
		}
		body = body[:len(body)-4] // trailing copy of the length
		switch btype {
		case blockIDB:
			if len(body) < 8 {
				return fmt.Errorf("pcapng: short interface block")
			}
			ifaces = append(ifaces, ngInterface{
				link: int(bo.Uint16(body[0:2])),
				unit: tsUnit(bo, body[8:]),
			})
		case blockEPB:
			if len(body) < 20 {
				st.Malformed++
				continue
			}
			id := int(bo.Uint32(body[0:4]))
			caplen := int(bo.Uint32(body[12:16]))
			if id >= len(ifaces) || caplen < 0 || 20+caplen > len(body) {
				st.Malformed++
				continue
			}
			ticks := uint64(bo.Uint32(body[4:8]))<<32 | uint64(bo.Uint32(body[8:12]))
			ts := ifaces[id].nanos(ticks)
			deliver(ifaces[id].link, body[20:20+caplen], ts, fn, st)
		case blockSPB:
			st.Frames++
			st.NoTime++ // a simple packet has no timestamp, and quality needs one
		}
	}
}

// tsUnit reads the if_tsresol option; the default is microseconds.
func tsUnit(bo binary.ByteOrder, opts []byte) float64 {
	unit := 1e3
	for len(opts) >= 4 {
		code, n := bo.Uint16(opts[0:2]), int(bo.Uint16(opts[2:4]))
		if code == 0 {
			break
		}
		padded := (n + 3) &^ 3
		if 4+padded > len(opts) {
			break
		}
		if code == 9 && n >= 1 {
			v := opts[4]
			if v&0x80 != 0 {
				unit = 1e9 / math.Pow(2, float64(v&0x7f))
			} else {
				unit = 1e9 / math.Pow(10, float64(v))
			}
		}
		opts = opts[4+padded:]
	}
	return unit
}
