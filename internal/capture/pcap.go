package capture

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

const maxFrame = 1 << 24 // anything larger is a corrupt length field, not a packet

func isPcapMagic(b []byte) bool {
	switch binary.BigEndian.Uint32(b) {
	case 0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1:
		return true
	}
	return false
}

func readPcap(r *bufio.Reader, fn func(Packet), st *Stats) error {
	var hdr [24]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return fmt.Errorf("pcap header: %w", err)
	}
	var bo binary.ByteOrder
	var nano bool
	switch binary.BigEndian.Uint32(hdr[:4]) {
	case 0xa1b2c3d4:
		bo = binary.BigEndian
	case 0xd4c3b2a1:
		bo = binary.LittleEndian
	case 0xa1b23c4d:
		bo, nano = binary.BigEndian, true
	case 0x4d3cb2a1:
		bo, nano = binary.LittleEndian, true
	}
	link := int(bo.Uint32(hdr[20:24]) & 0x0fffffff) // the top bits carry the FCS length
	var rec [16]byte
	buf := make([]byte, 0, 2048)
	for {
		if _, err := io.ReadFull(r, rec[:]); err != nil {
			if err == io.EOF {
				return nil
			}
			if err == io.ErrUnexpectedEOF {
				return nil // a capture cut off mid-record is normal when tcpdump is killed
			}
			return err
		}
		sec, frac := int64(bo.Uint32(rec[0:4])), int64(bo.Uint32(rec[4:8]))
		incl := int(bo.Uint32(rec[8:12]))
		if incl < 0 || incl > maxFrame {
			return fmt.Errorf("pcap record %d: implausible length %d (corrupt file?)", st.Frames+1, incl)
		}
		if cap(buf) < incl {
			buf = make([]byte, incl)
		}
		buf = buf[:incl]
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil // truncated last record
		}
		ts := sec * 1e9
		if nano {
			ts += frac
		} else {
			ts += frac * 1e3
		}
		deliver(link, buf, ts, fn, st)
	}
}
