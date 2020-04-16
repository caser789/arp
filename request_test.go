package arp

import (
	"io"
	"net"
	"reflect"
	"testing"
)

func Test_parseRequest(t *testing.T) {
	var tests = []struct {
		desc string
		buf  []byte
		r    *Request
		err  error
	}{
		{
			desc: "invalid ethernet frame",
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "non-ARP EtherType",
			buf:  make([]byte, 56),
			err:  errInvalidARPPacket,
		},
		{
			desc: "invalid ARP Packet",
			buf: append([]byte{
				0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0,
				0x08, 0x06,
				0, 0,
				0, 0,
				255, 255,
			}, make([]byte, 40)...),
			err: io.ErrUnexpectedEOF,
		},
		{
			desc: "OK",
			buf: append([]byte{
				0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
				0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
				0x08, 0x06,
				0, 1,
				0x08, 0x06,
				6,
				4,
				0, 2,
				0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
				192, 168, 1, 10,
				0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
				192, 168, 1, 1,
			}, make([]byte, 40)...),
			r: &Request{
				Operation: OperationReply,
				SenderMAC: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
				SenderIP:  net.IP{192, 168, 1, 10},
				TargetMAC: net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad},
				TargetIP:  net.IP{192, 168, 1, 1},
			},
		},
	}

	for i, tt := range tests {
		r, err := parseRequest(tt.buf)
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
					i, tt.desc, want, got)
			}

			continue
		}

		if want, got := tt.r, r; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected Packet:\n- want: %v\n- got: %v",
				i, tt.desc, want, got)
		}
	}
}
