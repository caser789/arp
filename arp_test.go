package arp

import (
	"bytes"
	"io"
	"net"
	"reflect"
	"testing"

	"github.com/caser789/ethernet"
)

func TestNewPacket(t *testing.T) {
	zeroMAC := net.HardwareAddr{0, 0, 0, 0, 0, 0}

	var tests = []struct {
		desc   string
		op     Operation
		srcMAC net.HardwareAddr
		srcIP  net.IP
		dstMAC net.HardwareAddr
		dstIP  net.IP
		p      *Packet
		err    error
	}{
		{
			desc:   "short source MAC address",
			srcMAC: net.HardwareAddr{0, 0, 0, 0, 0},
			err:    ErrInvalidMAC,
		},
		{
			desc:   "short destination MAC address",
			srcMAC: zeroMAC,
			dstMAC: net.HardwareAddr{0, 0, 0, 0, 0},
			err:    ErrInvalidMAC,
		},
		{
			desc:   "MAC address length mismatch",
			srcMAC: zeroMAC,
			dstMAC: net.HardwareAddr{0, 0, 0, 0, 0, 0, 0, 0},
			err:    ErrInvalidMAC,
		},
		{
			desc:   "short source IPv4 address",
			srcMAC: zeroMAC,
			dstMAC: zeroMAC,
			srcIP:  net.IP{0, 0, 0},
			err:    ErrInvalidIP,
		},
		{
			desc:   "long source IPv4 address",
			srcMAC: zeroMAC,
			dstMAC: zeroMAC,
			srcIP:  net.IP{0, 0, 0, 0, 0},
			err:    ErrInvalidIP,
		},
		{
			desc:   "IPv6 source IP address",
			srcMAC: zeroMAC,
			dstMAC: zeroMAC,
			srcIP:  net.IPv6zero,
			err:    ErrInvalidIP,
		},
		{
			desc:   "short dest IPv4 address",
			srcMAC: zeroMAC,
			dstMAC: zeroMAC,
			srcIP:  net.IPv4zero,
			dstIP:  net.IP{0, 0, 0},
			err:    ErrInvalidIP,
		},
		{
			desc:   "long dest IPv4 address",
			srcMAC: zeroMAC,
			dstMAC: zeroMAC,
			srcIP:  net.IPv4zero,
			dstIP:  net.IP{0, 0, 0, 0, 0},
			err:    ErrInvalidIP,
		},
		{
			desc:   "IPv6 dest IP address",
			srcMAC: zeroMAC,
			dstMAC: zeroMAC,
			srcIP:  net.IPv4zero,
			dstIP:  net.IPv6zero,
			err:    ErrInvalidIP,
		},
		{
			desc:   "OK",
			op:     OperationRequest,
			srcMAC: zeroMAC,
			dstMAC: zeroMAC,
			srcIP:  net.IPv4zero,
			dstIP:  net.IPv4zero,
			p: &Packet{
				HardwareType: 1,
				ProtocolType: uint16(ethernet.EtherTypeIPv4),
				MACLength:    6,
				IPLength:     4,
				Operation:    OperationRequest,
				SenderMAC:    zeroMAC,
				SenderIP:     net.IPv4zero.To4(),
				TargetMAC:    zeroMAC,
				TargetIP:     net.IPv4zero.To4(),
			},
		},
	}

	for i, tt := range tests {
		p, err := NewPacket(tt.op, tt.srcMAC, tt.srcIP, tt.dstMAC, tt.dstIP)
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
					i, tt.desc, want, got)
			}

			continue
		}

		if want, got := tt.p, p; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected Packet:\n- want: %v\n- got: %v",
				i, tt.desc, want, got)
		}
	}
}

func TestPacketMarshalBinary(t *testing.T) {
	zeroMAC := net.HardwareAddr{0, 0, 0, 0, 0, 0}
	ip1 := net.IP{192, 168, 1, 10}
	ip2 := net.IP{192, 168, 1, 1}

	iboip1 := net.HardwareAddr(bytes.Repeat([]byte{0}, 20))
	iboip2 := net.HardwareAddr(bytes.Repeat([]byte{1}, 20))

	var tests = []struct {
		desc string
		p    *Packet
		b    []byte
	}{
		{
			desc: "ARP request to ethernet broadcast, 6 byte MAC addresses",
			p: &Packet{
				HardwareType: 1,
				ProtocolType: uint16(ethernet.EtherTypeIPv4),
				MACLength:    6,
				IPLength:     4,
				Operation:    OperationRequest,
				SenderMAC:    zeroMAC,
				SenderIP:     ip1,
				TargetMAC:    ethernet.Broadcast,
				TargetIP:     ip2,
			},
			b: []byte{
				0, 1,
				8, 0,
				6,
				4,
				0, 1,
				0, 0, 0, 0, 0, 0,
				192, 168, 1, 10,
				255, 255, 255, 255, 255, 255,
				192, 168, 1, 1,
			},
		},
		{
			desc: "ARP reply over infiniband, 20 byte MAC addresses",
			p: &Packet{
				HardwareType: 32,
				ProtocolType: uint16(ethernet.EtherTypeIPv4),
				MACLength:    20,
				IPLength:     4,
				Operation:    OperationReply,
				SenderMAC:    iboip1,
				SenderIP:     ip1,
				TargetMAC:    iboip2,
				TargetIP:     ip2,
			},
			b: []byte{
				0, 32,
				8, 0,
				20,
				4,
				0, 2,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				192, 168, 1, 10,
				1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
				1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
				192, 168, 1, 1,
			},
		},
	}

	for i, tt := range tests {
		b, err := tt.p.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}

		if want, got := tt.b, b; !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected Packet bytes:\n- want: %v\n- got: %v",
				i, tt.desc, want, got)
		}
	}
}

func TestPacketUnmarshalBinary(t *testing.T) {
	zeroMAC := net.HardwareAddr{0, 0, 0, 0, 0, 0}
	ip1 := net.IP{192, 168, 1, 10}
	ip2 := net.IP{192, 168, 1, 1}

	iboip1 := net.HardwareAddr(bytes.Repeat([]byte{0}, 20))
	iboip2 := net.HardwareAddr(bytes.Repeat([]byte{1}, 20))

	var tests = []struct {
		desc string
		p    *Packet
		b    []byte
		err  error
	}{
		{
			desc: "short buffer",
			b:    bytes.Repeat([]byte{0}, 7),
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "short buffer, too short for MAC addresses",
			b: []byte{
				0, 1,
				8, 0,
				255,
				4,
				0, 1,
			},
			err: io.ErrUnexpectedEOF,
		},
		{
			desc: "short buffer, too short for IP addresses",
			b: []byte{
				0, 1,
				8, 0,
				6,
				255,
				0, 1,
			},
			err: io.ErrUnexpectedEOF,
		},
		{
			desc: "ARP request to ethernet broadcast, 6 byte MAC addresses",
			b: []byte{
				0, 1,
				8, 0,
				6,
				4,
				0, 1,
				0, 0, 0, 0, 0, 0,
				192, 168, 1, 10,
				255, 255, 255, 255, 255, 255,
				192, 168, 1, 1,
			},
			p: &Packet{
				HardwareType: 1,
				ProtocolType: uint16(ethernet.EtherTypeIPv4),
				MACLength:    6,
				IPLength:     4,
				Operation:    OperationRequest,
				SenderMAC:    zeroMAC,
				SenderIP:     ip1,
				TargetMAC:    ethernet.Broadcast,
				TargetIP:     ip2,
			},
		},
		{
			desc: "ARP reply over infiniband, 20 byte MAC addresses",
			b: []byte{
				0, 32,
				8, 0,
				20,
				4,
				0, 2,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				192, 168, 1, 10,
				1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
				1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
				192, 168, 1, 1,
			},
			p: &Packet{
				HardwareType: 32,
				ProtocolType: uint16(ethernet.EtherTypeIPv4),
				MACLength:    20,
				IPLength:     4,
				Operation:    OperationReply,
				SenderMAC:    iboip1,
				SenderIP:     ip1,
				TargetMAC:    iboip2,
				TargetIP:     ip2,
			},
		},
	}

	for i, tt := range tests {
		p := new(Packet)
		if err := p.UnmarshalBinary(tt.b); err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
					i, tt.desc, want, got)
			}
			continue
		}

		if want, got := tt.p, p; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected Packet bytes:\n- want: %v\n- got: %v",
				i, tt.desc, want, got)
		}
	}
}
