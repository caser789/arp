package arp

import (
	"bytes"
	"errors"
	"net"
	"time"

	"github.com/caser789/ethernet"
	"github.com/caser789/raw"
)

var (
	// errNoIPv4Addr is returned when an interface does not have an IPv4
	// address
	errNoIPv4Addr = errors.New("no IPv4 address available for interface")
)

// A Client is an ARP client, which can be used to send ARP requests to
// retrieve the MAC address of a machine using its IPv4 address.
type Client struct {
	ifi *net.Interface
	ip  net.IP
	p   net.PacketConn
}

// NewClient creates a new Client using the specified network interface.
// NewClient retrieves the IPv4 address of the interface and binds a raw socket
// to send and receive ARP packets
func NewClient(ifi *net.Interface) (*Client, error) {
	// Open raw socket to send and receive ARP packets using ethernet frames
	p, err := raw.ListenPacket(ifi, raw.ProtocolARP)
	if err != nil {
		return nil, err
	}

	// Check for usable IPv4 addresses for the client
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}

	return newClient(ifi, p, addrs)
}

// newClient is the internal, generic implementation of newClient. It is used
// to allow an arbitrary net.PacketConn to be used in a client, so testing
// is easier to accomplish
func newClient(ifi *net.Interface, p net.PacketConn, addrs []net.Addr) (*Client, error) {
	ip, err := firstIPv4Addr(addrs)
	if err != nil {
		return nil, err
	}

	return &Client{
		ifi: ifi,
		ip:  ip,
		p:   p,
	}, nil
}

// Close closes the Client's raw socket and stops sending and receiving
// ARP packets
func (c *Client) Close() error {
	return c.p.Close()
}

// Request performs an ARP request, attempting to retrieve the MAC address
// of a machine using its IPv4 address
func (c *Client) Request(ip net.IP) (net.HardwareAddr, error) {
	// Create ARP packet addressed to broadcast MAC to attempt to find the
	// hardware address of the input IP address
	arp, err := NewPacket(OperationRequest, c.ifi.HardwareAddr, c.ip, ethernet.Broadcast, ip)
	if err != nil {
		return nil, err
	}

	arpb, err := arp.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// Create ethernet frame addressed to broadcast MAC to encapsulate the
	// ARP packet
	eth := &ethernet.Frame{
		Destination: ethernet.Broadcast,
		Source:      c.ifi.HardwareAddr,
		EtherType:   ethernet.EtherTypeARP,
		Payload:     arpb,
	}
	ethb, err := eth.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// Write frame to ethernet broadcast address
	_, err = c.p.WriteTo(ethb, &raw.Addr{
		HardwareAddr: ethernet.Broadcast,
	})
	if err != nil {
		return nil, err
	}

	// Loop and wait for replies
	buf := make([]byte, 128)
	for {
		n, _, err := c.p.ReadFrom(buf)
		if err != nil {
			return nil, err
		}

		// Unmarshal ethernet frame and check:
		//   - Frame is for our MAC address
		//   - Frame has ARP EtherType
		if err := eth.UnmarshalBinary(buf[:n]); err != nil {
			return nil, err
		}
		if !bytes.Equal(eth.Destination, c.ifi.HardwareAddr) {
			continue
		}
		if eth.EtherType != ethernet.EtherTypeARP {
			continue
		}

		// Unmarshal ARP packet and check
		//    - Packet is a reply, not a request
		//    - Packet is for our IP address
		//    - Packet is for our MAC address
		//    - Packet is a reply to our query, not another query
		if err := arp.UnmarshalBinary(eth.Payload); err != nil {
			return nil, err
		}
		if arp.Operation != OperationReply {
			continue
		}
		if !arp.TargetIP.Equal(c.ip) {
			continue
		}
		if !bytes.Equal(arp.TargetMAC, c.ifi.HardwareAddr) {
			continue
		}
        if !ip.Equal(arp.SenderIP) {
            continue
        }

		return arp.SenderMAC, nil
	}
}

// SetDeadline sets the read and write deadlines associated with the
// connection
func (c *Client) SetDeadline(t time.Time) error {
	return c.p.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future raw socket read calls
func (c *Client) SetReadDeadline(t time.Time) error {
	return c.p.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future raw socket write calls
func (c *Client) SetWriteDeadline(t time.Time) error {
	return c.p.SetWriteDeadline(t)
}

// firstIPv4Addr attempts to retrieve the first detected IPv4 address from an
// input slice of network addresses.
func firstIPv4Addr(addrs []net.Addr) (net.IP, error) {
	for _, a := range addrs {
		if a.Network() != "ip+net" {
			continue
		}

		ip, _, err := net.ParseCIDR(a.String())
		if err != nil {
			return nil, err
		}

		// If ip is not an IPv4 address, To4 returns nil
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
	}

	return nil, errNoIPv4Addr
}
