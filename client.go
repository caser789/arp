package arp

import (
	"bytes"
	"errors"
	"net"
	"syscall"
	"time"

	"github.com/caser789/ethernet"
	"github.com/caser789/raw"
)

// A Client is an ARP client, which can be used to send ARP requests to
// retrieve the MAC address of a machine using its IPv4 address.
type Client struct {
	ifi *net.Interface
	ip  net.IP
	p   *raw.Conn
}

// NewClient creates a new Client using the specified network interface.
// NewClient retrieves the IPv4 address of the interface and binds a raw socket
// to send and receive ARP packets
func NewClient(ifi *net.Interface) (*Client, error) {
	// Check for usable IPv4 address for the Client
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}

	ip, err := firstIPv4Addr(addrs)
	if err != nil {
		return nil, err
	}

	// Open raw socket to send and receive ARP packets using ethernet frames
	// we build ourselves
	p, err := raw.ListenPacket(ifi, syscall.ETH_P_ARP)
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

		// Unmarshal ethernet frame and ARP packet
		if err := eth.UnmarshalBinary(buf[:n]); err != nil {
			return nil, err
		}

		if err := arp.UnmarshalBinary(eth.Payload); err != nil {
			return nil, err
		}

		// Check if ARP is in reply to our MAC address
		if bytes.Equal(arp.TargetMAC, c.ifi.HardwareAddr) {
			return arp.SenderMAC, nil
		}
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

	return nil, errors.New("no IPv4 address")
}
