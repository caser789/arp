package arp

import (
    "bytes"
    "errors"
    "net"
    "log"
    // "syscall"

    // "github.com/caser789/ethernet"
    // "github.com/caser789/raw"
    "github.com/mdlayher/ethernet"
    "github.com/mdlayher/raw"
)

// A Client is an ARP client, which can be used to send ARP requests to
// retrieve the MAC address of a machine using its IPv4 address.
type Client struct {
    ifi *net.Interface
    ip net.IP
    p net.PacketConn
}

const protocolARP = 0x0806

// NewClient creates a new Client using the specified network interface.
// NewClient retrieves the IPv4 address of the interface and binds a raw socket
// to send and receive ARP packets.
func NewClient(ifi *net.Interface) (*Client, error) {
    // Check for a usable IPv4 address for the client
    addrs, err := ifi.Addrs()
    if err != nil {
        return nil, err
    }
    ip, err := firstIPv4Addr(addrs)
    if err != nil {
        return nil, err
    }

    // Open raw socket to send and receive ARP packets using ethernet frames
    p, err := raw.ListenPacket(ifi, protocolARP, nil)
    if err != nil {
        return nil, err
    }

    return &Client{
        ifi: ifi,
        ip: ip,
        p: p,
    }, nil
}

// Close closes the client's raw socket and stops sending and receiveing 
// ARP packets
func (c *Client) Close() error {
    return c.p.Close()
}

// Request performs an ARP request, attempting to retrieve the MAC address
// of a machine using its IPv4 address.
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

    eth := &ethernet.Frame{
        Destination: ethernet.Broadcast,
        Source: c.ifi.HardwareAddr,
        EtherType: ethernet.EtherTypeARP,
        Payload: arpb,
    }
    ethb, err := eth.MarshalBinary()
    if err != nil {
        return nil, err
    }

    _, err = c.p.WriteTo(ethb, &raw.Addr{
        HardwareAddr: ethernet.Broadcast,
    })
    if err != nil {
        return nil, err
    }

    buf := make([]byte, 128)
    for {
        n, _, err := c.p.ReadFrom(buf)
        if err != nil {
            return nil, err
        }

        if err := eth.UnmarshalBinary(buf[:n]); err != nil {
            return nil, err
        }

        if err := arp.UnmarshalBinary(eth.Payload); err != nil {
            return nil, err
        }

        if bytes.Equal(arp.TargetMAC, c.ifi.HardwareAddr) {
            return arp.SenderMAC, nil
        }

    }
}

func firstIPv4Addr(addrs []net.Addr) (net.IP, error) {
    for _, a := range addrs {
        log.Println("Network")
        log.Println(a.Network())
        if a.Network() != "ip+net" {
            continue
        }

        ip, _, err := net.ParseCIDR(a.String())
        if err != nil {
            return nil, err
        }

        if ip4 := ip.To4(); ip4 != nil {
            return ip4, nil
        }
    }

    return nil, errors.New("no IPv4 address")
}
