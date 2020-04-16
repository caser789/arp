package arp

import (
	"io"
	"net"
	"syscall"

	"github.com/caser789/ethernet"
	"github.com/caser789/raw"
)

// A Server is an ARP server, and is used to configure an ARP server's
// behavior
type Server struct {
	// Iface is the network interface on which this server should
	// listen
	Iface *net.Interface

	// Handler is the handler to use while serving ARP requests. If this
	// value is nil, DefaultServeMux will be used in place of Handler
	Handler Handler
}

// ListenAndServe listens for ARP requests using a raw ethernet socket on
// the specified interface, using the default Server configuration and
// specified handler to handle ARP requests. If the handler is nil,
// DefaultServeMux is used instead
func ListenAndServe(iface string, handler Handler) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}

	return (&Server{Iface: ifi, Handler: handler}).ListenAndServe()
}

// ListenAndServe listens for ARP requests using a raw ethernet socket on the
// network interface specified by s.Iface. Serve is called to handle serving
// traffic once ListenAndServe opens a raw ethernet socket
func (s *Server) ListenAndServe() error {
	p, err := raw.ListenPacket(s.Iface, syscall.ETH_P_ARP)
	if err != nil {
		return err
	}

	return s.Serve(p)
}

// Serve accepts incoming connections ARP requests on net.PacketConn p,
// creating a new goroutine for each
//
// The service goroutine reads requests, generates the appropriate Request and
// ResponseSender values, then calls s.Handler to handle the request
func (s *Server) Serve(p net.PacketConn) error {
	defer p.Close()

	buf := make([]byte, 128)
	for {
		n, addr, err := p.ReadFrom(buf)
		if err != nil {
            if err == io.EOF {
                return nil
            }

			return err
		}

		c := s.newConn(p, addr.(*raw.Addr), n, buf)
		go c.serve()
	}
}

// A conn is an in-flight ARP request which contains information about a
// request to the server
type conn struct {
	p          net.PacketConn
	remoteAddr *raw.Addr
	server     *Server
	buf        []byte
}

// newConn creates a new conn using information received in a single ARP
// request. newConn makes a copy of the input buffer for use in handling
// a single connection
func (s *Server) newConn(p net.PacketConn, addr *raw.Addr, n int, buf []byte) *conn {
	c := &conn{
		p:          p,
		remoteAddr: addr,
		server:     s,
		buf:        make([]byte, n),
	}
	copy(c.buf, buf[:n])

	return c
}

// serve handles serving an individual ARP request, and is invoked in a
// goroutine
func (c *conn) serve() {
	r, err := parseRequest(c.buf)
	if err != nil {
        if err == errInvalidARPPacket {
            return
        }

		return
	}

	w := &response{
		p:          c.p,
		remoteAddr: c.remoteAddr,
	}

	handler := c.server.Handler
	if handler == nil {
		handler = DefaultServeMux
	}

	handler.ServeARP(w, r)
}

// response represents an ARP response, and implements ResponseSender so that
// outbound Packets can be appropriately created and sent to a client
type response struct {
	p          net.PacketConn
	remoteAddr *raw.Addr
}

// Send marshals an input Packet to binary form, wraps it in an ethernet frame,
// and sneds it to the hardware address specified by r.remoteAddr
func (r *response) Send(p *Packet) (int, error) {
	pb, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}

	f := &ethernet.Frame{
		Destination: p.TargetMAC,
		Source:      p.SenderMAC,
		EtherType:   ethernet.EtherTypeARP,
		Payload:     pb,
	}

	fb, err := f.MarshalBinary()
	if err != nil {
		return 0, err
	}

	return r.p.WriteTo(fb, r.remoteAddr)
}
