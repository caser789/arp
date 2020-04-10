// Command arpc provides a simple ARP client which can be used to retrieve MAC
// addresses of other machines in a LAN using their IPv4 address.
package main

import (
    "flag"
    "fmt"
    "log"
    "net"

    "github.com/caser789/arp"
)

var (
    // ifaceFlag is used to set a network interface for ARP requests
    ifaceFlag = flag.String("i", "eth0", "network interface to use for ARP request")

    // ipFlag is used to set an IPv4 address destination for an ARP request
    ipFlag = flag.String("ip", "", "IPV4 address destination for ARP request")
)

func main() {
    flag.Parse()

    // Ensure valid network interface
    ifi, err := net.InterfaceByName(*ifaceFlag)
    if err != nil {
        log.Fatal(err)
    }

    // Set up ARP client with socket
    c, err := arp.NewClient(ifi)
    if err != nil {
        log.Fatal(err)
    }

    // Request MAC address for IP address
    ip := net.ParseIP(*ipFlag).To4()
    mac, err := c.Request(ip)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("%s -> %s", ip, mac)

    // Clean up ARP client socket
    _ = c.Close()
}