raw [![Build Status](https://travis-ci.org/caser789/arp.svg?branch=master)](https://travis-ci.org/caser789/arp)
[![GoDoc](https://godoc.org/github.com/caser789/arp?status.svg)](https://godoc.org/github.com/caser789/arp)
[![Go Report Card](https://goreportcard.com/badge/github.com/caser789/arp)](https://goreportcard.com/report/github.com/caser789/arp)
[![Coverage Status](https://coveralls.io/repos/caser789/arp/badge.svg?branch=master)](https://coveralls.io/r/caser789/arp?branch=master)
=====

![class uml diagram](./arp.png)

```
@startuml

title arp

interface net.Interface {}
interface net.IP {}
interface net.PacketConn {}
interface net.HardwareAddr {}

class ethernet.Frame {}

class Client {
    -ifi net.Interface
    -ip net.IP
    -p net.PacketConn
    +Close()
    +Request(net.IP)
    +Resolve(net.IP net.HardwareAddr
    +Read() Packet ethernet.Frame
    +WriteTo(Packet, net.HardwareAddr)
    +Reply(Packet, net.HardwareAddr, net.IP)
    +SetDeadline()
    +SetReadDeadline()
    +SetWriteDeadline()
    +HardwareAddr()
}

class Packet {
    +HardwareType
    +ProtocolType
    +MACLength
    +IPLength
    +Operation
    +SenderMAC
    +SenderIP
    +TargetMAC
    +TargetIP
    +MarshalBinary() []byte
    +UnmarshalBinary([]byte)
}

@enduml
```
