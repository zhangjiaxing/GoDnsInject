package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func getDnsInjectServer() *DnsInjectServer {
	dnsServer := NewDnsInjectServer()
	dnsServer.AddRecord("gw.com", "192.168.1.1")
	dnsServer.AddRecord("gw.com", "192.168.1.1")
	dnsServer.AddRecord("gw.com", "192.168.1.2")
	dnsServer.AddRecord("gw.com", "192.168.1.3")
	dnsServer.AddRecord("gw.com", "192.168.1.4")
	dnsServer.AddRecord("gw.com", "192.168.1.5")
	dnsServer.AddRecord("gw.com", "192.168.1.6")
	dnsServer.AddRecord("gw.com", "192.168.1.7")
	dnsServer.AddRecord("gw.com", "192.168.1.8")
	dnsServer.AddRecord("gw.com", "192.168.1.9")
	dnsServer.AddRecord("gw.com", "192.168.1.10")

	dnsServer.AddRecord("test.com", "asdf34ga")
	dnsServer.AddRecord("test.com", "192.168.1.1")

	dnsServer.AddRecord("test.com", "192.168.2.10")
	dnsServer.AddRecord("test.com", "192.168.2.100")
	dnsServer.AddRecord("test.com", ".1asdfadfwe")

	dnsServer.AddRecord("test.com", "fe80::800:27ff:fe00:0")
	dnsServer.AddRecord("test.com", "::1")
	dnsServer.AddRecord("test.com", "::1")
	dnsServer.AddRecord("test.com", "::1asdfadfwe")

	return dnsServer
}

func main() {
	dnsInjectServer := getDnsInjectServer()

	if handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("udp and port 53"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			dnsLayer := packet.Layer(layers.LayerTypeDNS)
			if dnsLayer != nil {
				handlePacket(&packet, dnsInjectServer, handle)
			}
		}
	}
}

const (
	QRdnsQuery    = false
	QRdnsResponse = true
)

func handlePacket(packet *gopacket.Packet, dnsInjectServer *DnsInjectServer, handle *pcap.Handle) {
	dnsLayer := (*packet).Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		fmt.Println("dnsLayer is nil")
		return
	}

	// dnsData := dnsLayer.LayerContents()
	// dnsStruct := &layers.DNS{}

	// if err := dnsStruct.DecodeFromBytes(dnsData, gopacket.NilDecodeFeedback); err != nil {
	// 	log.Fatalf("could not decode: %v", err)
	// }

	// if dnsStruct.QR != QRdnsQuery {
	// 	return
	// }

	// request := dnsStruct.Questions[0]
	// fmt.Println("Query for ", string(request.Name))
	// responseList, ok := dnsInjectServer.Lookup(string(request.Name), request.Type)
	// if ok {
	// 	fmt.Println("Response ", responseList)
	// }

	writeData := dnsInjectServer.GetDNSResponseBytes(packet)

	if err := handle.WritePacketData(writeData); err != nil {
		panic(err)
	}
}
