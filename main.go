package main

import (
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func getDnsInjectServer() *DnsInjectServer {
	dnsServer := NewDnsInjectServer()
	dnsServer.Register("gw.local", "192.168.1.1")
	dnsServer.Register("gw.local", "192.168.1.1")
	dnsServer.Register("gw.local", "192.168.1.2")
	dnsServer.Register("gw.local", "192.168.1.3")
	dnsServer.Register("gw.local", "192.168.1.4")

	dnsServer.Register("test.local", "asdf34ga")
	dnsServer.Register("test.local", "192.168.1.1")

	dnsServer.Register("test.local", "192.168.2.10")
	dnsServer.Register("test.local", "192.168.2.100")
	dnsServer.Register("test.local", ".1asdfadfwe")

	dnsServer.Register("test.local", "fe80::800:27ff:fe00:0")
	dnsServer.Register("test.local", "::1")
	dnsServer.Register("test.local", "::1")
	dnsServer.Register("test.local", "::1asdfadfwe")

	return dnsServer
}

func main() {
	f, err := os.Create("/tmp/eth0.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	pcapw := pcapgo.NewWriter(f)
	if err := pcapw.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		log.Fatalf("WriteFileHeader: %v", err)
	}

	handle, err := pcapgo.NewEthernetHandle("eth0")
	if err != nil {
		log.Fatalf("OpenEthernet: %v", err)
	}

	pkgsrc := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)

	dnsInjectServer := getDnsInjectServer()

	for packet := range pkgsrc.Packets() {
		// if err := pcapw.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
		// 	log.Fatalf("pcap.WritePacket(): %v", err)
		// }

		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil {
			fmt.Println("got one DNS packet")
			handlePacket(&packet, dnsInjectServer, pcapw)
		}
	}
}

const (
	QRdnsQuery    = false
	QRdnsResponse = true
)

func handlePacket(packet *gopacket.Packet, dnsInjectServer *DnsInjectServer, pcapw *pcapgo.Writer) {
	dnsLayer := (*packet).Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		fmt.Println("dnsLayer is nil")
		return
	}

	dnsData := dnsLayer.LayerContents()
	dnsStruct := &layers.DNS{}

	if err := dnsStruct.DecodeFromBytes(dnsData, gopacket.NilDecodeFeedback); err != nil {
		log.Fatalf("could not decode: %v", err)
	}

	if dnsStruct.QR != QRdnsQuery {
		return
	}

	writeData := dnsInjectServer.GetDNSResponseBytes(packet)

	captureInfo := (*packet).Metadata().CaptureInfo
	captureInfo.Length = len(writeData)
	captureInfo.CaptureLength = len(writeData)

	if err := pcapw.WritePacket(captureInfo, writeData); err != nil {
		log.Fatalf("pcap.WritePacket(): %v", err)
	}

	//ques := dnsStruct.Questions

	//for _, query := range ques {
	// qryName := string(query.Name)

	// if targetIpList, has := dnsInjectServer.Lookup(qryName, query.Type); has {
	// 	for _, target := range targetIpList {
	// 		fmt.Println("DNS Inject ", qryName, query.Type, target.String())
	// 	}
	// }
	//}

	// answers := dnsStruct.Answers
	// for _, ans := range answers {
	// 	fmt.Println("DNS Response", string(ans.Name), ans.Type, ans.IP, string(ans.CNAME))
	// }

	fmt.Print("\n\n")
}
