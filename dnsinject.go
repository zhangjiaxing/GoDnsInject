package main

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type DnsInjectServer struct {
	dnsMap4 map[string][]net.IP
	dnsMap6 map[string][]net.IP
}

func prepend(ipList []net.IP, element net.IP) []net.IP {
	ipListLen := len(ipList)
	if cap(ipList) == ipListLen {
		retList := make([]net.IP, ipListLen+1, ipListLen+2)
		copy(retList[1:ipListLen+1], ipList[:])
		retList[0] = element
		return retList
	} else {
		ipList = ipList[:ipListLen+1]
		copy(ipList[1:ipListLen+1], ipList[:ipListLen])
		ipList[0] = element
		return ipList
	}
}

func NewDnsInjectServer() *DnsInjectServer {
	self := DnsInjectServer{}
	self.dnsMap4 = make(map[string][]net.IP)
	self.dnsMap6 = make(map[string][]net.IP)
	return &self
}

func (self *DnsInjectServer) Empty(domainName string) {
	delete(self.dnsMap4, domainName)
	delete(self.dnsMap6, domainName)
}

func (self *DnsInjectServer) AddRecord4(domainName string, ip net.IP) {
	if ip == nil {
		return
	}

	val, check := self.dnsMap4[domainName]
	if check == false {
		val = []net.IP{}
	}

	for _, curIp := range val {
		if curIp.Equal(ip) {
			return
		}
	}

	val = prepend(val, ip)
	self.dnsMap4[domainName] = val
}

func (self *DnsInjectServer) AddRecord6(domainName string, ip net.IP) {
	if ip == nil {
		return
	}

	val, check := self.dnsMap6[domainName]
	if check == false {
		val = []net.IP{}
	}

	for _, curIp := range val {
		if curIp.Equal(ip) {
			return
		}
	}

	val = prepend(val, ip)
	self.dnsMap6[domainName] = val
}

func (self *DnsInjectServer) AddRecord(domainName string, ipStr string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return
	}

	for _, c := range ipStr {
		if c == '.' {
			self.AddRecord4(domainName, ip)
			break

		} else if c == ':' {
			self.AddRecord6(domainName, ip)
			break
		}
	}
}

func (self *DnsInjectServer) Lookup4(domainName string) ([]net.IP, bool) {
	ip, hased := self.dnsMap4[domainName]
	return ip, hased
}

func (self *DnsInjectServer) Lookup6(domainName string) ([]net.IP, bool) {
	ip, hased := self.dnsMap6[domainName]
	return ip, hased
}

func (self *DnsInjectServer) Lookup(domainName string, dnsType layers.DNSType) ([]net.IP, bool) {
	switch dnsType {
	case layers.DNSTypeA:
		return self.Lookup4(domainName)

	case layers.DNSTypeAAAA:
		return self.Lookup6(domainName)
	default:
		return nil, false
	}
}

func (self *DnsInjectServer) GetAnswers(request *layers.DNSQuestion) []layers.DNSResourceRecord {
	var answerList []layers.DNSResourceRecord

	answerIPList, _ := self.Lookup(string(request.Name), request.Type)

	for _, answerIP := range answerIPList {
		record := layers.DNSResourceRecord{
			Name:  request.Name,
			Type:  request.Type,
			Class: request.Class,
			TTL:   60,
			IP:    answerIP,
		}
		answerList = append(answerList, record)
	}

	return answerList
}

func (self *DnsInjectServer) GetResponseDNSLayer(packet *gopacket.Packet) *layers.DNS {
	dnsLayer := (*packet).Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return nil
	}

	dnsData := dnsLayer.LayerContents()
	request := &layers.DNS{}

	if err := request.DecodeFromBytes(dnsData, gopacket.NilDecodeFeedback); err != nil {
		return nil
	}

	questions := request.Questions

	response := &layers.DNS{
		BaseLayer:    layers.BaseLayer{},
		ID:           request.ID,
		QR:           true,
		OpCode:       0,
		AA:           false,
		TC:           false,
		RD:           true,
		RA:           true,
		Z:            0,
		ResponseCode: 0,
		QDCount:      uint16(len(questions)),
		ANCount:      0,
		NSCount:      0,
		ARCount:      0,
		Questions:    questions,
		Answers:      []layers.DNSResourceRecord{},
	}

	for _, question := range questions {
		answers := self.GetAnswers(&question)

		respAnsLen := len(response.Answers)
		if cap(response.Answers) < respAnsLen+len(answers) {
			newAnswers := make([]layers.DNSResourceRecord, respAnsLen+len(answers), respAnsLen+len(answers))
			copy(newAnswers, response.Answers)
			copy(newAnswers[respAnsLen:], answers)
			response.Answers = newAnswers
		} else {
			copy(response.Answers[respAnsLen:], answers)
		}
	}
	response.ANCount = uint16(len(response.Answers))

	return response
}

func (self *DnsInjectServer) GetResponseIPv4Layer(packet *gopacket.Packet) *layers.IPv4 {
	networkLayer := (*packet).NetworkLayer()
	networkContents := networkLayer.LayerContents()

	if networkLayer.LayerType() == layers.LayerTypeIPv4 {
		recvipv4header := layers.IPv4{}
		recvipv4header.DecodeFromBytes(networkContents, gopacket.NilDecodeFeedback)
		srcIP := recvipv4header.SrcIP
		dstIP := recvipv4header.DstIP

		ipv4header := &layers.IPv4{
			Version:  4,
			TTL:      64,
			SrcIP:    dstIP,
			DstIP:    srcIP,
			Protocol: layers.IPProtocolUDP,
		}
		return ipv4header
	}
	return nil
}

func (self *DnsInjectServer) GetResponseIPv6Layer(packet *gopacket.Packet) *layers.IPv6 {
	networkLayer := (*packet).NetworkLayer()
	networkContents := networkLayer.LayerContents()

	if networkLayer.LayerType() == layers.LayerTypeIPv6 {
		recvipv6header := layers.IPv6{}
		recvipv6header.DecodeFromBytes(networkContents, gopacket.NilDecodeFeedback)
		flowLable := recvipv6header.FlowLabel
		srcIP := recvipv6header.SrcIP
		dstIP := recvipv6header.DstIP

		ipv6header := &layers.IPv6{
			Version:    6,
			FlowLabel:  flowLable,
			NextHeader: layers.IPProtocolUDP,
			HopLimit:   64,
			SrcIP:      dstIP,
			DstIP:      srcIP,
		}
		return ipv6header
	}
	return nil
}

func (self *DnsInjectServer) GetResponseUDPLayer(packet *gopacket.Packet) *layers.UDP {
	transportLayer := (*packet).TransportLayer()
	udpContents := transportLayer.LayerContents()

	if transportLayer.LayerType() == layers.LayerTypeUDP {
		recvUDPheader := layers.UDP{}
		recvUDPheader.DecodeFromBytes(udpContents, gopacket.NilDecodeFeedback)
		srcPort := recvUDPheader.SrcPort
		dstPort := recvUDPheader.DstPort

		udpheader := &layers.UDP{
			SrcPort: dstPort,
			DstPort: srcPort,
		}

		return udpheader
	}
	return nil
}

func (self *DnsInjectServer) GetResponseEthernetLayer(packet *gopacket.Packet) *layers.Ethernet {
	linkLayer := (*packet).LinkLayer()
	ethernetContents := linkLayer.LayerContents()

	if linkLayer.LayerType() == layers.LayerTypeEthernet {
		recvEthernetheader := layers.Ethernet{}
		recvEthernetheader.DecodeFromBytes(ethernetContents, gopacket.NilDecodeFeedback)
		srcMAC := recvEthernetheader.SrcMAC
		dstMAC := recvEthernetheader.DstMAC
		ethernetType := recvEthernetheader.EthernetType

		ethernetheader := &layers.Ethernet{
			SrcMAC:       dstMAC,
			DstMAC:       srcMAC,
			EthernetType: ethernetType,
		}
		return ethernetheader
	}
	return nil
}

func (self *DnsInjectServer) GetDNSResponseBytes(packet *gopacket.Packet) []byte {
	ethLayer := self.GetResponseEthernetLayer(packet)

	ipLayerType := (*packet).NetworkLayer().LayerType()
	var ipLayer gopacket.NetworkLayer

	switch ipLayerType {
	case layers.LayerTypeIPv4:
		ipLayer = self.GetResponseIPv4Layer(packet)
	case layers.LayerTypeIPv6:
		ipLayer = self.GetResponseIPv6Layer(packet)
	default:
		return nil
	}

	udpLayer := self.GetResponseUDPLayer(packet)
	dnsLayer := self.GetResponseDNSLayer(packet)

	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	switch ipLayerType {
	case layers.LayerTypeIPv4:
		if err := gopacket.SerializeLayers(buffer, options,
			ethLayer,
			ipLayer.(*layers.IPv4),
			udpLayer,
			dnsLayer,
		); err != nil {
			panic(err)
		}

	case layers.LayerTypeIPv6:
		if err := gopacket.SerializeLayers(buffer, options,
			ethLayer,
			ipLayer.(*layers.IPv6),
			udpLayer,
			dnsLayer,
		); err != nil {
			panic(err)
		}
	}

	return buffer.Bytes()
}
