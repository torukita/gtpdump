package main

import (
    "flag"
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
    "github.com/torukita/gtpdump/gtp"
    "log"
    "time"
)

var (
    snapshot_len int32  = 1024
    promiscuous  bool   = false
    err          error
    timeout      time.Duration = 10 * time.Second
    handle       *pcap.Handle
	debug bool
	pcapFile string
	device string
)

func main() {
	flag.BoolVar(&debug, "debug", false, "debug option")
	flag.StringVar(&pcapFile, "f", "", "pcap file")
	flag.Parse()
	if len(flag.Args()) != 0 {
        device = flag.Args()[0]
    }
	fmt.Printf("device=%s\n", device)
	fmt.Println(debug)
	fmt.Println(pcapFile)
	if pcapFile != "" {
		handle, err = pcap.OpenOffline(pcapFile)
	} else {
		handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	}
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

    // Set filter
    var filter string = "udp and port 2152"
    err = handle.SetBPFFilter(filter)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Only capturing UDP port 2152 packets.")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

    var eth layers.Ethernet
    var ip  layers.IPv4
    var udp layers.UDP
	var payload gopacket.Payload

    for packet := range packetSource.Packets() {
        parser := gopacket.NewDecodingLayerParser(
            layers.LayerTypeEthernet,
            &eth,
            &ip,
            &udp,
			&payload,
        )
        foundLayerTypes := []gopacket.LayerType{}

        err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
        if err != nil {
            fmt.Println("Trouble decoding layers: ", err)
        }

        for _, layerType := range foundLayerTypes {
            if layerType == layers.LayerTypeIPv4 {
                fmt.Println("   IPv4: ", ip.SrcIP, "->", ip.DstIP)
            }
            if layerType == layers.LayerTypeUDP {
                fmt.Println("   UDP Port: ", udp.SrcPort, "->", udp.DstPort)
            }
			if layerType == gopacket.LayerTypePayload {
				packet := gopacket.NewPacket(
					payload,
					gtp.LayerTypeGTPv1,
					gopacket.Default,
				)
				fmt.Println(packet)
			}
        }
    }
}

