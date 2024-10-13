package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <interface>\n", os.Args[0])
		os.Exit(1)
	}

	ifaceName := os.Args[1]

	handle, err := pcap.OpenLive(ifaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to open device: %v", err)
	}
	defer handle.Close()

	// Set up signal handling to close the program cleanly on interrupt.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Printf("Firewall started on %s, waiting for packets...\n", ifaceName)

	go func() {
		for packet := range packetSource.Packets() {
			processPacket(packet)
		}
	}()

	<-sigChan
	fmt.Println("\nFirewall stopped")
}

func processPacket(packet gopacket.Packet) {
	// Get Ethernet layer
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer != nil {
		ethPacket, _ := ethLayer.(*layers.Ethernet)
		fmt.Printf("Ethernet: %s -> %s\n", ethPacket.SrcMAC, ethPacket.DstMAC)
	}

	// Get IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ipPacket, _ := ipLayer.(*layers.IPv4)
		fmt.Printf("IPv4: %s -> %s\n", ipPacket.SrcIP, ipPacket.DstIP)

		// Check for TCP packets
		if ipPacket.Protocol == layers.IPProtocolTCP {
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				tcpPacket, _ := tcpLayer.(*layers.TCP)
				fmt.Printf("TCP: %s:%d -> %s:%d\n", ipPacket.SrcIP, tcpPacket.SrcPort, ipPacket.DstIP, tcpPacket.DstPort)

				// Example rule: Drop all packets to port 80 (HTTP)
				if tcpPacket.DstPort == 80 {
					fmt.Println("Dropping packet to port 80 (HTTP)")
					return
				}
			}
		}

		// Check for UDP packets
		if ipPacket.Protocol == layers.IPProtocolUDP {
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer != nil {
				udpPacket, _ := udpLayer.(*layers.UDP)
				fmt.Printf("UDP: %s:%d -> %s:%d\n", ipPacket.SrcIP, udpPacket.SrcPort, ipPacket.DstIP, udpPacket.DstPort)
			}
		}

		// Check for ICMP packets
		if ipPacket.Protocol == layers.IPProtocolICMPv4 {
			icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
			if icmpLayer != nil {
				fmt.Println("ICMP packet detected")
			}
		}
	}
}
