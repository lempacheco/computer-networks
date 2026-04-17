package org.example;

import org.pcap4j.packet.*;

public class PacketAnalyzer {
    public String detectProtocol(Packet packet) {
        if (packet.contains(ArpPacket.class)) {
            return "ARP";
        }

        if (packet.contains(IpV4Packet.class)) {
            if (packet.contains(IcmpV4CommonPacket.class)) {
                return "ICMP";
            }
            if (packet.contains(TcpPacket.class)) {
                return "TCP";
            }
            if (packet.contains(UdpPacket.class)) {
                return "UDP";
            }
            return "IPv4";
        }

        return "OTHER";
    }


}
