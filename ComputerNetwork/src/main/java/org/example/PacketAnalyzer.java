package org.example;

import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IcmpV4Type;

public class PacketAnalyzer {
    public String analyzePacket(Packet packet) {
        int length = packet.length();

        if (packet.contains(ArpPacket.class)) {
            ArpPacket arpPacket = packet.get(ArpPacket.class);

            String srcIp = arpPacket.getHeader().getSrcProtocolAddr().getHostAddress();
            String dstIp = arpPacket.getHeader().getSrcProtocolAddr().getHostAddress();

            return "ARP | " + srcIp + " -> " + dstIp + " | len= " + length;
        }

        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);

            String srcIp = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
            String dstIp = ipV4Packet.getHeader().getDstAddr().getHostAddress();

            if (packet.contains(IcmpV4CommonPacket.class)) {

                IcmpV4CommonPacket icmp = packet.get(IcmpV4CommonPacket.class);
                IcmpV4Type type = icmp.getHeader().getType();

                if (type.equals(IcmpV4Type.ECHO)) {
                    return "ICMP ECHO REQUEST | " + srcIp + " -> " + dstIp + " | len=" + length;
                }

                if (type.equals(IcmpV4Type.ECHO_REPLY)) {
                    return "ICMP ECHO REPLY | " + srcIp + " -> " + dstIp + " | len=" + length;
                }

                return "ICMP OTHER | " + srcIp + " -> " + dstIp + " | len=" + length;
            }

            if (packet.contains(TcpPacket.class)) {
                TcpPacket tcpPacket = packet.get(TcpPacket.class);

                int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
                int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();

                return "TCP | " + srcIp + ":" + srcPort + " -> " + dstIp + ":" + dstPort + " | len=" + length;
            }

            if (packet.contains(UdpPacket.class)) {
                UdpPacket udpPacket = packet.get(UdpPacket.class);

                int srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
                int dstPort = udpPacket.getHeader().getDstPort().valueAsInt();

                return "UDP | " + srcIp + ":" + srcPort + " -> " + dstIp + ":" + dstPort + " | len=" + length;
            }

            return "IPv4 | " + srcIp + " -> " + dstIp + " | len=" + length;
        }

        return "OTHER | len=" + length;
    }

}
