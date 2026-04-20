package sniffer;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.IcmpV4Type;

public class PacketAnalyzer {

    public PacketInfo analyze(Packet packet) {
        PacketInfo info = new PacketInfo();
        info.setLength(packet.length());

        if (packet.contains(ArpPacket.class)) {
            ArpPacket arpPacket = packet.get(ArpPacket.class);

            String srcIp = arpPacket.getHeader().getSrcProtocolAddr().getHostAddress();
            String dstIp = arpPacket.getHeader().getDstProtocolAddr().getHostAddress();
            ArpOperation operation = arpPacket.getHeader().getOperation();

            info.setProtocol("ARP");
            info.setSrcIp(srcIp);
            info.setDstIp(dstIp);

            if (operation.equals(ArpOperation.REQUEST)) {
                info.setSummary("ARP request");
            } else if (operation.equals(ArpOperation.REPLY)) {
                info.setSummary("ARP reply");
            } else {
                info.setSummary("ARP other");
            }

            return info;
        }

        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);

            String srcIp = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
            String dstIp = ipV4Packet.getHeader().getDstAddr().getHostAddress();

            info.setSrcIp(srcIp);
            info.setDstIp(dstIp);

            if (packet.contains(IcmpV4CommonPacket.class)) {
                IcmpV4CommonPacket icmpPacket = packet.get(IcmpV4CommonPacket.class);
                IcmpV4Type type = icmpPacket.getHeader().getType();

                info.setProtocol("ICMP");

                if (type.equals(IcmpV4Type.ECHO)) {
                    info.setSummary("ICMP echo request");
                } else if (type.equals(IcmpV4Type.ECHO_REPLY)) {
                    info.setSummary("ICMP echo reply");
                } else {
                    info.setSummary("ICMP other");
                }

                return info;
            }

            if (packet.contains(TcpPacket.class)) {
                TcpPacket tcpPacket = packet.get(TcpPacket.class);

                info.setProtocol("TCP");
                info.setSrcPort(tcpPacket.getHeader().getSrcPort().valueAsInt());
                info.setDstPort(tcpPacket.getHeader().getDstPort().valueAsInt());
                info.setSummary("TCP segment");

                return info;
            }

            if (packet.contains(UdpPacket.class)) {
                UdpPacket udpPacket = packet.get(UdpPacket.class);

                info.setProtocol("UDP");
                info.setSrcPort(udpPacket.getHeader().getSrcPort().valueAsInt());
                info.setDstPort(udpPacket.getHeader().getDstPort().valueAsInt());
                info.setSummary("UDP datagram");

                return info;
            }

            info.setProtocol("IPv4");
            info.setSummary("IPv4 packet");
            return info;
        }

        info.setProtocol("OTHER");
        info.setSummary("Unknown packet");
        return info;
    }
}