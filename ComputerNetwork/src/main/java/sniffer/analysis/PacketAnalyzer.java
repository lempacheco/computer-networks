package sniffer.analysis;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.IcmpV4Type;

import sniffer.model.*;;

public class PacketAnalyzer {

    public PacketInfo analyze(Packet packet) {
        PacketInfo info = new PacketInfo();
        info.setLength(packet.length());

        extractEthernetInfo(packet, info);

        if (packet.contains(ArpPacket.class)) {
            return analyzeArp(packet.get(ArpPacket.class), info);
        }

        if (packet.contains(IpV4Packet.class)) {
            return analyzeIpv4(packet, packet.get(IpV4Packet.class), info);
        }

        info.setProtocol("OTHER");
        info.setSummary("Unknown or unsupported packet");
        return info;
    }



    private void extractEthernetInfo(Packet packet, PacketInfo info) {
        if (!packet.contains(EthernetPacket.class)) {
            return;
        }

        EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
        info.setSrcMac(ethernetPacket.getHeader().getSrcAddr().toString());
        info.setDstMac(ethernetPacket.getHeader().getDstAddr().toString());
    }

    private PacketInfo analyzeArp(ArpPacket arpPacket, PacketInfo info) {
        String srcIp = arpPacket.getHeader().getSrcProtocolAddr().getHostAddress();
        String dstIp = arpPacket.getHeader().getDstProtocolAddr().getHostAddress();
        ArpOperation operation = arpPacket.getHeader().getOperation();

        info.setProtocol("ARP");
        info.setSrcIp(srcIp);
        info.setDstIp(dstIp);

        if (ArpOperation.REQUEST.equals(operation)) {
            info.setSummary("ARP request");
        } else if (ArpOperation.REPLY.equals(operation)) {
            info.setSummary("ARP reply");
        } else {
            info.setSummary("ARP other");
        }

        return info;
    }

    private PacketInfo analyzeIpv4(Packet packet, IpV4Packet ipV4Packet, PacketInfo info) {
        info.setSrcIp(ipV4Packet.getHeader().getSrcAddr().getHostAddress());
        info.setDstIp(ipV4Packet.getHeader().getDstAddr().getHostAddress());

        if (packet.contains(IcmpV4CommonPacket.class)) {
            return analyzeIcmp(packet.get(IcmpV4CommonPacket.class), info);
        }

        if (packet.contains(TcpPacket.class)) {
            return analyzeTcp(packet.get(TcpPacket.class), info);
        }

        if (packet.contains(UdpPacket.class)) {
            return analyzeUdp(packet.get(UdpPacket.class), info);
        }

        info.setProtocol("IPv4");
        info.setSummary("IPv4 packet");
        return info;
    }

    private PacketInfo analyzeIcmp(IcmpV4CommonPacket icmpPacket, PacketInfo info) {
        IcmpV4Type type = icmpPacket.getHeader().getType();
        info.setProtocol("ICMP");

        if (IcmpV4Type.ECHO.equals(type)) {
            info.setSummary("ICMP echo request");
        } else if (IcmpV4Type.ECHO_REPLY.equals(type)) {
            info.setSummary("ICMP echo reply");
        } else {
            info.setSummary("ICMP other");
        }

        return info;
    }

    private PacketInfo analyzeTcp(TcpPacket tcpPacket, PacketInfo info) {
        info.setProtocol("TCP");
        info.setSrcPort(tcpPacket.getHeader().getSrcPort().valueAsInt());
        info.setDstPort(tcpPacket.getHeader().getDstPort().valueAsInt());
        info.setSummary(buildTcpSummary(tcpPacket));
        return info;
    }

    private String buildTcpSummary(TcpPacket tcpPacket) {
        TcpPacket.TcpHeader header = tcpPacket.getHeader();

        if (header.getSyn() && !header.getAck()) {
            return "TCP SYN";
        }
        if (header.getSyn() && header.getAck()) {
            return "TCP SYN-ACK";
        }
        if (header.getFin()) {
            return "TCP FIN";
        }
        if (header.getRst()) {
            return "TCP RST";
        }
        if (header.getPsh()) {
            return "TCP PSH";
        }
        if (header.getAck()) {
            return "TCP ACK";
        }

        return "TCP segment";
    }

    private PacketInfo analyzeUdp(UdpPacket udpPacket, PacketInfo info) {
        info.setProtocol("UDP");
        info.setSrcPort(udpPacket.getHeader().getSrcPort().valueAsInt());
        info.setDstPort(udpPacket.getHeader().getDstPort().valueAsInt());
        info.setSummary("UDP datagram");
        return info;
    }




}