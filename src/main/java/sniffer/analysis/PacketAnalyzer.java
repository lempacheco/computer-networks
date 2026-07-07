package sniffer.analysis;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.ArpOperation;

import sniffer.model.*;

public class PacketAnalyzer {

    public PacketInfo analyze(Packet packet) {
        PacketInfo info = new PacketInfo();

        if(packet == null){
            info.setProtocol("OTHER");
            info.setSummary("Null packet");
            return info;
        }

        info.setLength(packet.length());
        extractEthernetInfo(packet, info);

        if (packet.contains(ArpPacket.class)) {
            return analyzeArp(packet.get(ArpPacket.class), info);
        }

        if (packet.contains(IpV4Packet.class)) {
            return analyzeIpv4(packet, packet.get(IpV4Packet.class), info);
        }

        if (packet.contains(IpV6Packet.class)) {
            return analyzeIpv6(packet, packet.get(IpV6Packet.class), info);
        }

        info.setProtocol("OTHER");
        info.setSummary("Unsupported Ethernet payload");
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
        String senderMac = arpPacket.getHeader().getSrcHardwareAddr().toString();
        String targetMac = arpPacket.getHeader().getDstHardwareAddr().toString();

        String senderIp = arpPacket.getHeader().getSrcProtocolAddr().getHostAddress();
        String targetIp = arpPacket.getHeader().getDstProtocolAddr().getHostAddress();

        ArpOperation operation = arpPacket.getHeader().getOperation();

        info.setProtocol("ARP");
        info.setSrcMac(senderMac);
        info.setDstMac(targetMac);
        info.setSrcIp(senderIp);
        info.setDstIp(targetIp);

        if (ArpOperation.REQUEST.equals(operation)) {
            info.setArpOperation("REQUEST");
            info.setSummary("ARP request: Who has " + targetIp + "? Tell " + senderIp);
        } else if (ArpOperation.REPLY.equals(operation)) {
            info.setArpOperation("REPLY");
            info.setSummary("ARP reply: " + senderIp + " is at " + senderMac);
        } else {
            info.setArpOperation(operation.toString());
            info.setSummary("ARP " + operation + ": sender " + senderIp + " is at " + senderMac + ", target " + targetIp + " / " + targetMac);
        }

        return info;
    }

    private PacketInfo analyzeIpv4(Packet packet, IpV4Packet ipV4Packet, PacketInfo info) {
        info.setSrcIp(ipV4Packet.getHeader().getSrcAddr().getHostAddress());
        info.setDstIp(ipV4Packet.getHeader().getDstAddr().getHostAddress());
        info.setTTL(ipV4Packet.getHeader().getTtlAsInt());

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
        info.setSummary("IPv4 packet, ttl=" + info.getTTL());
        return info;
    }

    private PacketInfo analyzeIpv6(Packet packet, IpV6Packet ipV6Packet, PacketInfo info) {
        info.setSrcIp(ipV6Packet.getHeader().getSrcAddr().getHostAddress());
        info.setDstIp(ipV6Packet.getHeader().getDstAddr().getHostAddress());
        info.setTTL(ipV6Packet.getHeader().getHopLimit() & 0xFF);

        if (packet.contains(IcmpV6CommonPacket.class)) {
            return analyzeIcmpV6(packet.get(IcmpV6CommonPacket.class), info);
        }

        if (packet.contains(TcpPacket.class)) {
            return analyzeTcp(packet.get(TcpPacket.class), info);
        }

        if (packet.contains(UdpPacket.class)) {
            return analyzeUdp(packet.get(UdpPacket.class), info);
        }

        info.setProtocol("IPv6");
        info.setSummary("IPv6 packet, hopLimit=" + info.getTTL());
        return info;
    }

    private PacketInfo analyzeIcmpV6(IcmpV6CommonPacket icmpV6Packet, PacketInfo info) {
        info.setProtocol("ICMPv6");

        int type = icmpV6Packet.getHeader().getType().value() & 0xFF;
        int code = icmpV6Packet.getHeader().getCode().value() & 0xFF;

        info.setIcmpType(type);
        info.setIcmpCode(code);

        info.setSummary("ICMPv6 type=" + type + ", code=" + code + " - " + getIcmpV6Description(type));
        return info;
    }

    private String getIcmpV6Description(int type) {
        switch (type) {
            case 1:   return "destination unreachable";
            case 2:   return "packet too big";
            case 3:   return "time exceeded";
            case 4:   return "parameter problem";
            case 128: return "echo request (ping6 request)";
            case 129: return "echo reply (ping6 response)";
            case 133: return "router solicitation";
            case 134: return "router advertisement";
            case 135: return "neighbor solicitation";
            case 136: return "neighbor advertisement";
            case 137: return "redirect message";
            default:  return "unknown ICMPv6 message";
        }
    }

    private PacketInfo analyzeIcmp(IcmpV4CommonPacket icmpPacket, PacketInfo info) {
        info.setProtocol("ICMP");

        int type = icmpPacket.getHeader().getType().value() & 0xFF;
        int code = icmpPacket.getHeader().getCode().value() & 0xFF;

        info.setIcmpType(type);
        info.setIcmpCode(code);

        String description = getIcmpDescription(type, code);
        StringBuilder summary = new StringBuilder("ICMP type=").append(type).append(", code=").append(code).append(" - ").append(description);

        info.setSummary(summary.toString());
        return info;
    }

    private String getIcmpDescription(int type, int code) {
        switch (type) {
            case 0: return code == 0 ? "echo reply (ping response)" : "echo reply";
            case 3:
                switch (code) {
                    case 0: return "destination network unreachable";
                    case 1: return "destination host unreachable";
                    case 2: return "destination protocol unreachable";
                    case 3: return "destination port unreachable";
                    case 6: return "destination network unknown";
                    case 7: return "destination host unknown";
                    default: return "destination unreachable";
                }
            case 8: return code == 0 ? "echo request (ping request)" : "echo request";
            case 9: return "router advertisement";
            case 10: return "router solicitation";
            case 11: return code == 0 ? "TTL expired / time exceeded" : "time exceeded";
            case 12: return "parameter problem / bad IP header";
            case 13: return "timestamp request";
            case 14: return "timestamp reply";
            default: return "unknown ICMP message";
        }
    }


    private PacketInfo analyzeTcp(TcpPacket tcpPacket, PacketInfo info) {
        info.setProtocol("TCP");
        info.setSrcPort(tcpPacket.getHeader().getSrcPort().valueAsInt());
        info.setDstPort(tcpPacket.getHeader().getDstPort().valueAsInt());
        String flags = buildTcpFlags(tcpPacket.getHeader());
        info.setTcpFlags(flags);
        info.setSummary("TCP " + flags);
        return info;
    }

    private String buildTcpFlags(TcpPacket.TcpHeader header) {
        StringBuilder flags = new StringBuilder();
        appendFlag(flags, header.getSyn(), "SYN");
        appendFlag(flags, header.getAck(), "ACK");
        appendFlag(flags, header.getFin(), "FIN");
        appendFlag(flags, header.getRst(), "RST");
        appendFlag(flags, header.getPsh(), "PSH");
        appendFlag(flags, header.getUrg(), "URG");
        return flags.length() == 0 ? "segment" : flags.toString();
    }

    private void appendFlag(StringBuilder flags, boolean enabled, String name) {
        if (!enabled) return;
        if (flags.length() > 0) flags.append("-");
        flags.append(name);
    }

    private PacketInfo analyzeUdp(UdpPacket udpPacket, PacketInfo info) {
        info.setProtocol("UDP");
        info.setSrcPort(udpPacket.getHeader().getSrcPort().valueAsInt());
        info.setDstPort(udpPacket.getHeader().getDstPort().valueAsInt());
        info.setSummary("UDP datagram");
        return info;
    }
}