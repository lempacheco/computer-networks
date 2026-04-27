package sniffer.analysis;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.ArpOperation;

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
        String senderMac = arpPacket.getHeader().getSrcHardwareAddr().toString();
        String targetMac = arpPacket.getHeader().getDstHardwareAddr().toString();

        String senderIp = arpPacket.getHeader().getSrcProtocolAddr().getHostAddress();
        String targetIp = arpPacket.getHeader().getDstProtocolAddr().getHostAddress();

        ArpOperation operation = arpPacket.getHeader().getOperation();

        info.setProtocol("ARP");

        // No ARP, estes campos representam o emissor e o alvo do protocolo ARP
        info.setSrcMac(senderMac);
        info.setDstMac(targetMac);
        info.setSrcIp(senderIp);
        info.setDstIp(targetIp);

        if (ArpOperation.REQUEST.equals(operation)) {
            info.setSummary(
                    "ARP request: Who has " + targetIp + "? Tell " + senderIp
            );
        } else if (ArpOperation.REPLY.equals(operation)) {
            info.setSummary(
                    "ARP reply: " + senderIp + " is at " + senderMac
            );
        } else {
            info.setSummary(
                    "ARP operation " + operation
                            + ": sender " + senderIp + " is at " + senderMac
                            + ", target " + targetIp + " / " + targetMac
            );
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
        info.setSummary("IPv4 packet");
        return info;
    }

    private PacketInfo analyzeIcmp(IcmpV4CommonPacket icmpPacket, PacketInfo info) {
        info.setProtocol("ICMP");

        int type = icmpPacket.getHeader().getType().value() & 0xFF;
        int code = icmpPacket.getHeader().getCode().value() & 0xFF;

        String description = getIcmpDescription(type, code);

        info.setSummary("ICMP type=" + type + ", code=" + code + " - " + description);

        return info;
    }

    private String getIcmpDescription(int type, int code) {
    switch (type) {
        case 0:
            if (code == 0) {
                return "echo reply (ping)";
            }
            break;

        case 3:
            switch (code) {
                case 0:
                    return "destination network unreachable";
                case 1:
                    return "destination host unreachable";
                case 2:
                    return "destination protocol unreachable";
                case 3:
                    return "destination port unreachable";
                case 6:
                    return "destination network unknown";
                case 7:
                    return "destination host unknown";
                default:
                    return "destination unreachable";
            }

        case 8:
            if (code == 0) {
                return "echo request (ping)";
            }
            break;

        case 9:
            if (code == 0) {
                return "route advertisement";
            }
            break;

        case 10:
            if (code == 0) {
                return "router discovery";
            }
            break;

        case 11:
            if (code == 0) {
                return "TTL expired / exceeded";
            }
            return "time exceeded";

        case 12:
            if (code == 0) {
                return "bad IP header";
            }
            return "parameter problem";

        case 13:
            if (code == 0) {
                return "timestamp";
            }
            break;

        case 14:
            if (code == 0) {
                return "timestamp reply";
            }
            break;

        default:
            return "unknown ICMP message";
    }

        return "unknown ICMP message";
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
        String flags = buildTcpFlags(header);

        return "TCP " + flags;
    }

    private String buildTcpFlags(TcpPacket.TcpHeader header) {
        if (header.getSyn() && header.getAck()) {
            return "SYN-ACK";
        }

        if (header.getSyn()) {
            return "SYN";
        }

        if (header.getFin()) {
            return "FIN";
        }

        if (header.getRst()) {
            return "RST";
        }

        if (header.getPsh() && header.getAck()) {
            return "PSH-ACK";
        }

        if (header.getAck()) {
            return "ACK";
        }

        return "segment";
    }

    private PacketInfo analyzeUdp(UdpPacket udpPacket, PacketInfo info) {
        info.setProtocol("UDP");
        info.setSrcPort(udpPacket.getHeader().getSrcPort().valueAsInt());
        info.setDstPort(udpPacket.getHeader().getDstPort().valueAsInt());
        info.setSummary("UDP datagram");
        return info;
    }
}