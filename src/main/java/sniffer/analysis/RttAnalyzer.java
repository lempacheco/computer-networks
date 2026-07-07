package sniffer.analysis;

import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IcmpV4EchoReplyPacket;
import org.pcap4j.packet.Packet;
import sniffer.model.PacketInfo;

import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;

public class RttAnalyzer {

    private final Map<String, PacketInfo> pendingRequests = new HashMap<>();

    public PacketInfo calculateRtt(Packet packet, PacketInfo info, Timestamp timestamp) {

        if (packet == null || info == null || timestamp == null) {
            return null;
        }
        if (!packet.contains(IcmpV4CommonPacket.class)) {
            return null;
        }

        IcmpV4CommonPacket icmpPacket = packet.get(IcmpV4CommonPacket.class);

        int type = icmpPacket.getHeader().getType().value() & 0xFF;

        String srcIp = info.getSrcIp();
        String dstIp = info.getDstIp();

        if (srcIp == null || dstIp == null) {
            return null;
        }

        if(type!= 8 && type != 0){
            return null;
        }

        int identifier = -1;
        int sequenceNumber = -1;

        if(packet.contains(IcmpV4EchoPacket.class)) {
            IcmpV4EchoPacket echoPacket = packet.get(IcmpV4EchoPacket.class);
            identifier = echoPacket.getHeader().getIdentifier() & 0xFFFF;
            sequenceNumber = echoPacket.getHeader().getSequenceNumber() & 0xFFFF;
        } else if (icmpPacket.getPayload() instanceof IcmpV4EchoReplyPacket){
            IcmpV4EchoReplyPacket replyPacket = (IcmpV4EchoReplyPacket) icmpPacket.getPayload();
            identifier = replyPacket.getHeader().getIdentifier() & 0xFFFF;
            sequenceNumber = replyPacket.getHeader().getSequenceNumber() & 0xFFFF;
        } else {
            return null;
        }

        info.setIcmpIdentifier(identifier);
        info.setIcmpSequenceNumber(sequenceNumber);

        if (type == 8) {
            String key = buildKey(srcIp, dstIp, identifier, sequenceNumber);
            info.setCaptureTimestamp(timestamp);
            pendingRequests.put(key, info);
            return null;
        }

        if (type == 0) {
            String reverseKey = buildKey(dstIp, srcIp, identifier, sequenceNumber);

            PacketInfo requestInfo = pendingRequests.remove(reverseKey);

            if (requestInfo != null) {
                long rtt = timestamp.getTime() - requestInfo.getCaptureTimestamp().getTime();
                info.setRtt(rtt);
                return requestInfo;
            }
        }

        return null;
    }

    private String buildKey(String srcIp, String dstIp, int identifier, int sequenceNumber) {
        return srcIp + "->" + dstIp + ":" + identifier + ":" + sequenceNumber;
    }
}