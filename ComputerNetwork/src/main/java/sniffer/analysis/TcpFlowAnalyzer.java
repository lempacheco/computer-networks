package sniffer.analysis;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import sniffer.model.PacketInfo;

import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;

public class TcpFlowAnalyzer {

    private final Map<String, TcpFlow> flows = new HashMap<>();

    public String analyze(Packet packet, PacketInfo info, Timestamp timestamp) {
        if (!packet.contains(TcpPacket.class)) {
            return null;
        }

        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        TcpPacket.TcpHeader header = tcpPacket.getHeader();

        String flowKey = buildFlowKey(info);
        TcpFlow flow = flows.get(flowKey);

        if (flow == null) {
            flow = new TcpFlow(info, timestamp);
            flows.put(flowKey, flow);
        }

        flow.update(info, tcpPacket, timestamp);

        if (header.getSyn() && !header.getAck()) {
            flow.synTime = timestamp;
            flow.status = "SYN_SENT";
            return flow.summary("TCP flow started: SYN");
        }

        if (header.getSyn() && header.getAck()) {
            flow.synAckTime = timestamp;
            flow.status = "SYN_RECEIVED";

            if (flow.synTime != null) {
                flow.initialRtt = timestamp.getTime() - flow.synTime.getTime();
            }

            return flow.summary("TCP handshake: SYN-ACK");
        }

        if (header.getAck() && "SYN_RECEIVED".equals(flow.status)) {
            flow.handshakeComplete = true;
            flow.status = "ESTABLISHED";
            return flow.summary("TCP handshake complete");
        }

        if (header.getFin()) {
            flow.status = "CLOSING";
            flow.termination = "FIN";
            return flow.summary("TCP connection closing");
        }

        if (header.getRst()) {
            flow.status = "RESET";
            flow.termination = "RST";
            return flow.summary("TCP connection reset");
        }

        return null;
    }

    private String buildFlowKey(PacketInfo info) {
        String a = info.getSrcIp() + ":" + info.getSrcPort();
        String b = info.getDstIp() + ":" + info.getDstPort();

        if (a.compareTo(b) <= 0) {
            return a + " <-> " + b;
        }

        return b + " <-> " + a;
    }

    private static class TcpFlow {
        String endpointA;
        String endpointB;

        Timestamp startTime;
        Timestamp lastTime;
        Timestamp synTime;
        Timestamp synAckTime;

        String status = "NEW";
        String termination = "-";

        boolean handshakeComplete = false;
        Long initialRtt = null;

        int packets = 0;
        long bytesAToB = 0;
        long bytesBToA = 0;

        TcpFlow(PacketInfo info, Timestamp timestamp) {
            this.endpointA = info.getSrcIp() + ":" + info.getSrcPort();
            this.endpointB = info.getDstIp() + ":" + info.getDstPort();
            this.startTime = timestamp;
            this.lastTime = timestamp;
        }

        void update(PacketInfo info, TcpPacket tcpPacket, Timestamp timestamp) {
            packets++;
            lastTime = timestamp;

            int payloadLength = 0;

            if (tcpPacket.getPayload() != null) {
                payloadLength = tcpPacket.getPayload().length();
            }

            String currentSrc = info.getSrcIp() + ":" + info.getSrcPort();

            if (currentSrc.equals(endpointA)) {
                bytesAToB += payloadLength;
            } else {
                bytesBToA += payloadLength;
            }
        }

        String summary(String event) {
            long duration = lastTime.getTime() - startTime.getTime();

            return event
                    + " | Flow " + endpointA + " <-> " + endpointB
                    + " | status=" + status
                    + " | handshake=" + (handshakeComplete ? "complete" : "incomplete")
                    + " | initialRTT=" + (initialRtt == null ? "-" : initialRtt + " ms")
                    + " | duration=" + duration + " ms"
                    + " | packets=" + packets
                    + " | bytes A->B=" + bytesAToB
                    + " | bytes B->A=" + bytesBToA
                    + " | termination=" + termination;
        }
    }
}