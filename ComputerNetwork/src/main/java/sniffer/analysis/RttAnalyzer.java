package sniffer.analysis;

import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.Packet;
import sniffer.model.PacketInfo;

import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;

public class RttAnalyzer {

    // Guarda pedidos ICMP (Echo Request)
    private final Map<String, Timestamp> requests = new HashMap<>();

    public void calculateRtt(Packet packet, PacketInfo info, Timestamp timestamp) {

        // Só interessa ICMP
        if (!packet.contains(IcmpV4CommonPacket.class)) {
            return;
        }

        // Só interessa Echo (ping)
        if (!packet.contains(IcmpV4EchoPacket.class)) {
            return;
        }

        IcmpV4CommonPacket icmp = packet.get(IcmpV4CommonPacket.class);
        IcmpV4EchoPacket echo = packet.get(IcmpV4EchoPacket.class);

        int type = icmp.getHeader().getType().value() & 0xFF;

        String srcIp = info.getSrcIp();
        String dstIp = info.getDstIp();

        int identifier = echo.getHeader().getIdentifier();
        int sequence = echo.getHeader().getSequenceNumber();

        // =========================
        // ECHO REQUEST
        // =========================
        if (type == 8) { // Echo Request

            String key = buildKey(srcIp, dstIp, identifier, sequence);

            requests.put(key, timestamp);

        }

        // =========================
        // ECHO REPLY
        // =========================
        else if (type == 0) { // Echo Reply

            String reverseKey = buildKey(dstIp, srcIp, identifier, sequence);

            Timestamp requestTime = requests.remove(reverseKey);

            if (requestTime != null) {

                long rtt = timestamp.getTime() - requestTime.getTime();

                info.setRTT(rtt);

                // Opcional: melhorar o resumo
                info.setSummary(info.getSummary() + " | RTT=" + rtt + " ms");
            }
        }
    }

    private String buildKey(String src, String dst, int id, int seq) {
        return src + "->" + dst + ":" + id + ":" + seq;
    }
}