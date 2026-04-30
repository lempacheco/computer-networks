package sniffer.analysis;

import sniffer.model.PacketInfo;

import java.util.HashMap;
import java.util.Map;

public class StatisticsService {

    private long totalPackets = 0;
    private long totalBytes = 0;

    private Long firstPacketTimeMs = null;
    private Long lastPacketTimeMs = null;

    private long arpRequests = 0;
    private long arpReplies = 0;

    private final Map<String, Long> packetsByProtocol = new HashMap<>();
    private final Map<String, Long> bytesByProtocol = new HashMap<>();
    private final Map<String, Long> packetsBySourceIp = new HashMap<>();
    private final Map<String, Long> packetsByDestinationIp = new HashMap<>();
    private final Map<String, Long> packetsByConversation = new HashMap<>();

    // Tabela ARP observada: IP -> MAC
    private final Map<String, String> arpTable = new HashMap<>();

    // Estatísticas ICMP RTT por par de intervenientes
    private final Map<String, RttStats> rttByHostPair = new HashMap<>();

    public void register(PacketInfo info) {
        if (info == null) {
            return;
        }

        updateCaptureTimes();

        totalPackets++;
        totalBytes += info.getLength();

        String protocol = valueOrUnknown(info.getProtocol());
        packetsByProtocol.put(protocol, packetsByProtocol.getOrDefault(protocol, 0L) + 1);
        bytesByProtocol.put(protocol, bytesByProtocol.getOrDefault(protocol, 0L) + info.getLength());

        if (info.getSrcIp() != null && !info.getSrcIp().isBlank()) {
            packetsBySourceIp.put(info.getSrcIp(), packetsBySourceIp.getOrDefault(info.getSrcIp(), 0L) + 1);
        }

        if (info.getDstIp() != null && !info.getDstIp().isBlank()) {
            packetsByDestinationIp.put(info.getDstIp(), packetsByDestinationIp.getOrDefault(info.getDstIp(), 0L) + 1);
        }

        if (info.getSrcIp() != null && info.getDstIp() != null) {
            String conversation = buildConversationKey(info);
            packetsByConversation.put(conversation, packetsByConversation.getOrDefault(conversation, 0L) + 1);
        }

        if ("ARP".equalsIgnoreCase(protocol)) {
            registerArp(info);
        }

        if ("ICMP".equalsIgnoreCase(protocol) && info.getRtt() != null) {
            registerIcmpRtt(info);
        }
    }

    public void printSummary() {
        System.out.println();
        System.out.println("========== Capture summary ==========");
        System.out.println("Total packets: " + totalPackets);
        System.out.println("Total bytes: " + totalBytes);

        printDurationStats();

        printProtocolStats();
        printMap("Bytes by protocol", bytesByProtocol);
        printMap("Top source IPs", packetsBySourceIp);
        printMap("Top destination IPs", packetsByDestinationIp);
        printMap("Top conversations", packetsByConversation);

        printArpStats();
        printIcmpRttStats();

        System.out.println("=====================================");
    }

    private void updateCaptureTimes() {
        long now = System.currentTimeMillis();

        if (firstPacketTimeMs == null) {
            firstPacketTimeMs = now;
        }

        lastPacketTimeMs = now;
    }

    private void printDurationStats() {
        if (firstPacketTimeMs == null || lastPacketTimeMs == null || totalPackets == 0) {
            return;
        }

        double durationSeconds = Math.max(0.001, (lastPacketTimeMs - firstPacketTimeMs) / 1000.0);
        double packetsPerSecond = totalPackets / durationSeconds;
        double bytesPerSecond = totalBytes / durationSeconds;

        System.out.printf("Capture duration: %.3f s%n", durationSeconds);
        System.out.printf("Packets/sec: %.2f%n", packetsPerSecond);
        System.out.printf("Bytes/sec: %.2f%n", bytesPerSecond);
        System.out.println();
    }

    private void printProtocolStats() {
        System.out.println("Packets by protocol:");

        if (packetsByProtocol.isEmpty()) {
            System.out.println("  none");
            System.out.println();
            return;
        }

        packetsByProtocol.entrySet()
                .stream()
                .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
                .forEach(entry -> {
                    double percentage = totalPackets == 0 ? 0 : (entry.getValue() * 100.0) / totalPackets;
                    System.out.printf("  %s: %d (%.2f%%)%n", entry.getKey(), entry.getValue(), percentage);
                });

        System.out.println();
    }

    private void registerArp(PacketInfo info) {
        if ("REQUEST".equalsIgnoreCase(info.getArpOperation())) {
            arpRequests++;
        } else if ("REPLY".equalsIgnoreCase(info.getArpOperation())) {
            arpReplies++;
        }

        if (isValidIp(info.getSrcIp()) && isValidMac(info.getSrcMac())) {
            arpTable.put(info.getSrcIp(), info.getSrcMac());
        }
    }

    private void printArpStats() {
        System.out.println("ARP statistics:");
        System.out.println("  Requests: " + arpRequests);
        System.out.println("  Replies: " + arpReplies);
        System.out.println();

        System.out.println("Observed ARP table (IP -> MAC):");

        if (arpTable.isEmpty()) {
            System.out.println("  none");
            System.out.println();
            return;
        }

        arpTable.entrySet()
                .stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(entry -> System.out.println("  " + entry.getKey() + " -> " + entry.getValue()));

        System.out.println();
    }

    private void registerIcmpRtt(PacketInfo info) {
        if (!isValidIp(info.getSrcIp()) || !isValidIp(info.getDstIp())) {
            return;
        }

        String hostPair = buildHostPairKey(info.getSrcIp(), info.getDstIp());
        RttStats stats = rttByHostPair.get(hostPair);

        if (stats == null) {
            stats = new RttStats();
            rttByHostPair.put(hostPair, stats);
        }

        stats.register(info.getRtt());
    }

    private void printIcmpRttStats() {
        System.out.println("ICMP RTT statistics:");

        if (rttByHostPair.isEmpty()) {
            System.out.println("  none");
            System.out.println();
            return;
        }

        rttByHostPair.entrySet()
                .stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(entry -> {
                    RttStats stats = entry.getValue();
                    System.out.printf(
                            "  %s: count=%d, avg=%.2f ms, min=%d ms, max=%d ms%n",
                            entry.getKey(),
                            stats.count,
                            stats.getAverage(),
                            stats.min,
                            stats.max
                    );
                });

        System.out.println();
    }

    private void printMap(String title, Map<String, Long> map) {
        System.out.println(title + ":");

        if (map.isEmpty()) {
            System.out.println("  none");
            System.out.println();
            return;
        }

        map.entrySet()
                .stream()
                .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
                .limit(10)
                .forEach(entry -> System.out.println("  " + entry.getKey() + ": " + entry.getValue()));

        System.out.println();
    }

    private String buildConversationKey(PacketInfo info) {
        String src = info.getSrcIp();
        String dst = info.getDstIp();

        if (info.getSrcPort() != null) {
            src += ":" + info.getSrcPort();
        }

        if (info.getDstPort() != null) {
            dst += ":" + info.getDstPort();
        }

        if (src.compareTo(dst) <= 0) {
            return src + " <-> " + dst;
        }

        return dst + " <-> " + src;
    }

    private String buildHostPairKey(String ipA, String ipB) {
        if (ipA.compareTo(ipB) <= 0) {
            return ipA + " <-> " + ipB;
        }

        return ipB + " <-> " + ipA;
    }

    private String valueOrUnknown(String value) {
        if (value == null || value.isBlank()) {
            return "UNKNOWN";
        }

        return value;
    }

    private boolean isValidIp(String ip) {
        return ip != null && !ip.isBlank() && !"0.0.0.0".equals(ip);
    }

    private boolean isValidMac(String mac) {
        return mac != null
                && !mac.isBlank()
                && !"00:00:00:00:00:00".equalsIgnoreCase(mac)
                && !"ff:ff:ff:ff:ff:ff".equalsIgnoreCase(mac);
    }

    private static class RttStats {
        long count = 0;
        long total = 0;
        long min = Long.MAX_VALUE;
        long max = Long.MIN_VALUE;

        void register(long rtt) {
            count++;
            total += rtt;
            min = Math.min(min, rtt);
            max = Math.max(max, rtt);
        }

        double getAverage() {
            if (count == 0) {
                return 0;
            }

            return total / (double) count;
        }
    }
}