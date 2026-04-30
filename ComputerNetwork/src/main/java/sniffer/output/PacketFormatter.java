package sniffer.output;

import sniffer.model.PacketInfo;

import java.sql.Timestamp;
import java.text.SimpleDateFormat;

public class PacketFormatter {

    public String formatTxt(PacketInfo info) {
        return formatTimestamp(info.getCaptureTimestamp())
                + " | " + (info.getInterfaceName() == null ? "-" : info.getInterfaceName())
                + " | " + (info.getProtocol() == null ? "-" : info.getProtocol())
                + " | MAC " + macToString(info.getSrcMac()) + " -> " + macToString(info.getDstMac())
                + " | IP " + ipToString(info.getSrcIp(), info.getSrcPort())
                + " -> " + ipToString(info.getDstIp(), info.getDstPort())
                + " | ttl=" + (info.getTTL() == null ? "-" : info.getTTL())
                + " | len=" + info.getLength()
                + " | " + (info.getSummary() == null ? "-" : info.getSummary())
                + " | rtt=" + (info.getRtt() == null ? "-" : info.getRtt() + " ms");
    }


    public String formatCsv(PacketInfo info) {
        return csv(formatTimestamp(info.getCaptureTimestamp())) + ","
                + csv(info.getInterfaceName()) + ","
                + csv(info.getProtocol()) + ","
                + csv(info.getSrcMac()) + ","
                + csv(info.getDstMac()) + ","
                + csv(info.getSrcIp()) + ","
                + csv(info.getDstIp()) + ","
                + csv(info.getSrcPort() == null ? "" : String.valueOf(info.getSrcPort())) + ","
                + csv(info.getDstPort() == null ? "" : String.valueOf(info.getDstPort())) + ","
                + csv(info.getTTL() == null ? "" : String.valueOf(info.getTTL())) + ","
                + info.getLength() + ","
                + csv(info.getSummary()) + ","
                + csv(info.getRtt() == null ? "-" : info.getRtt() + " ms");
    }

    public String formatJson(PacketInfo info) {
        return "{"
                + "\"timestamp\":\"" + json(formatTimestamp(info.getCaptureTimestamp())) + "\","
                + "\"interface\":\"" + json(info.getInterfaceName()) + "\","
                + "\"protocol\":\"" + json(info.getProtocol()) + "\","
                + "\"srcMac\":\"" + json(info.getSrcMac()) + "\","
                + "\"dstMac\":\"" + json(info.getDstMac()) + "\","
                + "\"srcIp\":\"" + json(info.getSrcIp()) + "\","
                + "\"dstIp\":\"" + json(info.getDstIp()) + "\","
                + "\"srcPort\":" + jsonNumber(info.getSrcPort()) + ","
                + "\"dstPort\":" + jsonNumber(info.getDstPort()) + ","
                + "\"ttl\":" + jsonNumber(info.getTTL()) + ","
                + "\"length\":" + info.getLength() + ","
                + "\"summary\":\"" + json(info.getSummary()) + "\","
                + "\"rtt\":" + jsonLong(info.getRtt())
                + "}";

    }

    private String macToString(String mac) {
        if (mac == null || mac.isBlank()) {
            return "-";
        }

        return mac;
    }

    private String ipToString(String ip, Integer port) {
        if (ip == null || ip.isBlank()) {
            return "-";
        }

        if (port == null) {
            return ip;
        }

        return ip + ":" + port;
    }

    private String csv(String value) {
        String safeValue = value == null ? "" : value.replace("\"", "\"\"");
        return "\"" + safeValue + "\"";
    }

    private String json(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private String jsonNumber(Integer value) {
        return value == null ? "null" : String.valueOf(value);
    }

    private String jsonLong(Long value) {
        return value == null ? "null" : String.valueOf(value);
    }

    public String formatTimestamp(Timestamp ts) {
        if (ts == null) return "-";
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(ts);
    }
}
