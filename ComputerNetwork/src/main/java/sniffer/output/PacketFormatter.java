package sniffer.output;

import sniffer.model.PacketInfo;

public class PacketFormatter {

    public String formatTxt(PacketInfo info) {
        return info.getTimestamp()
                + " | " + safe(info.getInterfaceName())
                + " | " + safe(info.getProtocol())
                + " | " + addressToString(info.getSrcMac(), info.getSrcIp(), info.getSrcPort())
                + " -> " + addressToString(info.getDstMac(), info.getDstIp(), info.getDstPort())
                + " | len=" + info.getLength()
                + " | " + safe(info.getSummary());
    }

    public String formatCsv(PacketInfo info) {
        return csv(info.getTimestamp()) + ","
                + csv(info.getInterfaceName()) + ","
                + csv(info.getProtocol()) + ","
                + csv(info.getSrcMac()) + ","
                + csv(info.getDstMac()) + ","
                + csv(info.getSrcIp()) + ","
                + csv(info.getDstIp()) + ","
                + csv(valueOf(info.getSrcPort())) + ","
                + csv(valueOf(info.getDstPort())) + ","
                + info.getLength() + ","
                + csv(info.getSummary());
    }

    public String formatJson(PacketInfo info) {
        return "{"
                + "\"timestamp\":\"" + json(info.getTimestamp()) + "\","
                + "\"interface\":\"" + json(info.getInterfaceName()) + "\","
                + "\"protocol\":\"" + json(info.getProtocol()) + "\","
                + "\"srcMac\":\"" + json(info.getSrcMac()) + "\","
                + "\"dstMac\":\"" + json(info.getDstMac()) + "\","
                + "\"srcIp\":\"" + json(info.getSrcIp()) + "\","
                + "\"dstIp\":\"" + json(info.getDstIp()) + "\","
                + "\"srcPort\":" + jsonNumber(info.getSrcPort()) + ","
                + "\"dstPort\":" + jsonNumber(info.getDstPort()) + ","
                + "\"length\":" + info.getLength() + ","
                + "\"summary\":\"" + json(info.getSummary()) + "\""
                + "}";
    }

    private String addressToString(String mac, String ip, Integer port) {
        StringBuilder sb = new StringBuilder();

        if (mac != null && !mac.isBlank()) {
            sb.append(mac);
        }

        if (ip != null && !ip.isBlank()) {
            if (sb.length() > 0) {
                sb.append(" /");
            }
            sb.append(ip);
        }

        if (port != null) {
            sb.append(":").append(port);
        }

        return sb.length() == 0 ? "-" : sb.toString();
    }

    private String safe(String value) {
        return value == null ? "-" : value;
    }

    private String valueOf(Integer value) {
        return value == null ? "" : String.valueOf(value);
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
}
