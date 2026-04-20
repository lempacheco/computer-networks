package sniffer.analysis;

import sniffer.PacketInfo;

public class PacketFormatter {

    public String format(PacketInfo info) {

        String src = info.getSrcIp() != null ? info.getSrcIp() : "-";
        String dst = info.getDstIp() != null ? info.getDstIp() : "-";

        if (info.getSrcPort() != null && info.getDstPort() != null) {
            src += ":" + info.getSrcPort();
            dst += ":" + info.getDstPort();
        }

        return info.getTimestamp() +
                " | " + info.getProtocol() +
                " | " + src + " -> " + dst +
                " | len=" + info.getLength() +
                " | " + info.getSummary();
    }
}