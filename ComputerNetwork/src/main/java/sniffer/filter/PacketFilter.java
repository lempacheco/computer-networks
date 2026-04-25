package sniffer.filter;

import sniffer.model.PacketInfo;

public class PacketFilter {

    private String protocol;
    private String ip;
    private String mac;

    public PacketFilter(String protocol, String ip, String mac) {
        this.protocol = normalize(protocol);
        this.ip = normalize(ip);
        this.mac = normalize(mac);
    }

    public boolean matches(PacketInfo info) {
        if (info == null) {
            return false;
        }

        if (protocol != null && !matchesProtocol(info)) {
            return false;
        }

        if (ip != null && !matchesIp(info)) {
            return false;
        }

        if (mac != null && !matchesMac(info)) {
            return false;
        }

        return true;
    }

    private boolean matchesProtocol(PacketInfo info) {
        return info.getProtocol() != null
                && info.getProtocol().equalsIgnoreCase(protocol);
    }

    private boolean matchesIp(PacketInfo info) {
        return ip.equals(info.getSrcIp()) || ip.equals(info.getDstIp());
    }

    private boolean matchesMac(PacketInfo info) {
        return equalsIgnoreCase(mac, info.getSrcMac())
                || equalsIgnoreCase(mac, info.getDstMac());
    }

    private boolean equalsIgnoreCase(String a, String b) {
        return a != null && b != null && a.equalsIgnoreCase(b);
    }

    private String normalize(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }
}