package sniffer.model;

public class PacketInfo {
    private String timestamp;
    private String interfaceName;
    private String protocol;
    private String srcMac;
    private String dstMac;
    private String srcIp;
    private String dstIp;
    private Integer srcPort;
    private Integer dstPort;
    private Integer ttl;
    private int length;
    private String summary;
    private Long rtt;

    // Campos extra úteis para a análise pedida no trabalho
    private String arpOperation;
    private Integer icmpType;
    private Integer icmpCode;
    private Integer icmpIdentifier;
    private Integer icmpSequenceNumber;
    private String tcpFlags;

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }

    public String getInterfaceName() { return interfaceName; }
    public void setInterfaceName(String interfaceName) { this.interfaceName = interfaceName; }

    public String getProtocol() { return protocol; }
    public void setProtocol(String protocol) { this.protocol = protocol; }

    public String getSrcMac() { return srcMac; }
    public void setSrcMac(String srcMac) { this.srcMac = srcMac; }

    public String getDstMac() { return dstMac; }
    public void setDstMac(String dstMac) { this.dstMac = dstMac; }

    public String getSrcIp() { return srcIp; }
    public void setSrcIp(String srcIp) { this.srcIp = srcIp; }

    public String getDstIp() { return dstIp; }
    public void setDstIp(String dstIp) { this.dstIp = dstIp; }

    public Integer getSrcPort() { return srcPort; }
    public void setSrcPort(Integer srcPort) { this.srcPort = srcPort; }

    public Integer getDstPort() { return dstPort; }
    public void setDstPort(Integer dstPort) { this.dstPort = dstPort; }

    public Integer getTTL() { return ttl; }
    public void setTTL(Integer ttl) { this.ttl = ttl; }

    public int getLength() { return length; }
    public void setLength(int length) { this.length = length; }

    public String getSummary() { return summary; }
    public void setSummary(String summary) { this.summary = summary; }

    public Long getRtt() { return rtt; }
    public void setRtt(Long rtt) { this.rtt = rtt; }

    public String getArpOperation() { return arpOperation; }
    public void setArpOperation(String arpOperation) { this.arpOperation = arpOperation; }

    public Integer getIcmpType() { return icmpType; }
    public void setIcmpType(Integer icmpType) { this.icmpType = icmpType; }

    public Integer getIcmpCode() { return icmpCode; }
    public void setIcmpCode(Integer icmpCode) { this.icmpCode = icmpCode; }

    public Integer getIcmpIdentifier() { return icmpIdentifier; }
    public void setIcmpIdentifier(Integer icmpIdentifier) { this.icmpIdentifier = icmpIdentifier; }

    public Integer getIcmpSequenceNumber() { return icmpSequenceNumber; }
    public void setIcmpSequenceNumber(Integer icmpSequenceNumber) { this.icmpSequenceNumber = icmpSequenceNumber; }

    public String getTcpFlags() { return tcpFlags; }
    public void setTcpFlags(String tcpFlags) { this.tcpFlags = tcpFlags; }


}
