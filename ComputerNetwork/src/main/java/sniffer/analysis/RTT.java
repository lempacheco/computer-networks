package sniffer.analysis;

import java.util.HashMap;
import java.util.Map;

import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.Packet;

import java.sql.Timestamp;

import sniffer.model.PacketInfo;

public class RTT {
	//ICMP
	private Map<String, Timestamp> requests = new HashMap<>();

	public void calculateRtt(Packet packet, PacketInfo info, Timestamp timestamp){

		//filtra só pacotes usados no ping e que são icmp
		if(!packet.contains(IcmpV4CommonPacket.class)){
			return;
		}
		if(!packet.contains(IcmpV4EchoPacket.class)){
			return;
		}

		IcmpV4EchoPacket echoPacket = packet.get(IcmpV4EchoPacket.class);
		IcmpV4CommonPacket icmpPacket = packet.get(IcmpV4CommonPacket.class);


		//se for request add a requests
        if (IcmpV4Type.ECHO.equals(icmpPacket.getHeader().getType())) {
            String key = buildKey(info, echoPacket);
            requests.put(key, timestamp);
            return;
        }
        if (IcmpV4Type.ECHO_REPLY.equals(icmpPacket.getHeader().getType())) {
            String key = reverseKey(info, echoPacket);

            Timestamp requestTimestamp = requests.remove(key);

            if (requestTimestamp != null) {
                long rtt = timestamp.getTime() - requestTimestamp.getTime();
                info.setRTT(rtt);
            }
        }

	}

	public String buildKey(PacketInfo info,  IcmpV4EchoPacket echoPacket){
		return info.getSrcIp() + ','
			   + info.getDstIp() + ','
			   + echoPacket.getHeader().getIdentifier() + ','
			   + echoPacket.getHeader().getSequenceNumber();
	}

	public String reverseKey(PacketInfo info, IcmpV4EchoPacket echoPacket){
		return info.getDstPort() + ','
			   + info.getSrcIp() + ','
			   + echoPacket.getHeader().getIdentifier() + ','
			   + echoPacket.getHeader().getSequenceNumber();
	}
}
