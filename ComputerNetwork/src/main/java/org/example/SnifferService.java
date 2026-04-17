package org.example;

import org.pcap4j.core.*;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

import java.io.EOFException;
import java.sql.Timestamp;
import java.util.concurrent.TimeoutException;

public class SnifferService {
    public void startSniffing(PcapNetworkInterface nif){

        try{
            int snapLen = 65536;
            PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
            int timeout = 10;

            PcapHandle handle = nif.openLive(snapLen, mode, timeout);

            System.out.println("Sniffing on: " + nif.getName());

            PacketAnalyzer analyzer = new PacketAnalyzer();
            while(true){
                try{
                    Packet packet = handle.getNextPacketEx();
                    Timestamp timestamp = handle.getTimestamp();

                    System.out.println(timestamp + " | " + analyzer.analyzePacket(packet));

                } catch (NotOpenException e) {
                    throw new RuntimeException(e);
                } catch (EOFException e) {
                    throw new RuntimeException(e);
                } catch (TimeoutException e) {
                    // nenhum pacote chegou neste intervalo
                }

            }

        } catch (PcapNativeException e) {
            System.out.println("Error opening interface for capture. Check permissions.");
            e.printStackTrace();
        }
    }
}
