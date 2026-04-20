package sniffer;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import sniffer.output.PacketOutput;

import java.io.BufferedWriter;
import java.io.EOFException;
import java.io.FileWriter;

import java.io.IOException;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.TimeoutException;

public class SnifferService {

    public void startSniffing(PcapNetworkInterface nif,
                              boolean liveMode,
                              boolean logMode,
                              String format,
                              String filename) {

        if (nif == null) {
            System.out.println("No interface selected.");
            return;
        }

        PacketAnalyzer analyzer = new PacketAnalyzer();
        BufferedWriter output = null;
        PacketOutput packetOutput = null;

        try {
            if (logMode) {
                output = new BufferedWriter(new FileWriter(filename, true));
            }

            packetOutput = new PacketOutput(liveMode, logMode, format, output);

            int snapLen = 65536;
            int timeout = 10;
            PcapNetworkInterface.PromiscuousMode mode =
                    PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;

            PcapHandle handle = nif.openLive(snapLen, mode, timeout);

            System.out.println("Sniffing on: " + nif.getName());

            boolean running = true;

            while (running) {
                try {
                    Packet packet = handle.getNextPacketEx();
                    Timestamp ts = handle.getTimestamp();

                    PacketInfo info = analyzer.analyze(packet);
                    info.setTimestamp(formatTimestamp(ts));
                    info.setInterfaceName(nif.getName());

                    packetOutput.writeOutput(info);

                } catch (TimeoutException e) {
                    // nenhum pacote neste intervalo
                } catch (NotOpenException | EOFException e) {
                    System.out.println("Capture stopped.");
                    running = false;
                }
            }

        } catch (PcapNativeException e) {
            System.out.println("Error opening interface for capture. Check permissions.");
            e.printStackTrace();
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
    }

    private String formatTimestamp(Timestamp ts) {
        LocalDateTime dateTime = ts.toLocalDateTime();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");
        return dateTime.format(formatter);
    }
}