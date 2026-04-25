package sniffer.capture;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import sniffer.output.PacketOutput;

import java.io.EOFException;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.TimeoutException;

import sniffer.analysis.*;
import sniffer.model.*;
import sniffer.filter.PacketFilter;

public class SnifferService {

    private static final int SNAP_LEN = 65536;
    private static final int READ_TIMEOUT_MILLIS = 10;

    // open the interface and capture the packets
    public void startSniffing(PcapNetworkInterface nif,
            boolean liveMode,
            boolean logMode,
            String logFormat,
            String logFileName,
            PacketFilter packetFilter,
            String bpfFilter) {

        if (nif == null) {
            System.out.println("No interface selected.");
            return;
        }

        PacketAnalyzer analyzer = new PacketAnalyzer();
        TcpFlowAnalyzer tcpFlowAnalyzer = new TcpFlowAnalyzer();
        RTT rttAnalyzer = new RTT();

        try {
            PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
            // open the interface and captutre the packts
            PcapHandle handle = nif.openLive(SNAP_LEN, mode, READ_TIMEOUT_MILLIS);

            if (bpfFilter != null && !bpfFilter.isBlank()) {
    try {
        handle.setFilter(
                bpfFilter,
                BpfProgram.BpfCompileMode.OPTIMIZE
        );
        System.out.println("BPF filter applied: " + bpfFilter);
    } catch (Exception e) {
        System.err.println("Invalid BPF filter or failed to apply filter: " + bpfFilter);
        System.err.println("Reason: " + e.getMessage());
        return;
    }

}

            PacketOutput packetOutput = new PacketOutput(liveMode, logMode, logFormat, logFileName);

            System.out.println("Sniffing on: " + nif.getName());
            System.out.println("Press Ctrl+C to stop.");

            while (true) {
                try {
                    Packet packet = handle.getNextPacketEx();
                    Timestamp ts = handle.getTimestamp();

                    // the analyzer
                    PacketInfo info = analyzer.analyze(packet);
                    info.setTimestamp(formatTimestamp(ts));
                    info.setInterfaceName(nif.getName());

                    rttAnalyzer.calculateRtt(packet, info, ts);

                    String tcpFlowSummary = tcpFlowAnalyzer.analyze(packet, info, ts);

                    if (tcpFlowSummary != null) {
                        info.setSummary(info.getSummary() + " | " + tcpFlowSummary);
                    }

                    if (packetFilter == null || packetFilter.matches(info)) {
                        packetOutput.write(info);
                    }

                } catch (TimeoutException e) {
                    // no packets received in this interval
                } catch (NotOpenException | EOFException e) {
                    System.out.println("Capture stopped.");
                }
            }

        } catch (PcapNativeException e) {
            System.out.println("Error opening interface for capture. Check permissions.");
            e.printStackTrace();
        }
    }

    private String formatTimestamp(Timestamp ts) {
        LocalDateTime dateTime = ts.toLocalDateTime();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");
        return dateTime.format(formatter);
    }
}