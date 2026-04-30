package sniffer.capture;

import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;
import sniffer.analysis.PacketAnalyzer;
import sniffer.analysis.RttAnalyzer;
import sniffer.analysis.StatisticsService;
import sniffer.filter.PacketFilter;
import sniffer.model.PacketInfo;
import sniffer.output.PacketOutput;

import java.io.EOFException;
import java.sql.Timestamp;
import java.util.Scanner;
import java.util.concurrent.TimeoutException;

public class SnifferService {

    private static final int SNAP_LEN = 65536;
    private static final int READ_TIMEOUT_MILLIS = 50;

    private volatile boolean running = true;

    private final PacketAnalyzer analyzer = new PacketAnalyzer();
    private final RttAnalyzer rttAnalyzer = new RttAnalyzer();
    private final StatisticsService statisticsService = new StatisticsService();

    public void startSniffing(PcapNetworkInterface nif,
                              boolean liveMode,
                              boolean logMode,
                              String logFormat,
                              String logFileName,
                              PacketFilter packetFilter,
                              String bpfFilter) {
        if (nif == null) {
            System.err.println("Invalid interface.");
            return;
        }

        PcapHandle handle = null;
        PacketOutput packetOutput = null;
        running = true;

        try {
            handle = nif.openLive(SNAP_LEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT_MILLIS);

            applyBpfFilter(handle, bpfFilter);
            packetOutput = new PacketOutput(liveMode, logMode, logFormat, logFileName);

            startStopListener();

            System.out.println("Capture started on interface: " + nif.getName());
            System.out.println("Type 's' and press ENTER to stop.");
            System.out.println();

            while (running) {
                try {
                    Packet packet = handle.getNextPacketEx();
                    Timestamp timestamp = handle.getTimestamp();

                    PacketInfo info = analyzer.analyze(packet);
                    info.setCaptureTimestamp(timestamp);
                    info.setInterfaceName(nif.getName());

                    PacketInfo matchedRequest = rttAnalyzer.calculateRtt(packet, info, timestamp);

                    if (packetFilter == null || packetFilter.matches(info)) {
                        if (matchedRequest != null) {
                            packetOutput.outputIcmpMatch(matchedRequest, info);
                        } else {
                            packetOutput.write(info);
                        }
                        statisticsService.register(info);
                    }
                } catch (TimeoutException e) {
                    // Normal: permite verificar periodicamente a variável running.
                } catch (NotOpenException | EOFException e) {
                    System.out.println("Capture stopped.");
                    running = false;
                }
            }
        } catch (PcapNativeException e) {
            System.err.println("Error opening interface. Check permissions.");
        } catch (NotOpenException e) {
            System.err.println("Error: capture handle is not open.");
        } finally {
            if (packetOutput != null) packetOutput.close();
            if (handle != null && handle.isOpen()) handle.close();
            statisticsService.printSummary();
        }
    }

    private void applyBpfFilter(PcapHandle handle, String bpfFilter) throws PcapNativeException, NotOpenException {
        if (bpfFilter == null || bpfFilter.isBlank()) return;
        handle.setFilter(bpfFilter, BpfProgram.BpfCompileMode.OPTIMIZE);
        System.out.println("BPF filter applied: " + bpfFilter);
    }

    private void startStopListener() {
        Thread inputThread = new Thread(() -> {
            Scanner scanner = new Scanner(System.in);
            while (running) {
                try {
                    String input = scanner.nextLine();
                    if ("s".equalsIgnoreCase(input.trim())) {
                        System.out.println("Stopping capture...");
                        running = false;
                    }
                } catch (Exception e) {
                    running = false;
                }
            }
        });
        inputThread.setDaemon(true);
        inputThread.start();
    }

}