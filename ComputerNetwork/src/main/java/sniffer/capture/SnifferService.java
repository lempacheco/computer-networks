package sniffer.capture;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import sniffer.analysis.PacketAnalyzer;
import sniffer.analysis.RttAnalyzer;
import sniffer.analysis.StatisticsService;
import sniffer.filter.PacketFilter;
import sniffer.model.PacketInfo;
import sniffer.output.PacketOutput;

import java.io.EOFException;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Scanner;
import java.util.concurrent.TimeoutException;

public class SnifferService {

    private static final int SNAP_LEN = 65536;
    private static final int READ_TIMEOUT_MILLIS = 50;

    private boolean running = true;

    private final PacketAnalyzer analyzer = new PacketAnalyzer();
    private final RttAnalyzer rttAnalyzer = new RttAnalyzer();
    private final StatisticsService statisticsService = new StatisticsService();

    public void startSniffing(
            PcapNetworkInterface nif,
            boolean liveMode,
            boolean logMode,
            String logFormat,
            String logFileName,
            PacketFilter packetFilter,
            String bpfFilter
    ) {
        PcapHandle handle = null;
        PacketOutput packetOutput = null;
        running = true;

        try {
            PcapNetworkInterface.PromiscuousMode mode =
                    PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;

            handle = nif.openLive(SNAP_LEN, mode, READ_TIMEOUT_MILLIS);

            if (bpfFilter != null && !bpfFilter.isBlank()) {
                try {
                    handle.setFilter(bpfFilter, BpfProgram.BpfCompileMode.OPTIMIZE);
                    System.out.println("BPF filter applied: " + bpfFilter);
                } catch (Exception e) {
                    System.err.println("Invalid BPF filter: " + bpfFilter);
                    System.err.println("Reason: " + e.getMessage());
                    return;
                }
            }

            packetOutput = new PacketOutput(liveMode, logMode, logFormat, logFileName);

            startStopListener();

            System.out.println("Sniffing on interface: " + nif.getName());
            System.out.println("Type 's' and press ENTER to stop sniffing...\n");

            while (running) {
                try {
                    Packet packet = handle.getNextPacketEx();
                    Timestamp ts = handle.getTimestamp();

                    PacketInfo info = analyzer.analyze(packet);
                    info.setTimestamp(formatTimestamp(ts));
                    info.setInterfaceName(nif.getName());

                    rttAnalyzer.calculateRtt(packet, info, ts);

                    if (packetFilter == null || packetFilter.matches(info)) {
                        packetOutput.write(info);
                        statisticsService.register(info);
                    }

                } catch (TimeoutException e) {
                    // Sem pacotes neste intervalo. Continua para verificar running.
                } catch (NotOpenException | EOFException e) {
                    System.out.println("Capture stopped.");
                    running = false;
                }
            }

        } catch (PcapNativeException e) {
            System.err.println("Error opening interface. Check permissions/root/admin.");
            e.printStackTrace();

        } finally {
            if (packetOutput != null) {
                packetOutput.close();
            }

            if (handle != null && handle.isOpen()) {
                handle.close();
            }

            statisticsService.printSummary();
            System.out.println("Resources closed.");
        }
    }

    private void startStopListener() {
        Thread inputThread = new Thread(() -> {
            Scanner scanner = new Scanner(System.in);

            while (running) {
                String input = scanner.nextLine();

                if ("s".equalsIgnoreCase(input.trim())) {
                    System.out.println("Stopping sniffing...");
                    running = false;
                    break;
                }
            }
        });

        inputThread.setDaemon(true);
        inputThread.start();
    }

    private String formatTimestamp(Timestamp ts) {
        if (ts == null) {
            return "";
        }

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
        return sdf.format(ts);
    }
}