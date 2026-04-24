package sniffer;

import org.pcap4j.core.PcapNetworkInterface;

import java.util.List;
import java.util.Scanner;
import sniffer.filter.PacketFilter;

import sniffer.capture.*;

public class Main {
    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);

        System.out.println("=== Packet Sniffer ===");

        InterfaceManager interfaceManager = new InterfaceManager();

        // Choose the interface

        List<PcapNetworkInterface> interfaces = interfaceManager.listInterfaces();
        PcapNetworkInterface chosenInterface = interfaceManager.chooseInterface(interfaces, sc);

        System.out.print("Enable live mode? (y/n): ");
        boolean liveMode = sc.nextLine().trim().equalsIgnoreCase("y");

        System.out.print("Enable log mode? (y/n): ");
        boolean logMode = sc.nextLine().trim().equalsIgnoreCase("y");

        String logFormat = "txt";
        String logFileName = "capture.txt";

        if (logMode) {
            System.out.print("Choose format (txt/csv/json): ");
            logFormat = sc.nextLine().trim().toLowerCase();

            if (logFormat.equalsIgnoreCase("csv")) {
                logFileName = "capture.csv";
            } else if (logFormat.equalsIgnoreCase("json")) {
                logFileName = "capture.json";
            } else {
                logFormat = "txt";
                logFileName = "capture.txt";
            }
        }

        System.out.print("Filter by protocol? (ARP/IPv4/ICMP/TCP/UDP or empty): ");
        String protocolFilter = sc.nextLine().trim();

        System.out.print("Filter by IP? (empty for none): ");
        String ipFilter = sc.nextLine().trim();

        System.out.print("Filter by MAC? (empty for none): ");
        String macFilter = sc.nextLine().trim();

        System.out.print("BPF filter? (example: icmp, arp, tcp port 80; empty for none): ");
        String bpfFilter = sc.nextLine().trim();

        PacketFilter packetFilter = new PacketFilter(protocolFilter, ipFilter, macFilter);

        SnifferService sniffer = new SnifferService();
        sniffer.startSniffing(
                chosenInterface,
                liveMode,
                logMode,
                logFormat,
                logFileName,
                packetFilter,
                bpfFilter);

    }
}
