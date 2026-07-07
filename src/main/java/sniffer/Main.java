package sniffer;

import org.pcap4j.core.PcapNetworkInterface;
import sniffer.capture.InterfaceManager;
import sniffer.capture.SnifferService;
import sniffer.filter.PacketFilter;

import java.util.List;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {

        try(Scanner sc = new Scanner(System.in)){
            printBanner();

            InterfaceManager interfaceManager = new InterfaceManager();
            List<PcapNetworkInterface> interfaces = interfaceManager.listInterfaces();
            PcapNetworkInterface chosenInterface = interfaceManager.chooseInterface(interfaces, sc);

            if(chosenInterface == null){
                System.err.println("No interfaces selected");
                return;
            }

            boolean liveMode = askYesNo(sc, "Enable live mode?", true);
            boolean logMode = askYesNo(sc, "Enable log mode?", true);

            String logFormat = "txt";
            String logFileName = "capture.txt";

            if(logMode){
                logFormat = askOption(sc, "Log Format", new String[]{"txt", "csv", "json"}, "csv");
                String defaultFile = "capture." + ("json".equals(logFormat) ? "jsonl" : logFormat);

                logFileName = askText(sc, "File log name: ", defaultFile);

            }

            System.out.println();
            System.out.println("Application filters:");
            String protocolFilter = askOptionAllowEmpty(sc, "Protocol (ARP/IPv4/IPv6/ICMP/ICMPv6/TCP/UDP or empty)",
                new String[]{"ARP", "IPv4", "IPv6", "ICMP", "ICMPv6", "TCP", "UDP"});
            String ipFilter = askText(sc, "Source/destination IP (empty = no filter)", "");
            String macFilter = askText(sc, "Source/destination MAC (empty = no filter)", "");

            System.out.println();
            System.out.println("BPF filter");
            System.out.println("Examples: arp | icmp | tcp port 80 | host 10.0.0.2");
            String bpfFilter = askText(sc, "BPF", "");

            PacketFilter packetFilter = new PacketFilter(protocolFilter, ipFilter, macFilter);

            printConfiguration(chosenInterface, liveMode, logMode, logFormat, logFileName,
                    protocolFilter, ipFilter, macFilter, bpfFilter);

            SnifferService sniffer = new SnifferService();
            sniffer.startSniffing(chosenInterface, liveMode, logMode, logFormat, logFileName, packetFilter, bpfFilter);
        }
    }

    private static void printBanner() {
        System.out.println("========================================");
        System.out.println(" Packet Sniffer - Computer Networks     ");
        System.out.println(" Protocols: ARP, IPv4, IPv6, ICMP, ICMPv6, TCP, UDP ");
        System.out.println("========================================");
        System.out.println();
    }

    private static boolean askYesNo(Scanner sc, String question, boolean defaultValue) {
        String suffix = defaultValue ? " [Y/n]: " : " [y/N]: ";
        while (true) {
            System.out.print(question + suffix);
            String input = sc.nextLine().trim();
            if (input.isEmpty()) return defaultValue;
            if (input.equalsIgnoreCase("y") || input.equalsIgnoreCase("yes")) return true;
            if (input.equalsIgnoreCase("n") || input.equalsIgnoreCase("no")) return false;
            System.out.println("Invalid input. Write y/yes or n/no.");
        }
    }

    private static String askOption(Scanner sc, String question, String[] options, String defaultValue) {
        while (true) {
            System.out.print(question + " " + String.join("/", options) + " [" + defaultValue + "]: ");
            String input = sc.nextLine().trim().toLowerCase();
            if (input.isEmpty()) return defaultValue;
            for (String option : options) {
                if (option.equalsIgnoreCase(input)) return option.toLowerCase();
            }
            System.out.println("Invalid option.");
        }
    }

    private static String askOptionAllowEmpty(Scanner sc, String question, String[] options) {
        while (true) {
            System.out.print(question + ": ");
            String input = sc.nextLine().trim();
            if (input.isEmpty()) return "";
            for (String option : options) {
                if (option.equalsIgnoreCase(input)) return option;
            }
            System.out.println("Invalid protocol. Accepted values: " + String.join(", ", options) + ".");
        }
    }

    private static String askText(Scanner sc, String question, String defaultValue) {
        String suffix = defaultValue == null || defaultValue.isEmpty() ? ": " : " [" + defaultValue + "]: ";
        System.out.print(question + suffix);
        String input = sc.nextLine().trim();
        return input.isEmpty() ? defaultValue : input;
    }


    private static void printConfiguration(PcapNetworkInterface nif,
                                           boolean liveMode,
                                           boolean logMode,
                                           String logFormat,
                                           String logFileName,
                                           String protocolFilter,
                                           String ipFilter,
                                           String macFilter,
                                           String bpfFilter) {
        System.out.println();
        System.out.println("========== Configuration ==========");
        System.out.println("Interface: " + nif.getName() + " - " + nif.getDescription());
        System.out.println("Live: " + (liveMode ? "yes" : "no"));
        System.out.println("Log: " + (logMode ? logFormat + " -> " + logFileName : "no"));
        System.out.println("Protocol filter: " + emptyAsNone(protocolFilter));
        System.out.println("IP filter: " + emptyAsNone(ipFilter));
        System.out.println("MAC filter: " + emptyAsNone(macFilter));
        System.out.println("BPF filter: " + emptyAsNone(bpfFilter));
        System.out.println("===================================");
        System.out.println();
    }

    private static String emptyAsNone(String value) {
        return value == null || value.isBlank() ? "none" : value;
    }

}
