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
            System.out.println("Filtros da aplicação, aplicados depois da captura:");
            String protocolFilter = askOptionAllowEmpty(sc, "Protocolo (ARP/IPv4/ICMP/TCP/UDP ou vazio)",
                new String[]{"ARP", "IPv4", "ICMP", "TCP", "UDP"});
            String ipFilter = askText(sc, "IP origem/destino (vazio = sem filtro)", "");
            String macFilter = askText(sc, "MAC origem/destino (vazio = sem filtro)", "");

            System.out.println();
            System.out.println("Filtro BPF opcional, aplicado pelo pcap4j antes do parsing.");
            System.out.println("Exemplos: arp | icmp | tcp port 80 | host 10.0.0.2");
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
        System.out.println(" Packet Sniffer - Redes de Computadores ");
        System.out.println(" Protocolos: ARP, IPv4, ICMP, TCP, UDP  ");
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
            System.out.println("Invalid input. Write y/yes ou n/no.");
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
            System.out.println("Ivalid Option.");
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
            System.out.println("Protocolo inválido. Valores aceites: " + String.join(", ", options) + ".");
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
        System.out.println("========== Configuração ==========");
        System.out.println("Interface: " + nif.getName() + " - " + nif.getDescription());
        System.out.println("Live: " + (liveMode ? "sim" : "não"));
        System.out.println("Log: " + (logMode ? logFormat + " -> " + logFileName : "não"));
        System.out.println("Filtro protocolo: " + emptyAsNone(protocolFilter));
        System.out.println("Filtro IP: " + emptyAsNone(ipFilter));
        System.out.println("Filtro MAC: " + emptyAsNone(macFilter));
        System.out.println("Filtro BPF: " + emptyAsNone(bpfFilter));
        System.out.println("==================================");
        System.out.println();
    }

    private static String emptyAsNone(String value) {
        return value == null || value.isBlank() ? "nenhum" : value;
    }

}
