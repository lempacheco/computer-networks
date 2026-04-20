package sniffer;

import org.pcap4j.core.PcapNetworkInterface;

import java.util.List;
import java.util.Scanner;

public class Main {
    public static void main(String[] args){
        InterfaceManager interfaceManager = new InterfaceManager();
        SnifferService sniffer = new SnifferService();
        Scanner sc = new Scanner(System.in);

        List<PcapNetworkInterface> interfaces = interfaceManager.listInterfaces();
        PcapNetworkInterface chosenInterface = interfaceManager.chooseInterface(interfaces);

        System.out.print("Enable live mode? (y/n): ");
        boolean liveMode = sc.nextLine().trim().equalsIgnoreCase("y");

        System.out.print("Enable log mode? (y/n): ");
        boolean logMode = sc.nextLine().trim().equalsIgnoreCase("y");

        String format = "txt";
        String fileName = "packets.txt";

        if(logMode) {
            System.out.print("Choose format (txt/csv/json): ");
            format = sc.nextLine().trim().toLowerCase();

            if(format.equalsIgnoreCase("csv")){
                fileName = "packets.csv";
            } else if(format.equalsIgnoreCase("json")){
                fileName = "packets.json";
            } else {
                format = "txt";
                fileName = "packets.txt";
            }
        }

        sniffer.startSniffing(chosenInterface, liveMode, logMode, format, fileName);

    }
}
