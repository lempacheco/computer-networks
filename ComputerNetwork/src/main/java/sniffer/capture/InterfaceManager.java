package sniffer.capture;

import org.pcap4j.core.*;

import java.util.List;
import java.util.Scanner;

public class InterfaceManager {
    public List<PcapNetworkInterface> listInterfaces() {
        try {
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();

            if (interfaces == null || interfaces.isEmpty()) {
                return List.of();
            }

            int i = 0;
            for (PcapNetworkInterface nif : interfaces) {
                System.out.println("[" + i + "]");
                System.out.println("Name: " + nif.getName());
                System.out.println("Description: " + nif.getDescription());
                System.out.println("Address: " + nif.getAddresses());
                System.out.println("------------------------------------");
                i++;
            }

            return interfaces;

        } catch (PcapNativeException e) {
            System.out.println("Unable to list network interfaces.");
            e.printStackTrace();
            return List.of();
        }
    }

    public PcapNetworkInterface chooseInterface(List<PcapNetworkInterface> interfaces, Scanner sc){

        if(interfaces == null || interfaces.isEmpty()) {
            return null;
        }

        while(true){
            System.out.print("Select interface index: ");
            String input = sc.nextLine().trim();

            try{
                int index = Integer.parseInt(input);
                if (index >= 0 && index < interfaces.size()) {
                    return interfaces.get(index);
                }
                System.out.println("Invalid index. Try again.");
            } catch (NumberFormatException e){
                System.out.println("Enter a valid numeric index.");
            }
        }
    }
}
