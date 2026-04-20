package sniffer;

import org.pcap4j.core.*;

import java.util.List;
import java.util.Scanner;

public class InterfaceManager {
    public List<PcapNetworkInterface> listInterfaces() {
        try {
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();

            if (interfaces == null || interfaces.isEmpty()) {
                System.out.println("No interfaces found");
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
            e.printStackTrace();
            return List.of();
        }
    }

    public PcapNetworkInterface chooseInterface(List<PcapNetworkInterface> interfaces){

        if(interfaces == null || interfaces.isEmpty()) {
            System.out.print("No interfaces available.");
            return null;
        }

        Scanner sc = new Scanner(System.in);

        System.out.println("What interface do you want? " );
        int index = sc.nextInt();

        if (index < 0 || index >= interfaces.size()) {
            System.out.println("Invalid index.");
            return null;
        }

        return interfaces.get(index);
    }
}
