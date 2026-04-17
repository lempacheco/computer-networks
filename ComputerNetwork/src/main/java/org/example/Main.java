package org.example;

import org.pcap4j.core.PcapNetworkInterface;

import javax.net.ssl.SNIHostName;
import java.util.List;

public class Main {
    public static void main(String[] args){
        InterfaceManager interfaceManager = new InterfaceManager();
        SnifferService sniffer = new SnifferService();

        // list of all interfaces
        List<PcapNetworkInterface> interfaces = interfaceManager.listInterfaces();
        PcapNetworkInterface chosenInterface = interfaceManager.chooseInterface(interfaces);

        sniffer.startSniffing(chosenInterface);

    }
}
