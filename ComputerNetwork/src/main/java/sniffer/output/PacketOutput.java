package sniffer.output;

import sniffer.PacketAnalyzer;
import sniffer.PacketInfo;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

public class PacketOutput {

    private boolean liveMode;
    private boolean logMode;
    private String format;
    private BufferedWriter output;
    private boolean csvHeader;

    public PacketOutput(boolean liveMode, boolean logMode, String format, BufferedWriter output){
        this.liveMode = liveMode;
        this.logMode = logMode;
        this.format = format;
        this.output = output;
    }


    public void writeOutput(PacketInfo info) {
        if (liveMode) {
            System.out.println(formatTxt(info));
        }

        if (logMode) {
            writeToFile(info);
        }
    }

    public void writeToFile(PacketInfo info){
        if (this.output == null) return;

        try {
            if(this.format.equalsIgnoreCase("csv")){
                if(!csvHeader){
                    output.write("timestamp,interface,protocol,src,dst,length,summary");
                    output.newLine();
                    csvHeader = true;
                }
                output.write(formatCsv(info));
            } else if (this.format.equalsIgnoreCase("json")){
                output.write(formatJson(info));
            } else {
                output.write(formatTxt(info));
            }

            output.newLine();
            output.flush();

        } catch (IOException e) {
            System.out.println("Error writing packet to file.");
            e.printStackTrace();
        }
    }


    public String formatTxt(PacketInfo info) {
        String src = info.getSrcIp() != null ? info.getSrcIp() : "-";
        String dst = info.getDstIp() != null ? info.getDstIp() : "-";

        if (info.getSrcPort() != null && info.getDstPort() != null) {
            src = src + ":" + info.getSrcPort();
            dst = dst + ":" + info.getDstPort();
        }

        return info.getTimestamp()
                + " | " + info.getInterfaceName()
                + " | " + info.getProtocol()
                + " | " + src + " -> " + dst
                + " | len=" + info.getLength()
                + " | " + info.getSummary();
    }


    public String formatCsv(PacketInfo info) {
        String src = info.getSrcIp() != null ? info.getSrcIp() : "-";
        String dst = info.getDstIp() != null ? info.getDstIp() : "-";

        if (info.getSrcPort() != null && info.getDstPort() != null) {
            src = src + ":" + info.getSrcPort();
            dst = dst + ":" + info.getDstPort();
        }

        return info.getTimestamp() + ","
                + info.getInterfaceName() + ","
                + info.getProtocol() + ","
                + src + ","
                + dst + ","
                + info.getLength() + ","
                + info.getSummary();
    }

    public String formatJson(PacketInfo info){
        String src = info.getSrcIp() != null ? info.getSrcIp() : "-";
        String dst = info.getDstIp() != null ? info.getDstIp() : "-";

        if(info.getSrcPort() != null && info.getDstIp() != null){
            src += ":" + info.getSrcPort();
            dst += ":" + info.getDstPort();
        }

        return "{"
                + "\"timestamp\":\"" + info.getTimestamp() + "\","
                + "\"interface\":\"" + info.getInterfaceName() + "\","
                + "\"protocol\":\"" + info.getProtocol() + "\","
                + "\"src\":\"" + src + "\","
                + "\"dst\":\"" + dst + "\","
                + "\"length\":" + info.getLength() + ","
                + "\"summary\":\"" + info.getSummary() + "\""
                + "}";
    }
}