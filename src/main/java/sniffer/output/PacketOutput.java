package sniffer.output;

import sniffer.model.PacketInfo;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UncheckedIOException;

public class PacketOutput {

    private boolean livMode;
    private boolean logMode;
    private String logFormat;
    private BufferedWriter writer;
    private PacketFormatter formatter;

    public PacketOutput(boolean livMode, boolean logMode, String logFormat, String logFileName){
        this.livMode = livMode;
        this.logFormat = normalize(logFormat);
        this.logMode = logMode;
        this.formatter = new PacketFormatter();

        if (logMode) {
            try {
                File capturesDir = new File("captures");

            if (!capturesDir.exists()) {
                capturesDir.mkdirs();
            }

            File file = new File(capturesDir, logFileName);

            boolean isNew = !file.exists() || file.length() == 0;

            this.writer = new BufferedWriter(new FileWriter(file, true));

            if (isNew) {
                writeHeader();
            }

            } catch (IOException e) {
                throw new UncheckedIOException("Error opening log file: " + logFileName, e);
            }
        } else {
            this.writer = null;
        }
    }

    public void write(PacketInfo info){
        if(livMode){
            System.out.println(formatter.formatTxt(info));
        }

        writeToFile(info);
    }

    private void writeToFile(PacketInfo info) {
        if(logMode && writer != null){
            try{
                writer.write(format(info));
                writer.newLine();
                writer.flush();
            } catch (IOException e) {
                throw new UncheckedIOException("Error writing to log file.", e);
            }
        }
    }

    public String format(PacketInfo info){
        String result;

        switch (logFormat) {
            case "csv":
                result = formatter.formatCsv(info);
                break;
            case "json":
                result = formatter.formatJson(info);
                break;
            default:
                result = formatter.formatTxt(info);
                break;
        }

        return result;
    }

    private void writeHeader() throws IOException {
        if (!logMode || writer == null) {
            return;
        }

        if ("csv".equals(logFormat)) {
            writer.write("timestamp,interface,protocol,srcMac,dstMac,srcIp,dstIp,srcPort,dstPort,ttl,length,summary,rtt");
            writer.newLine();
            writer.flush();
        }
    }

    public void close(){
        if(writer != null){
            try {
                writer.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private String normalize(String format) {
        if (format == null || format.isBlank()) {
            return "txt";
        }

        String normalized = format.trim().toLowerCase();

        if (normalized.equals("txt") || normalized.equals("csv") || normalized.equals("json")) {
            return normalized;
        }

        return "txt";
    }


    public void outputIcmpMatch(PacketInfo request, PacketInfo reply) {
        if (request == null || reply == null) {
            return;
        }

        if (livMode) {
            System.out.println();
            System.out.println("+---------------------- ICMP RTT MATCH ----------------------+");
            System.out.println("| REQUEST | " + request.getSrcIp() + " -> " + request.getDstIp());
            System.out.println("|         | time=" + formatter.formatTimestamp(request.getCaptureTimestamp())
                    + " | id=" + request.getIcmpIdentifier()
                    + " | seq=" + request.getIcmpSequenceNumber());
            System.out.println("| REPLY   | " + reply.getSrcIp() + " -> " + reply.getDstIp());
            System.out.println("|         | time=" + formatter.formatTimestamp(reply.getCaptureTimestamp())
                    + " | id=" + reply.getIcmpIdentifier()
                    + " | seq=" + reply.getIcmpSequenceNumber());
            System.out.println("| RTT     | " + reply.getRtt() + " ms");
            System.out.println("+------------------------------------------------------------+");
            System.out.println();
        }

        writeToFile(reply);
    }
}