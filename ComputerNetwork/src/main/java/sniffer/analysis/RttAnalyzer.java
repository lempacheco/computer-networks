package sniffer.analysis;

import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.Packet;
import sniffer.model.PacketInfo;

import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;

public class RttAnalyzer {

    /*
     * Este HashMap guarda temporariamente os ICMP Echo Request capturados.
     *
     * A chave identifica unicamente um pedido ICMP:
     * srcIp -> dstIp : identifier : sequenceNumber
     *
     * O valor guardado é o timestamp do momento em que o Echo Request foi capturado.
     */
    private final Map<String, Timestamp> requests = new HashMap<>();

    /*
     * Este método é chamado para cada pacote capturado.
     *
     * Se o pacote for ICMP Echo Request, o timestamp é guardado.
     * Se o pacote for ICMP Echo Reply, procura-se o pedido correspondente
     * e calcula-se o RTT.
     */
    public void calculateRtt(Packet packet, PacketInfo info, Timestamp timestamp) {

        // Validação básica para evitar NullPointerException
        if (packet == null || info == null || timestamp == null) {
            return;
        }

        // O RTT só faz sentido para pacotes ICMP
        if (!packet.contains(IcmpV4CommonPacket.class)) {
            return;
        }

        /*
         * O cálculo de RTT é feito apenas para mensagens Echo,
         * ou seja, Echo Request e Echo Reply, usadas pelo comando ping.
         */
        if (!packet.contains(IcmpV4EchoPacket.class)) {
            return;
        }

        IcmpV4CommonPacket icmpPacket = packet.get(IcmpV4CommonPacket.class);
        IcmpV4EchoPacket echoPacket = packet.get(IcmpV4EchoPacket.class);

        /*
         * Campo type do ICMP:
         * type = 8 -> Echo Request
         * type = 0 -> Echo Reply
         */
        int type = icmpPacket.getHeader().getType().value() & 0xFF;

        String srcIp = info.getSrcIp();
        String dstIp = info.getDstIp();

        if (srcIp == null || dstIp == null) {
            return;
        }

        /*
         * O identifier e o sequence number permitem distinguir vários pings
         * em simultâneo entre os mesmos hosts.
         */
        int identifier = echoPacket.getHeader().getIdentifier() & 0xFFFF;
        int sequenceNumber = echoPacket.getHeader().getSequenceNumber() & 0xFFFF;

        /*
         * Caso seja um Echo Request, guardamos o timestamp.
         *
         * Exemplo:
         * 10.0.0.1 -> 10.0.0.2 : id : seq
         */
        if (type == 8) {
            String key = buildKey(srcIp, dstIp, identifier, sequenceNumber);
            requests.put(key, timestamp);
            return;
        }

        /*
         * Caso seja um Echo Reply, a resposta vem no sentido inverso.
         *
         * Se o pedido foi:
         * 10.0.0.1 -> 10.0.0.2
         *
         * A resposta será:
         * 10.0.0.2 -> 10.0.0.1
         *
         * Por isso, a chave é construída invertendo origem e destino.
         */
        if (type == 0) {
            String reverseKey = buildKey(dstIp, srcIp, identifier, sequenceNumber);

            Timestamp requestTimestamp = requests.remove(reverseKey);

            /*
             * Se encontrou o pedido correspondente, calcula o RTT:
             *
             * RTT = tempo da resposta - tempo do pedido
             */
            if (requestTimestamp != null) {
                long rtt = timestamp.getTime() - requestTimestamp.getTime();

                info.setRtt(rtt);

                /*
                 * Adiciona o RTT também ao resumo textual do pacote,
                 * para aparecer diretamente no output live/log.
                 */
                info.setSummary(info.getSummary() + " | RTT=" + rtt + " ms");
            }
        }
    }

    /*
     * Cria a chave usada no HashMap.
     *
     * Inclui:
     * - IP origem
     * - IP destino
     * - identifier
     * - sequence number
     */
    private String buildKey(String srcIp, String dstIp, int identifier, int sequenceNumber) {
        return srcIp + "->" + dstIp + ":" + identifier + ":" + sequenceNumber;
    }
}