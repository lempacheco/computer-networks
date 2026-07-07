# Packet Sniffer — Redes de Computadores

## Descrição

Packet sniffer desenvolvido em Java com a biblioteca Pcap4J.

A aplicação captura, identifica e analisa tráfego de rede em tempo real, suportando os protocolos:
- ARP
- IPv4
- IPv6
- ICMP
- ICMPv6
- TCP
- UDP

O sniffer suporta:
- captura live;
- logging para ficheiro;
- filtros BPF;
- filtros por protocolo/IP/MAC;
- cálculo de RTT para ICMP;
- estatísticas globais de captura.

---

## Dependências

- Java 11 ou superior
- Maven 3+
- Pcap4J
- libpcap (Linux/macOS) ou Npcap (Windows)

---

## Compilação na interface real

```bash
mvn clean package
```
---

## Execução (Linux / macOS (requer root))

```bash
sudo mvn exec:java -Dexec.mainClass="sniffer.Main"
```

> Permissões de administrador/root são obrigatórias para
> captura de pacotes em interfaces reais.

---

## Compilação no CORE

```bash
mvn clean compile
```

## Execução no CORE

1. Abrir terminal no nó (botão direito → Open Terminal) ir para a diretoria do projeto.

2. Executar:
```bash
java -jar target/ComputerNetwork-10-SNAPSHOT-jar-with-dependencies.jar
```

## Configuração interativa

O sniffer é configurado interativamente no arranque.
Os passos são os seguintes:

**1. Selecionar interface**
O programa lista todas as interfaces disponíveis numeradas.
Introduzir o número correspondente à interface desejada.

**2. Modo live**
Imprime cada pacote na consola em tempo real.

**3. Modo log**
Guarda os pacotes num ficheiro. Pode estar ativo
em simultâneo com o modo live.

**4. Filtros de aplicação**
Filtros aplicados após a análise do pacote.

**5. Filtro BPF**
Filtro aplicado diretamente ao handle de captura,
antes de qualquer pacote chegar à aplicação.

---

## Parar a captura

Durante a captura, escrever `s` e pressionar ENTER.

---
