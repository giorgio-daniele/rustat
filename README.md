# Rustat
Rustat is a simple clone of [Tstat](http://www.tstat.polito.it/), written in Rust. I developed it during the 2024 Christmas holidays as a way to cope with my **schizophrenia** crisis. This software is able to reconstruct data exchanges in both TCP and UDP protocols. While in TCP, client and server flows are highly correlated through the use of flags (SYN, RST, FIN), in UDP, client and server flows are decoupled. Both types of data exchanges are reconstructed from the client perspective, where the client is defined by an IP address that is considered local within a given network whose CIDR block is expected as input.

## Methodology
Rustat reconstructs a TCP data exchange by detecting when SYN = 1 and ACK = 0 from an IP address within the specified local network. The exchange finishes once either the client or the server emits a FIN or RST flag. In the case of UDP, since the flows are not coupled, each data exchange is reconstructed when a new packet is observed from a local IP address to a remote server. The exchange finishes when there is inactivity from either the client or server side, which by default is 30 seconds.

## Features
- Detailed statistical breakdown of TCP flows from a client perspective (e.g., .pcap trace).
- UDP flow reconstruction is also available, providing similar insights to TCP flow reconstruction.

## Requirements
- Rust (latest stable version)
- Libpcap or an equivalent packet capture library

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/giorgio-daniele/rustat.git
   cd rustat
   ```

2. Build the project:
   ```bash
   cargo build --release
   ```

3. Run the executable (requires root privileges for packet capture):
   ```bash
   sudo ./target/release/rustat
   ```

## Usage

### Basic Usage
Run Rustat on a specific network interface:
```bash
./target/release/rustat --input <filename> --network <network>
```
Where <network> is a subnet in CIDR format, e.g., 192.168.1.0/24. This option helps define which side of the flow is the client and which is the server, as flows are reconstructed from the client perspective.

### Options
- `--input <filename>`: Specify the pcap trace to be analyzed
- `--network <network>`: Define the network address in CIDR format (e.g., 192.168.1.0/24). This option helps determine which side plays the role of the client and which side plays the role of the server, as flow reconstruction is performed from the client’s perspective. It helps identify the client/server role based on IP addresses within the specified subnet.


## Output
Rustat provides detailed statistics, including:
- IP addresses
- TCP/UDP ports
- TCP packets count, including the ones with payload as well as UDP packets
- Bytes conveyed by TCP and UDP packets
- TCP flags count (for TCP traffic)

In the following, we provide an example of TCP reconstructed data exchange:
| s_ip           | s_port | d_ip            | d_port | s_packs | s_bytes | s_packs_data | s_packs_ack | s_packs_syn | s_packs_rst | s_packs_fin | s_packs_urg | s_packs_psh | s_ts            | s_te            | d_packs | d_bytes | d_packs_data | d_packs_ack | d_packs_syn | d_packs_rst | d_packs_fin | d_packs_urg | d_packs_psh | d_ts            | d_te            |
|----------------|--------|-----------------|--------|---------|---------|--------------|-------------|-------------|-------------|-------------|-------------|-------------|------------------|------------------|---------|---------|--------------|-------------|-------------|-------------|-------------|-------------|-------------|------------------|------------------|
| 192.168.200.254 | 44812  | 18.185.185.88    | 443    | 10      | 4309    | 9            | 8           | 1           | 0           | 1           | 0           | 5           | 1726887057595850 | 1726887061714777 | 12      | 525     | 12           | 11          | 1           | 0           | 1           | 0           | 2           | 1726887057630484 | 1726887061748218 |
| 192.168.200.254 | 46616  | 52.223.29.147    | 443    | 22      | 8713    | 21           | 20          | 1           | 0           | 1           | 0           | 10          | 1726887424274692 | 1726887444553090 | 29      | 6706    | 29           | 28          | 1           | 0           | 1           | 0           | 8           | 1726887424299681 | 1726887444555781 |
| 192.168.200.254 | 35986  | 162.247.243.29   | 443    | 50      | 54020   | 49           | 48          | 1           | 0           | 1           | 0           | 33          | 1726887251944893 | 1726887437943486 | 77      | 5711    | 77           | 76          | 1           | 0           | 1           | 0           | 13          | 1726887251969249 | 1726887437942830 |
| 192.168.200.254 | 53844  | 91.81.129.236    | 443    | 9       | 2313    | 8            | 7           | 1           | 0           | 1           | 0           | 2           | 1726887189250194 | 1726887194798142 | 10      | 711     | 10           | 9           | 1           | 0           | 1           | 0           | 3           | 1726887189277818 | 1726887194319066 |
| 192.168.200.254 | 60184  | 18.66.196.39     | 443    | 21      | 3343    | 20           | 19          | 1           | 0           | 1           | 0           | 10          | 1726887305195340 | 1726887475860437 | 28      | 4368    | 28           | 27          | 1           | 0           | 1           | 0           | 8           | 1726887305244229 | 1726887475860013 |
| 192.168.200.254 | 44814  | 18.185.185.88    | 443    | 21      | 4785    | 20           | 19          | 1           | 0           | 1           | 0           | 14          | 1726887063999552 | 1726887361981029 | 39      | 1182    | 39           | 38          | 1           | 0           | 1           | 0           | 11          | 1726887064020602 | 1726887362011766 |
| 192.168.200.254 | 41500  | 13.226.175.61    | 443    | 28      | 4989    | 27           | 26          | 1           | 0           | 1           | 0           | 13          | 1726887363755898 | 1726887484995478 | 35      | 5502    | 35           | 34          | 1           | 0           | 1           | 0           | 13          | 1726887363775261 | 1726887484995065 |
