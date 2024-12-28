use std::{collections::HashMap, net::Ipv4Addr};
use clap::Parser;
use pcap::{Capture, Offline};

const ETHERNET_HEADER_SIZE: usize = 14; // Ethernet header size in bytes
const MIN_IP_HEADER_SIZE: usize = 20;  // Minimum size of IPv4 header
const MIN_TCP_HEADER_SIZE: usize = 20; // Minimum size of TCP header

#[derive(PartialEq, Eq, Hash, Clone)]
struct Connection {
    sip:   Ipv4Addr,
    dip:   Ipv4Addr,
    sport: u16,
    dport: u16,
}

struct Metrics {
    packs: usize,
    bytes: usize,
    segms: usize,
    acks:  usize,
    syns:  usize,
    fins:  usize,
    rsts:  usize,
    pshs:  usize,
    urgs:  usize,
}

impl Metrics {
    fn new() -> Metrics {
        Metrics { packs: 0, bytes: 0, segms: 0, acks: 0, syns: 0, fins: 0, rsts: 0, pshs: 0, urgs: 0 }
    }
}

impl Connection {
    fn new(sip: Ipv4Addr, dip: Ipv4Addr, sport: u16, dport: u16) -> Connection {
        Connection { sip, dip, sport, dport }
    }
    fn rev(sip: Ipv4Addr, dip: Ipv4Addr, sport: u16, dport: u16) -> Connection {
        Connection { sip: dip, dip: sip, sport: dport, dport: sport }
    }
}

fn process_trace(mut cap: Capture<Offline>) {
    let mut connections: HashMap<Connection, (Metrics, Metrics)> = HashMap::new();

    while let Ok(pkt) = cap.next_packet() {
        let len = pkt.header.len as usize;

        if len < ETHERNET_HEADER_SIZE {
            continue; // Skip packets that are too short
        }

        // Check Ethertype (0x0800 for IPv4)
        let eth_tpe = &pkt[12..14];
        if eth_tpe != &[0x08, 0x00] {
            continue; // Skip non-IPv4 packets
        }

        let ip_head_len = ((pkt[14] & 0x0F) as usize) * 4;
        if ip_head_len < MIN_IP_HEADER_SIZE {
            continue; // Skip packets with invalid IP headers
        }

        // Extract IP addresses
        let sip = Ipv4Addr::new(pkt[14 + 12], pkt[14 + 13], pkt[14 + 14], pkt[14 + 15]);
        let dip = Ipv4Addr::new(pkt[14 + 16], pkt[14 + 17], pkt[14 + 18], pkt[14 + 19]);

        // Calculate the offset for TCP header
        let off = ETHERNET_HEADER_SIZE + ip_head_len;
        if pkt.len() < off + MIN_TCP_HEADER_SIZE {
            continue; // Skip packets with invalid TCP headers
        }

        // Extract TCP ports
        let sport = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
        let dport = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]);

        // Extract TCP data offset
        let tcp_data_offset = (pkt[off + 12] >> 4) as usize;  // Data Offset is in 4-byte words
        let tcp_header_size = tcp_data_offset * 4;

        // Validate the header size
        let total_header_size = ETHERNET_HEADER_SIZE + ip_head_len + tcp_header_size;
        if len < total_header_size {
            continue; // Skip packets with incomplete headers
        }

        // Calculate payload size
        let load = len - total_header_size;

        // Extract flags
        let flags_byte = pkt[off + 13];
        let syn = (flags_byte & 0x02) != 0;
        let ack = (flags_byte & 0x10) != 0;
        let fin = (flags_byte & 0x01) != 0;
        let rst = (flags_byte & 0x04) != 0;
        let psh = (flags_byte & 0x08) != 0;
        let urg = (flags_byte & 0x20) != 0;

        // Create connection keys
        let key = Connection::new(sip, dip, sport, dport);
        let rev = Connection::rev(sip, dip, sport, dport);

        // Closure to update metrics
        let update_metrics = |metric: &mut Metrics| {
            metric.segms += 1;
            if load > 0 {
                metric.packs += 1;
                metric.bytes += load;
            }
            if syn {
                metric.syns += 1;
            }
            if ack {
                metric.acks += 1;
            }
            if fin {
                metric.fins += 1;
            }
            if rst {
                metric.rsts += 1;
            }
            if psh {
                metric.pshs += 1;
            }
            if urg {
                metric.urgs += 1;
            }
        };

        if syn && !ack {
            connections.insert(key.clone(), (Metrics::new(), Metrics::new()));
        }

        if let Some((metric, _)) = connections.get_mut(&key) {
            update_metrics(metric);
        }
        if let Some((_, metric)) = connections.get_mut(&rev) {
            update_metrics(metric);
        }
    }

    // Print connections
    println!("sip sport packs bytes segms syns fins rsts pshs urgs acks dip dport packs bytes segms syns fins rsts pshs urgs acks");
    for (connection, (client, server)) in connections {
        println!(
            "{} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
            connection.sip, connection.sport,
            client.packs, client.bytes, client.segms, 
                client.syns, client.fins, client.rsts, client.pshs, client.urgs, client.acks,
            connection.dip, connection.dport,
            server.packs, server.bytes, server.segms, 
                server.syns, server.fins, server.rsts, server.pshs, server.urgs, server.acks
        );
    }
}


#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    input: String,

}

fn main() {
    let args = Args::parse();

    // The input trace
    let input = args.input;

    match Capture::from_file(input) {
        Ok(capture) => process_trace(capture),
        Err(error) => {
            println!("[ERROR]: {}", error);
            std::process::exit(1);
        }
    }
    std::process::exit(0);
}
