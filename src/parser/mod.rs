use std::collections::HashMap;
use pcap::{Capture, Offline};

use crate::{tcp, udp};

pub fn process_trace(mut cap: Capture<Offline>) -> 
    (HashMap<tcp::Connection, tcp::Metrics>, 
        HashMap<udp::Connection, udp::Metrics>) {

    let mut tcp_data: HashMap<tcp::Connection, tcp::Metrics> = HashMap::new();
    let mut udp_data: HashMap<udp::Connection, udp::Metrics> = HashMap::new();

    // let mut tcp: HashMap<tcp::Connection, tcp::Statistics> = HashMap::new();
    // let mut udp: HashMap<udp::Connection, udp::Metrics> = HashMap::new();

    while let Ok(packet) = cap.next_packet() {
        // Get the packet length
        let len: usize = packet.header.len as usize;

        // Get the packet timestamp
        let ts = (packet.header.ts.tv_sec as u64) * 1_000_000 + (packet.header.ts.tv_usec as u64);

        // Discard the packet if too short (can't read the header)
        let eth_head_len = 14;
        if len < eth_head_len {
            continue;
        }

        // Discard the packet if it's not IPv4 (using the EtherType)
        if &packet[12..14] != &[0x08, 0x00] {
            continue;
        }

        // Discard the packet if the IP header is incomplete
        let ip4_head_len = ((packet[14] & 0x0F) as usize) * 4;
        if eth_head_len + ip4_head_len > len {
            continue;
        }

        if packet[14 + 9] == 0x11 { // UDP
            udp::process_packet(ts, &packet, eth_head_len, ip4_head_len, &mut udp_data);
            // Process TCP packet
        } 
        if packet[14 + 9] == 0x06 { // TCP
            tcp::process_packet(ts, &packet, eth_head_len, ip4_head_len, &mut tcp_data);
        }
    }

    (tcp_data, 
        udp_data)
}
