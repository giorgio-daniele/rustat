use std::{collections::HashMap, fs::File, io::{self, Write}, net::Ipv4Addr, path::PathBuf};
use pcap::{Capture, Offline};

use crate::datatype::{Ipv4Connection, TcpDataExchange, UdpDataExchange};
use etherparse::{ip_number::{TCP, UDP}, Ethernet2Header, Ipv4Header, TcpHeader, UdpHeader};


fn process_tcp_packet(ts: u64, len: usize, l3_header: &Ipv4Header, l4_header: &TcpHeader, map: &mut HashMap<Ipv4Connection, TcpDataExchange>) {
    let sip: Ipv4Addr = Ipv4Addr::from(l3_header.source);
    let dip: Ipv4Addr = Ipv4Addr::from(l3_header.destination);

    let sport: u16 = l4_header.source_port;
    let dport: u16 = l4_header.destination_port;

    let syn: bool = l4_header.syn;
    let ack: bool = l4_header.ack;
    let rst: bool = l4_header.rst;
    let fin: bool = l4_header.fin;
    let urg: bool = l4_header.urg;
    let psh: bool = l4_header.psh;

    let tx_key: Ipv4Connection = Ipv4Connection::new(sip, dip, sport, dport);
    let rx_key: Ipv4Connection = Ipv4Connection::rev(sip, dip, sport, dport);

    let l3_header_size: usize = l3_header.header_len() as usize;
    let l4_header_size: usize = l4_header.header_len() as usize;

    let bytes = if len > (l3_header_size + l4_header_size) {
        len - l3_header_size  - l4_header_size
    } else {
        0 // No payload or invalid packet
    };

    match map.get_mut(&tx_key) {
        Some(metrics) => {
            if fin { // FIN = 1
                metrics.get_sender().update_packs_fin();
                metrics.get_sender().set_last_pack(ts);
                metrics.get_sender().set_te(ts); 
                metrics.get_sender().update_packs();   
            } else if rst { // RST = 1
                metrics.get_sender().update_packs_rst();
                metrics.get_sender().set_last_pack(ts);
                metrics.get_sender().set_te(ts);
                metrics.get_sender().update_packs();   
            } else {        // Just a packet
                if ack { metrics.get_sender().update_packs_ack(); }
                if urg { metrics.get_sender().update_packs_urg(); }
                if psh { metrics.get_sender().update_packs_psh(); }
                if bytes > 0 {
                    metrics.get_sender().update_packs_data();
                    metrics.get_sender().update_bytes(bytes as u64);
                }
                metrics.get_sender().update_packs(); 
                metrics.get_sender().set_last_pack(ts);
                
            } 
        },
        None => {
            if syn && !ack { // SYN = 1 and ACK = 1
                map.entry(tx_key).or_insert_with(|| {
                    let mut metrics = TcpDataExchange::new();
                    metrics.get_sender().apply(|sender| {
                        sender.update_packs_syn();
                        if bytes > 0 {
                            sender.update_packs_data();
                            sender.update_bytes(bytes as u64);
                        }
                        sender.update_packs(); 
                        sender.set_last_pack(ts);
                        sender.set_ts(ts);
                    });
                    metrics
                });
            }
            
        }
    }

    match map.get_mut(&rx_key) {
        Some(metrics) => {
            if syn && ack { // SYN = 1 and ACK = 1
                metrics.get_receiver().update_packs_syn();
                metrics.get_receiver().update_packs_ack();
                if bytes > 0 {
                    metrics.get_receiver().update_packs_data();
                    metrics.get_receiver().update_bytes(bytes as u64);
                }
                metrics.get_receiver().update_packs(); 
                metrics.get_receiver().set_last_pack(ts);
                metrics.get_receiver().set_ts(ts);              
            }
            else if fin { // FIN = 1
                metrics.get_receiver().update_packs_fin();
                if bytes > 0 {
                    metrics.get_receiver().update_packs_data();
                    metrics.get_receiver().update_bytes(bytes as u64);
                }
                metrics.get_receiver().update_packs(); 
                metrics.get_receiver().set_last_pack(ts);
                metrics.get_receiver().set_te(ts);    
            } else if rst { // RST = 1
                metrics.get_receiver().update_packs_rst();
                if bytes > 0 {
                    metrics.get_receiver().update_packs_data();
                    metrics.get_receiver().update_bytes(bytes as u64);
                }
                metrics.get_receiver().update_packs(); 
                metrics.get_receiver().set_last_pack(ts);
                metrics.get_receiver().set_te(ts);    
            } else {   // Just a packet
                if ack { metrics.get_receiver().update_packs_ack(); }
                if urg { metrics.get_receiver().update_packs_urg(); }
                if psh { metrics.get_receiver().update_packs_psh(); }
                if bytes > 0 {
                    metrics.get_receiver().update_packs_data();
                    metrics.get_receiver().update_bytes(bytes as u64);
                }
                metrics.get_receiver().update_packs(); 
                metrics.get_receiver().set_last_pack(ts);
            } 
        },
        None => { /* Ignore it */ }
    }
    
}

fn process_udp_packet(ts: u64, len: usize, l3_header: &Ipv4Header, l4_header: &UdpHeader, map: &mut HashMap<Ipv4Connection, UdpDataExchange>) {
    let sip: Ipv4Addr = Ipv4Addr::from(l3_header.source);
    let dip: Ipv4Addr = Ipv4Addr::from(l3_header.destination);

    let sport: u16 = l4_header.source_port;
    let dport: u16 = l4_header.destination_port;

    let tx_key: Ipv4Connection = Ipv4Connection::new(sip, dip, sport, dport);
    let rx_key: Ipv4Connection = Ipv4Connection::rev(sip, dip, sport, dport);

    let l3_header_size: usize = l3_header.header_len() as usize;
    let l4_header_size: usize = l4_header.header_len() as usize;

    let bytes = if len > (l3_header_size + l4_header_size) {
        len - l3_header_size  - l4_header_size
    } else {
        0 // No payload or invalid packet
    };

    match map.get_mut(&tx_key) {
        Some(metrics) => {
            metrics.get_sender().update_packs_data();
            metrics.get_sender().update_bytes(bytes as u64);
            metrics.get_sender().update_packs();
            metrics.get_sender().set_last_pack(ts);
        },
        None => {
            map.entry(tx_key).or_insert_with(|| {
                let mut metrics = UdpDataExchange::new();
                metrics.get_sender().apply(|sender| {
                    sender.set_ts(ts);
                    sender.update_packs_data();
                    sender.update_bytes(bytes as u64);
                    sender.update_packs();
                    sender.set_last_pack(ts);
                });
                metrics
            });
        }
    }

    match map.get_mut(&rx_key) {
        Some(metrics) => {
            if metrics.get_receiver().get_ts() == 0 {
                metrics.get_receiver().update_packs_data();
                metrics.get_receiver().update_bytes(bytes as u64);
                metrics.get_receiver().update_packs();
                metrics.get_receiver().set_ts(ts);
                metrics.get_receiver().set_last_pack(ts);
            } else {
                metrics.get_receiver().update_packs_data();
                metrics.get_receiver().update_bytes(bytes as u64);
                metrics.get_receiver().update_packs();
                metrics.get_receiver().set_last_pack(ts);
            }
        },
        None => { /* Ignore it */ }
    }

    // Define the timeout
    let timeout = 30 * 1_000_000;

    for data in map.values_mut() {
        let sender = data.get_sender();
        if sender.get_te() == 0 && sender.get_last_pack() > timeout {
            sender.set_te(ts);
        }
    
        let receiver = data.get_receiver();
        if receiver.get_te() == 0 && receiver.get_last_pack() > timeout {
            receiver.set_te(ts);
        }
    }

}

pub fn process_trace(mut capture: Capture<Offline>) -> (HashMap<Ipv4Connection, TcpDataExchange>, HashMap<Ipv4Connection, UdpDataExchange>) {

    // Define the TCP connections map
    let mut tcp_map: HashMap<Ipv4Connection, TcpDataExchange> = HashMap::new();

    // Define the UDP connections map
    let mut udp_map: HashMap<Ipv4Connection, UdpDataExchange> = HashMap::new();

    while let Ok(packet) = capture.next_packet() {
        // Metadata
        let ts = (packet.header.ts.tv_sec  as u64) * 1_000_000 + 
                      (packet.header.ts.tv_usec as u64);
        
        let len = packet.header.len as usize;

        // Layer 2
        let payload = match Ethernet2Header::from_slice(packet.data) {
            Ok((_, payload)) => payload,
            _ => continue,
        };

        // Layer 3
        let (l3, data) = match Ipv4Header::from_slice(payload) {
            Ok(result) => result,
            _ => continue,
        };

        // Layer 4
        match l3.protocol {
            TCP => {
                if let Ok((l4, _)) = TcpHeader::from_slice(data) {
                    process_tcp_packet(ts, len, &l3, &l4, &mut tcp_map);
                }
            }
            UDP => {
                if let Ok((l4, _)) = UdpHeader::from_slice(data) {
                    process_udp_packet(ts, len, &l3, &l4, &mut udp_map);
                }
            }
            _ => continue
        }
    }

    return (tcp_map, udp_map)


}

pub fn print_tcp_data(path: & mut PathBuf, map: &mut HashMap<Ipv4Connection, TcpDataExchange>) -> io::Result<()> {
    // Generate the header
    let header = "s_ip s_port d_ip d_port \
                s_packs s_bytes s_packs_data s_packs_ack s_packs_syn s_packs_rst s_packs_fin s_packs_urg s_packs_psh s_ts s_te \
                d_packs d_bytes d_packs_data d_packs_ack d_packs_syn d_packs_rst d_packs_fin d_packs_urg d_packs_psh d_ts d_te";

    // Get the buffer
    let mut buffer: Vec<u8> = header.as_bytes().to_vec();

    // Loop over all connection results
    for (connection, metrics) in map {
        // Generate the record
        let record = format!("{} {} {}", 
            connection.to_string(), 
                metrics.get_sender().to_string(), 
                metrics.get_receiver().to_string());

        // Add the record
        buffer.extend_from_slice(b"\n");
        buffer.extend_from_slice(record.as_bytes());
    }

    // Open a file to write
    let mut file = File::create(path)?;

    // Write the entire concatenated buffer to the file
    file.write_all(&buffer)?;

    Ok(())
}

pub fn print_udp_data(path: & mut PathBuf, map: &mut HashMap<Ipv4Connection, UdpDataExchange>) -> io::Result<()> {
    // Generate the header
    let header = "s_ip s_port d_ip d_port \
                s_packs s_bytes s_packs_data s_ts s_te \
                d_packs d_bytes d_packs_data d_ts d_te";

    // Get the buffer
    let mut buffer: Vec<u8> = header.as_bytes().to_vec();

    // Loop over all connection results
    for (connection, metrics) in map {
        // Generate the record
        let record = format!("{} {} {}", 
            connection.to_string(), 
                metrics.get_sender().to_string(), 
                metrics.get_receiver().to_string());

        // Add the record
        buffer.extend_from_slice(b"\n");
        buffer.extend_from_slice(record.as_bytes());
    }

    // Open a file to write
    let mut file = File::create(path)?;

    // Write the entire concatenated buffer to the file
    file.write_all(&buffer)?;

    Ok(())
}