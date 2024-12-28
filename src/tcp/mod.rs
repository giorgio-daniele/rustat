use std::{collections::HashMap, fmt, fs::File, io::{self, Write}, net::Ipv4Addr, path::PathBuf};
use pcap::{Capture, Offline};


const ETHERNET_HEADER_SIZE: usize = 14;  // Ethernet header size in bytes
const MIN_IP_HEADER_SIZE:   usize = 20;  // Minimum size of IPv4 header
const MIN_TCP_HEADER_SIZE:  usize = 20;  // Minimum size of TCP header

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Connection {
    sip:   Ipv4Addr,
    dip:   Ipv4Addr,
    sport: u16,
    dport: u16,
}

// #[derive(PartialEq, Eq, Hash, Clone)]
// enum Status {
//     Opened,
//     Closed,
// }


pub struct Metrics {
    packs: usize,
    bytes: usize,
    segms: usize,
    acks:  usize,
    syns:  usize,
    fins:  usize,
    rsts:  usize,
    pshs:  usize,
    urgs:  usize,
    // stat:  Status,
    ts:    u64,
    te:    u64
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        // Propagate the result from write! with the `?` operator
        write!(f, "{} {} {} {}", self.sip, self.sport, self.dip, self.dport)?;
        Ok(())
    }
}
impl Metrics {
    fn new() -> Metrics {
        Metrics { 
            packs: 0, 
            bytes: 0, 
            segms: 0, 
            acks:  0, 
            syns:  0, 
            fins:  0, 
            rsts:  0, 
            pshs:  0, 
            urgs:  0, //stat: Status::Opened, 
            ts: 0, te: 0 }
    }
    // fn set_closed(& mut self) {
    //     self.stat = Status::Closed
    // }
    // fn set_opened(& mut self) {
    //     self.stat = Status::Opened
    // }
    fn set_ts(&mut self, ts: u64) {
        self.ts = ts
    }
    fn set_te(&mut self, te: u64) {
        self.te = te
    }

}

impl fmt::Display for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        // Propagate the result from write! with the `?` operator
        write!(f, "{} {} {} {} {} {} {} {} {} {} {}",
            self.packs, self.bytes, self.segms, self.acks, self.syns, self.fins,
            self.rsts,  self.pshs,  self.urgs,  self.ts,   self.te)?;
        Ok(())
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


pub fn process_trace(mut cap: Capture<Offline>) -> HashMap<Connection, (Metrics, Metrics)> {
    let mut connections: HashMap<Connection, (Metrics, Metrics)> = HashMap::new();

    while let Ok(pkt) = cap.next_packet() {
        // Get the packet len
        let len = pkt.header.len as usize;

        // Get the timestamp
        let sec  = pkt.header.ts.tv_sec  as u64;
        let usec = pkt.header.ts.tv_usec as u64;

        // Generate the timestamp
        let ts = sec * 1_000_000 + usec;

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

        // Client open a new connection
        if syn && !ack && sip.is_private() {
            connections.insert(key.clone(), (Metrics::new(), Metrics::new()));
            if let Some((metric, _)) = connections.get_mut(&key) {
                //metric.set_opened();
                metric.set_ts(ts);
                
            }
        // Server accept the connection
        } else if syn && ack && !sip.is_private() {
            if let Some((_, metric)) = connections.get_mut(&rev) {
                //metric.set_opened();
                metric.set_ts(ts);
            }
        // A peer wants to disconnect
        } else if rst || fin {
            if let Some((metric, _)) = connections.get_mut(&key) {
                //metric.set_closed();
                metric.set_te(ts);
            }
            if let Some((_, metric)) = connections.get_mut(&rev) {
                //metric.set_closed();
                metric.set_te(ts);
            }
        }

        if let Some((metric, _)) = connections.get_mut(&key) {
            update_metrics(metric);
        }
        if let Some((_, metric)) = connections.get_mut(&rev) {
            update_metrics(metric);
        }
    }

    connections
}



pub fn save(path: PathBuf, connections: HashMap<Connection, (Metrics, Metrics)>) -> io::Result<()> {
    // Generate the header
    let header = "c_ip c_port s_ip s_port \
                  c_packs c_bytes c_segms c_acks c_syns c_fins c_rsts c_pshs c_urgs c_ts c_te \
                  s_packs s_bytes s_segms s_acks s_syns s_fins s_rsts s_pshs s_urgs s_ts s_te";

    // Get the buffer
    let mut buffer: Vec<u8> = header.as_bytes().to_vec();

    // Loop over all connection results
    for (connection, (client, server)) in connections {
        // Generate the record
        let record = format!("{} {} {}", connection.to_string(), client, server);

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