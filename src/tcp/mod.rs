use core::fmt;
use std::{collections::HashMap, fs::File, io::{self, Write}, net::Ipv4Addr, path::PathBuf};

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Connection {
    sip:  Ipv4Addr,
    dip:  Ipv4Addr,
    sport: u16,
    dport: u16,
}

impl Connection {
    pub fn new(sip: Ipv4Addr, dip: Ipv4Addr, sport: u16, dport: u16) -> Connection {
        Connection {
            sip,
            dip,
            sport,
            dport,
        }
    }
    pub fn rev(sip: Ipv4Addr, dip: Ipv4Addr, sport: u16, dport: u16) -> Connection {
        Connection {
            sip: dip,
            dip: sip,
            sport: dport,
            dport: sport,
        }
    }
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        // Propagate the result from write! with the `?` operator
        write!(f, "{} {} {} {}", self.sip, self.sport, self.dip, self.dport)?;
        Ok(())
    }
}

#[derive(PartialEq, Eq, Hash, Clone)]
struct Statistics {
    packs: usize,
    bytes: usize,
    segms: usize,
    acks: usize,
    syns: usize,
    fins: usize,
    rsts: usize,
    pshs: usize,
    urgs: usize,
    ts: u64,
    te: u64,
}

impl Statistics {
    fn new() -> Statistics {
        Statistics {
            packs: 0,
            bytes: 0,
            segms: 0,
            acks: 0,
            syns: 0,
            fins: 0,
            rsts: 0,
            pshs: 0,
            urgs: 0,
            ts: 0,
            te: 0,
        }
    }
    fn set_ts(&mut self, ts: u64) {
        self.ts = ts
    }
    fn set_te(&mut self, te: u64) {
        self.te = te
    }
}

impl Metrics {
    fn new() -> Metrics {
        Metrics {
            client: Statistics::new(),
            server: Statistics::new(),
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Metrics {
    client: Statistics,
    server: Statistics,
}

impl fmt::Display for Statistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        // Propagate the result from write! with the `?` operator
        write!(f, "{} {} {} {} {} {} {} {} {} {} {}",
            self.packs, self.bytes, self.segms, self.acks, self.syns, self.fins,
            self.rsts,  self.pshs,  self.urgs,  self.ts,   self.te)?;
        Ok(())
    }
}


fn ip4_addresses(packet: &[u8], eth_head_len: usize) -> (Ipv4Addr, Ipv4Addr) {
    let sip = Ipv4Addr::new(
        packet[eth_head_len + 12],
        packet[eth_head_len + 13],
        packet[eth_head_len + 14],
        packet[eth_head_len + 15],
    );

    let dip = Ipv4Addr::new(
        packet[eth_head_len + 16],
        packet[eth_head_len + 17],
        packet[eth_head_len + 18],
        packet[eth_head_len + 19],
    );

    (sip, dip)
}

fn update(v: &mut Statistics, load: usize, flags: u8) {
    // Get all TCP flags
    let syn = (flags & 0x02) != 0;
    let ack = (flags & 0x10) != 0;
    let fin = (flags & 0x01) != 0;
    let rst = (flags & 0x04) != 0;
    let psh = (flags & 0x08) != 0;
    let urg = (flags & 0x20) != 0;

    // Update the number of TCP segments
    v.segms += 1;

    // Update the payload related count
    if load > 0 {
        v.packs += 1;
        v.bytes += load;
    }

    // Update the flag conuters
    if syn {
        v.syns += 1;
    }
    if ack {
        v.acks += 1;
    }
    if fin {
        v.fins += 1;
    }
    if rst {
        v.rsts += 1;
    }
    if psh {
        v.pshs += 1;
    }
    if urg {
        v.urgs += 1;
    }
}

pub fn process_packet(ts: u64, packet: &[u8], eth_len: usize, ip_len: usize, data: &mut HashMap<Connection, Metrics>) {

    // Compute the length of the packet, compute the UDP header size and
    // then the payload size which is within the UDP datagram
    let len = packet.len() as usize;
    let off = eth_len + ip_len;
    let hed = ((packet[off + 12] >> 4) as usize) * 4;

    if len < hed + off { 
        return; // The packet is too short, then skip it
    }

    // Compute the payload size
    let pay = len.saturating_sub(hed + off);

    // Get IP addresses
    let (sip, dip) = ip4_addresses(packet, eth_len);

    // Get the UDP ports
    let sport = u16::from_be_bytes([packet[off], packet[off + 1]]);
    let dport = u16::from_be_bytes([packet[off + 2], packet[off + 3]]);

    // Generate the connection key and its reverse
    let key = Connection::new(sip, dip, sport, dport);
    let rev = Connection::rev(sip, dip, sport, dport);

    // Get all TCP flags
    let flags = packet[off + 13];
    let syn = (flags & 0x02) != 0;
    let ack = (flags & 0x10) != 0;
    let fin = (flags & 0x01) != 0;
    let rst = (flags & 0x04) != 0;

    /*  TCP is a connection oriented protocol. The data exchange starts as soon
    as SYN packet is detected. SYN = 1 and ACK = 0 for who wants to establish
    the connection, and SYN = 1 and ACK = 1 for the other peer that accepts 
    the connection. The data exchange finishes as soon as a peer is fed up
    and transmits FIN or RST */

    if syn && !ack && sip.is_private() {
        data.insert(key.clone(), Metrics::new());
        if let Some(metrics) = data.get_mut(&key) {
            metrics.client.set_ts(ts);
        }
    } else if syn && ack && !sip.is_private() {
        if let Some(metrics) = data.get_mut(&key) {
            metrics.server.set_ts(ts);
        }
    } else if rst || fin {
        if let Some(metrics) = data.get_mut(&key) {
            metrics.client.set_te(ts);
        }
        if let Some(metrics) = data.get_mut(&rev) {
            metrics.client.set_te(ts);
        }
    }

    if let Some(metrics) = data.get_mut(&key) {
        update(&mut metrics.client, pay, flags);
    }
    if let Some(metrics) = data.get_mut(&rev) {
        update(&mut metrics.server, pay, flags);
    }
}

pub fn print_data(path: & mut PathBuf, data: & HashMap<Connection, Metrics>) -> io::Result<()> {
    // Generate the header
    let header = "c_ip c_port s_ip s_port \
                  c_packs c_bytes c_segms c_acks c_syns c_fins c_rsts c_pshs c_urgs c_ts c_te \
                  s_packs s_bytes s_segms s_acks s_syns s_fins s_rsts s_pshs s_urgs s_ts s_te";

    // Get the buffer
    let mut buffer: Vec<u8> = header.as_bytes().to_vec();

    // Loop over all connection results
    for (connection, metrics) in data {
        // Generate the record
        let record = format!("{} {} {}", 
            connection.to_string(), 
                metrics.client.to_string(), 
                metrics.server.to_string());

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