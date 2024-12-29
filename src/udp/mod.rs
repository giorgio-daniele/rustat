use core::fmt;
use std::{collections::HashMap, fs::File, io::{self, Write}, net::Ipv4Addr, path::PathBuf};

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Connection {
    sip:   Ipv4Addr,
    dip:   Ipv4Addr,
    sport: u16,
    dport: u16,
}

impl Connection {
    fn new(sip: Ipv4Addr, dip: Ipv4Addr, sport: u16, dport: u16) -> Connection {
        Connection {
            sip,
            dip,
            sport,
            dport,
        }
    }
    fn rev(sip: Ipv4Addr, dip: Ipv4Addr, sport: u16, dport: u16) -> Connection {
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
    datas: usize,
    last:  u64,
    ts: u64,
    te: u64,
}

impl Statistics {
    fn new() -> Statistics {
        Statistics {
            packs: 0,
            bytes: 0,
            datas: 0,
            last:  0,
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

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Metrics {
    client: Statistics,
    server: Statistics,
}

impl Metrics {
    fn new() -> Metrics {
        Metrics {
            client: Statistics::new(),
            server: Statistics::new(),
        }
    }
}

impl fmt::Display for Statistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        // Propagate the result from write! with the `?` operator
        write!(f, "{} {} {} {} {}",
            self.packs, self.bytes, self.datas, self.ts, self.te)?;
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

fn update(v: &mut Statistics, load: usize, ts: u64) {
    // Update timestamp last packet observed
    v.last = ts;

    // Update the number of UDP datagrams
    v.datas += 1;

    // Update the payload related count
    if load > 0 {
        v.packs += 1;
        v.bytes += load;
    }
}


pub fn process_packet(ts: u64, packet: &[u8], eth_len: usize, ip_len: usize, data: &mut HashMap<Connection, Metrics>) {

    // Compute the length of the packet, compute the UDP header size and
    // then the payload size which is within the UDP datagram
    let len = packet.len() as usize;
    let hed = 8 as usize;
    let off = eth_len + ip_len;

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

    /*  UDP is not connection oriented, therefore C2S and S2C flows 
    are not correlated. Therefore, they are traced seperately. 
    Using the convention that the client starts data exchage, a 
    new data exchange is decteted if observing a UDP datagram 
    from private IP address to a remote IP address whose socket
    has not been already observed. */

    if let Some(metrics) = data.get_mut(&key) {
        update(&mut metrics.client, pay, ts);
    }
    else if let Some(metrics) = data.get_mut(&rev) {
        update(&mut metrics.server, pay, ts);

        /* If the reverse key exists, this could be the first
        packet in the data flow on reverse direction. Therefore,
        is the ts is not already set, set it up */

        if metrics.server.ts == 0 {
            metrics.server.set_ts(ts);
        }


    } else {

        /* Neither the direct nor the reverse key has been found.
        We detected a UDP segment from a key toward a key which
        have not seen before. Therefore, this is a new data flow.
        Conventionally, data exchange is tracked using the client
        perspective. If the the sender is remote, create the
        record, but update the server side */
        
        if sip.is_private() {
            let mut metrics = Metrics::new();
            metrics.client.set_ts(ts);
            update(&mut metrics.client, pay, ts);
            data.insert(key, metrics);
        } else {
            let mut metrics = Metrics::new();
            metrics.server.set_ts(ts);
            update(&mut metrics.server, pay, ts);   
            data.insert(rev, metrics);     
        }
    
    }

    // Define the timeout value
    let timeout = 30 * 1_000_000;

    /* If no data is detected for regisered flows,
    fix the timestamp for te */

    for (_, metrics) in data.iter_mut() {
        if metrics.client.last > timeout {
            metrics.client.set_te(ts);
        }
        if metrics.server.last > timeout {
            metrics.server.set_te(ts);
        }
    }

}

pub fn print_data(path: & mut PathBuf, data: & HashMap<Connection, Metrics>) -> io::Result<()> {
    // Generate the header
    let header = "c_ip c_port s_ip s_port \
                  c_packs c_bytes c_datas c_ts c_te \
                  s_packs s_bytes s_datas s_ts s_te";

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

