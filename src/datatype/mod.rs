use std::{fmt, net::Ipv4Addr};

/// Represents the source and destination IP addresses and TCP/UDP ports of a flow
#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Ipv4Connection {
    sip:   Ipv4Addr,
    dip:   Ipv4Addr,
    sport: u16,
    dport: u16,
}

impl Ipv4Connection {
    pub fn new(sip: Ipv4Addr, dip: Ipv4Addr, sport: u16, dport: u16) -> Ipv4Connection {
        Ipv4Connection { sip, dip, sport, dport }
    }

    pub fn rev(sip: Ipv4Addr, dip: Ipv4Addr, sport: u16, dport: u16) -> Ipv4Connection {
        Ipv4Connection { sip: dip, dip: sip, sport: dport, dport: sport }
    }
}

impl fmt::Display for Ipv4Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} {}", self.sip, self.sport, self.dip, self.dport)
    }
}


#[derive(PartialEq, Eq, Hash, Clone, Default)]
pub struct TcpFlowMetrics {
    packs: u64,         // How many TCP packets
    bytes: u64,         // How many TCP data bytes
    packs_data: u64,    // How many TCP packets with data
    packs_ack:  u64,    // How many TCP packets with ACK = 1
    packs_syn:  u64,    // How many TCP packets with SYN = 1
    packs_rst:  u64,    // How many TCP packets with RST = 1
    packs_fin:  u64,    // How many TCP packets with FIN = 1
    packs_urg:  u64,    // How many TCP packets with URG = 1
    packs_psh:  u64,    // How many TCP packets with PSH = 1
    last_pack:  u64,    // Last packet observed (relative)
    ts: u64,            // First packet observed
    te: u64,            // Last packet observed (absolute)
}

#[derive(PartialEq, Eq, Hash, Clone, Default)]
pub struct UdpFlowMetrics {
    packs: u64,         // How many UDP packets
    bytes: u64,         // How many UDP data bytes
    packs_data: u64,    // How many UDP packets with data
    last_pack:  u64,    // Last packet observed (relative)
    ts: u64,            // First packet observed
    te: u64,            // Last packet observed (absolute)
}

impl TcpFlowMetrics {
    pub fn new() -> TcpFlowMetrics {
        TcpFlowMetrics::default()
    }

    pub fn set_ts(&mut self, ts: u64) {
        self.ts = ts
    }

    pub fn set_te(&mut self, te: u64) {
        self.te = te
    }

    pub fn set_last_pack(&mut self, last_pack: u64) {
        self.last_pack = last_pack;
    }

    pub fn update_packs(&mut self) {
        self.packs += 1;
    }

    pub fn update_bytes(&mut self, bytes: u64) {
        self.bytes += bytes;
    }

    pub fn update_packs_data(&mut self) {
        self.packs_data += 1;
    }

    pub fn update_packs_ack(&mut self) {
        self.packs_ack += 1;
    }

    pub fn update_packs_syn(&mut self) {
        self.packs_syn += 1;
    }

    pub fn update_packs_rst(&mut self) {
        self.packs_rst += 1;
    }

    pub fn update_packs_fin(&mut self) {
        self.packs_fin += 1;
    }

    pub fn update_packs_urg(&mut self) {
        self.packs_urg += 1;
    }

    pub fn update_packs_psh(&mut self) {
        self.packs_psh += 1;
    }

    // Apply method: Allows applying a closure to modify the fields
    pub fn apply<F>(&mut self, f: F)
    where
        F: FnOnce(&mut TcpFlowMetrics),
    {
        f(self)
    }
}

impl fmt::Display for TcpFlowMetrics {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} {} {} {} {} {} {} {} {}",
            self.packs, self.bytes, self.packs_data, 
            self.packs_ack, self.packs_syn, self.packs_rst, self.packs_fin,
            self.packs_urg, self.packs_psh, 
            self.ts, self.te)
    }
}

impl UdpFlowMetrics {
    pub fn new() -> UdpFlowMetrics {
        UdpFlowMetrics::default()
    }

    pub fn set_ts(&mut self, ts: u64) {
        self.ts = ts;
    }

    pub fn set_te(&mut self, te: u64) {
        self.te = te;
    }

    pub fn get_ts(&mut self) -> u64 {
        self.ts
    }

    pub fn get_te(&mut self) -> u64 {
        self.te
    }

    pub fn get_last_pack(&mut self) -> u64 {
        self.last_pack
    }

    pub fn set_last_pack(&mut self, last_pack: u64) {
        self.last_pack = last_pack;
    }

    pub fn update_packs(&mut self) {
        self.packs += 1;
    }

    pub fn update_bytes(&mut self, bytes: u64) {
        self.bytes += bytes;
    }

    pub fn update_packs_data(&mut self) {
        self.packs_data += 1;
    }

    // Apply method: Allows applying a closure to modify the fields
    pub fn apply<F>(&mut self, f: F)
    where
        F: FnOnce(&mut UdpFlowMetrics),
    {
        f(self)
    }
}

impl fmt::Display for UdpFlowMetrics {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} {} {}",
            self.packs, self.bytes, self.packs_data, self.ts, self.te)
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Default)]
pub struct UdpDataExchange {
    sender: UdpFlowMetrics,
    receiver: UdpFlowMetrics
}

#[derive(PartialEq, Eq, Hash, Clone, Default)]
pub struct TcpDataExchange {
    sender: TcpFlowMetrics,
    receiver: TcpFlowMetrics
}

impl TcpDataExchange {
    pub fn new() -> TcpDataExchange {
        TcpDataExchange::default()
    }

    pub fn get_sender(&mut self) -> &mut TcpFlowMetrics {
        &mut self.sender
    }

    pub fn get_receiver(&mut self) -> &mut TcpFlowMetrics {
        &mut self.receiver
    }
}

impl UdpDataExchange {
    pub fn new() -> UdpDataExchange {
        UdpDataExchange::default()
    }

    pub fn get_sender(&mut self) -> &mut UdpFlowMetrics {
        &mut self.sender
    }

    pub fn get_receiver(&mut self) -> &mut UdpFlowMetrics {
        &mut self.receiver
    }
}
