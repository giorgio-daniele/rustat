/* main.rs */

pub mod parser;
pub mod datatype;

use clap::Parser;
use datatype::{Ipv4Connection, TcpDataExchange, UdpDataExchange};
use pcap::Capture;
use std::{collections::HashMap, fs, io, net::Ipv4Addr, path::Path, str::FromStr};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    input: String,
    #[arg(short, long)]
    subnet: String,

}


fn parse_cidr(cidr: &str) -> Option<(Ipv4Addr, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 { return None; }

    let ip = Ipv4Addr::from_str(parts[0]).ok()?;
    let mask_len: u8 = parts[1].parse().ok()?;

    let mask = Ipv4Addr::from(u32::MAX << (32 - mask_len));
    let network = Ipv4Addr::new(
        ip.octets()[0] & mask.octets()[0],
        ip.octets()[1] & mask.octets()[1],
        ip.octets()[2] & mask.octets()[2],
        ip.octets()[3] & mask.octets()[3],
    );

    Some((network, mask_len))
}

fn main() -> io::Result<()> {

    // Parse command-line arguments
    let args = Args::parse();

    // The wireshark input trace
    let input = &args.input;

    // The network that is defined as LAN
    let (network, mask) = match parse_cidr(&args.subnet) {
        Some((network, mask)) => (network, mask),
        None => {
            println!("[ERROR]: could not parse the network");
            std::process::exit(1)
        }
    };

    // Define the output folder path
    let output_folder = format!("{}.out", input);

    // Create the folder path
    let folder_path = Path::new(&output_folder);

    // Create the directory if it does not exist
    fs::create_dir_all(folder_path).expect("[ERROR]: Failed to create output folder");

    // Define the output for reconstructed flows
    let mut log_tcp = folder_path.join("tcp_flows.csv");
    let mut log_udp = folder_path.join("udp_flows.csv");

    match Capture::from_file(input) {
        Ok(capture) => {

            // Define the TCP connections map
            let mut tcp_map: HashMap<Ipv4Connection, TcpDataExchange> = HashMap::new();

            // Define the UDP connections map
            let mut udp_map: HashMap<Ipv4Connection, UdpDataExchange> = HashMap::new();

            // Process trace
            parser::process_trace(capture, (network, mask), &mut tcp_map, &mut udp_map);
           
            // Print TCP
            let _ = parser::print_tcp_data(&mut log_tcp, &mut tcp_map);
            // Print UDP
            let _ = parser::print_udp_data(&mut log_udp, &mut udp_map);
        }
        Err(error) => {
            eprintln!("[ERROR]: {}", error);
            std::process::exit(2);
        }
    }

    Ok(())
}
