/* main.rs */

pub mod parser;
pub mod tcp;
pub mod udp;

use clap::Parser;
use pcap::Capture;
use std::{fs, io, path::Path};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    input: String,
}

fn main() -> io::Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    // The input trace
    let input = &args.input;

    // Define the output folder path
    let output_folder = format!("{}.out", input);

    // Create the folder path
    let folder_path = Path::new(&output_folder);

    // Create the directory if it does not exist
    fs::create_dir_all(folder_path).expect("[ERROR]: Failed to create output folder");

    // Define the file paths where save the results
    let mut log_tcp = folder_path.join("tcp_flows.csv");
    let mut log_udp = folder_path.join("udp_flows.csv");

    match Capture::from_file(input) {
        Ok(capture) => {
            let (tcp, udp) = parser::process_trace(capture);
            match tcp::print_data(& mut log_tcp, &tcp) {
                Ok(_) => println!("[MESSAGE]: TCP connections have been reconstructed in {:?}", &log_tcp),
                Err(error) => eprintln!("[ERROR]: {}", error),
            }
            match udp::print_data(& mut log_udp, &udp) {
                Ok(_) => println!("[MESSAGE]: UDP connections have been reconstructed in {:?}", &log_udp),
                Err(error) => eprintln!("[ERROR]: {}", error),
            }
        }
        Err(error) => {
            eprintln!("[ERROR]: {}", error);
            std::process::exit(2);
        }
    }

    Ok(())
}
