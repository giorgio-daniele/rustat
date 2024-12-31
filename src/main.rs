/* main.rs */

pub mod parser;
pub mod datatype;

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

    let mut log_tcp = folder_path.join("tcp_flows.csv");
    let mut log_udp = folder_path.join("udp_flows.csv");

    match Capture::from_file(input) {
        Ok(capture) => {
           let (mut tcp, mut udp) = parser::process_trace(capture);
           // Print TCP
           let _ = parser::print_tcp_data(&mut log_tcp, &mut tcp);
           // Print UDP
           let _ = parser::print_udp_data(&mut log_udp, &mut udp);
        }
        Err(error) => {
            eprintln!("[ERROR]: {}", error);
            std::process::exit(2);
        }
    }

    Ok(())
}
