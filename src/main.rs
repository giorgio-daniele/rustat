/* main.rs */

pub mod tcp;

use std::{fs::{self}, io::{self}, path::Path};
use pcap::Capture;
use tcp::{process_trace, save};
use clap::Parser;

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
    let log_tcp = folder_path.join("tcp_flows.csv");

    // Open the capture file
    let capture = Capture::from_file(input).unwrap_or_else(|error| {
        eprintln!("[ERROR]: {}", error);
        std::process::exit(2);
    });

    // Process the TCP connections from the capture
    let connections = process_trace(capture);

    // Save the TCP connections
    match save(log_tcp, connections) {
        Ok(_) => println!("[MESSAGE]: TCP connections have been reconstructed"),
        Err(error) => eprintln!("[ERROR]: {}", error),
    }

    Ok(())
}