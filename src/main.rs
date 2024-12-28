pub mod tcp;

use pcap::Capture;
use tcp::process_trace;
use clap::Parser;


#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    input: String,

}

fn main() {
    let args = Args::parse();

    // The input trace
    let input = args.input;

    match Capture::from_file(input) {
        Ok(capture) => {
            let connections = process_trace(capture);

            // Print the header
            println!("c_ip c_port s_ip s_port \
            c_packs c_bytes c_segms c_acks c_syns c_fins c_rsts c_pshs c_urgs c_ts c_te \
            s_packs s_bytes s_segms s_acks s_syns s_fins s_rsts s_pshs s_urgs s_ts s_te");

            // Print the connections
            for (connection, (client, server)) in connections {
                println!("{} {} {}", connection, client, server)
            }
        }
        Err(error) => {
            println!("[ERROR]: {}", error);
            std::process::exit(1);
        }
    }
    std::process::exit(0);
}
