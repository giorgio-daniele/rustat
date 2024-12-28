# Rustat
Rustat is a simple clone of [Tstat](http://www.tstat.polito.it/), written in Rust. I developed it during Xmas 2024 holidays as a way to cope with my schizophrenia crisis.
## Features

- Detailed statistical breakdown of TCP in offline (e.g., .pcap trace)

## Requirements

- Rust (latest stable version)
- Libpcap or equivalent packet capture library

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/giorgio-daniele/rustat.git
   cd rustat
   ```

2. Build the project:
   ```bash
   cargo build --release
   ```

3. Run the executable (requires root privileges for packet capture):
   ```bash
   sudo ./target/release/rustat
   ```

## Usage

### Basic Usage
Run Rustat on a specific network interface:
```bash
./target/release/rustat --input <filename>
```

### Options
- `--input <filename>`: Specify the pcap trace to be analyzed


## Output
Rustat provides detailed statistics, including:
- IP addresses
- TCP ports
- Packet counts
- Byte counts
- TCP flags count