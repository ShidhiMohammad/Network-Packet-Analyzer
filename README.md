# Network Packet Analyzer

This suite consists of two Python scripts that work together to parse and analyze network packets.

## Files

- `p2.py`: The main script that processes network packets, calculates various statistics, and manages network connections.
- `packet_struct.py`: A helper module that defines classes and functions used by `p2.py` for representing and manipulating packet data structures.

## Usage

To use the network packet analyzer, ensure that both `p2.py` and `packet_struct.py` are in the same directory.

Run the main script as follows:

python3 p2.py filename.cap

Enter any .cap file and sthe script should run and output information.
