# WPA2-Cracker

This project provides tools and scripts for generating WPA2 handshake PCAP files, brute-forcing WPA2 passwords, and analyzing WPA2 handshakes for educational and CTF purposes.

## Directory Structure
  - **solution.py**, **solution_mic.py**, **solution_pmk.py**, **solution_ptk.py**: Reference solutions for various WPA2 key derivation and MIC calculation tasks.

## Usage

### Cracking a WPA2 Handshake

To brute-force a WPA2 handshake using a password prefix:

```sh
python solution.py <SSID> <pcap file> <password prefix>
```

- `<SSID>`: The WiFi network name (e.g., `team_one_wifi`)
- `<pcap file>`: Path to the handshake PCAP (e.g., `team_name.pcap`)
- `<password prefix>`: Numeric prefix for password brute-forcing (e.g., `741`)

### Generating a PCAP File

To generate a custom WPA2 handshake PCAP for a group:

```sh
python gen.py <group_name> <output_pcap_file>
```

- `<group_name>`: Used to generate SSID and password.
- `<output_pcap_file>`: Output file path for the generated PCAP.

### Solution Scripts

- **solution_pmk.py**: Calculate the Pairwise Master Key (PMK) from SSID and password.
- **solution_ptk.py**: Calculate the Pairwise Transient Key (PTK) from PMK and handshake data.
- **solution_mic.py**: Calculate the MIC for a given PTK and EAPOL frame.

## Skeletons

The `skeletons/` directory contains starter code for CTF participants to implement WPA2 cracking logic for various challenge levels.

## Requirements

- Python 3.11
- [Scapy](https://scapy.net/)
- [pycryptodome](https://www.pycryptodome.org/) (for AES-CCMP in `gen.py`)

Install dependencies with:

```sh
pip install scapy pycryptodome
```

## License

For educational and CTF use only.

---

**Note:** This project is for educational purposes. Do not use these tools on networks you do not own or have explicit permission to test.