# WPA2 CTF Challenge: Packet Generator and Solution

## Overview

This repository contains two Python scripts designed for a Capture The Flag (CTF) challenge focused on the WPA2 protocol. The challenge involves understanding and exploiting the WPA2 handshake mechanism to retrieve a hidden flag. 

- **`gen_basic_pcap_with_comments.py`**: A script to generate PCAP files simulating WPA2-encrypted communication, including the 4-way handshake and encrypted messages.
- **`solution.py`**: A script to analyze the generated PCAP file, extract the WPA2 handshake, and attempt to crack the pre-shared key (PSK) using a password list.

---

## What is WPA2?

WPA2 (Wi-Fi Protected Access 2) is a security protocol used to secure wireless networks. It employs the 4-way handshake mechanism to establish a secure connection between a client and an access point (AP). The handshake ensures that both parties share a Pairwise Master Key (PMK) derived from the pre-shared key (PSK) and other parameters like nonces and MAC addresses. The handshake also verifies the integrity of the connection using a Message Integrity Code (MIC).

---

## File Descriptions

### 1. `gen_basic_pcap_with_comments.py`

This script generates a PCAP file simulating a WPA2 handshake and encrypted communication. It includes:

- **Unencrypted UDP communication**: Simulates initial communication between two devices (Alice and Bob).
- **WPA2 4-way handshake**: Simulates the handshake process between a client and an AP.
- **Encrypted communication**: Simulates encrypted messages exchanged after the handshake.

#### Key Features:
- Customizable parameters like SSID, passkey, MAC addresses, and messages.
- Option to simulate a faulty MIC for testing purposes.
- Outputs the PCAP file to a specified location or as a `BytesIO` object.

---

### 2. `solution.py`

This script analyzes the generated PCAP file to extract the WPA2 handshake and attempts to crack the PSK using a password list.

#### Key Features:
- Extracts the 4-way handshake from the PCAP file.
- Derives the PMK and PTK using the SSID and password.
- Validates the MIC to identify the correct password.
- Supports multiple password list types:
    - **`guess_taz`**: Generates 9-digit ID numbers based on a prefix.
    - **`password_file`**: Reads passwords from a file.
    - **`single_guess`**: Tests a single password.

---

## How to Use

### Prerequisites

- Python 3.x
- Required Python libraries: `scapy`, `binascii`, `hashlib`, `hmac`
- Install dependencies using:
    ```bash
    pip install scapy
    ```

---

### Step 1: Generate the PCAP File

Run the `gen_basic_pcap_with_comments.py` script to create a PCAP file for the challenge.

#### Example Usage:
```bash
python gen_basic_pcap_with_comments.py <team_name> <output_pcap_file> [faulty_mic] [flag]
```

#### Parameters:
- `<team_name>`: Name of the team or group (used to generate SSID, passkey, and flag).
- `<output_pcap_file>`: Path to save the generated PCAP file.
- `[faulty_mic]` (optional): Set to `True` to simulate a faulty MIC.
- `[flag]` (optional): Custom flag to embed in the encrypted communication.

#### Example:
```bash
python gen_basic_pcap_with_comments.py groupname challenge.pcap
```

---

### Step 2: Crack the WPA2 Handshake

Run the `solution.py` script to analyze the PCAP file and crack the PSK.

#### Example Usage:
```bash
python solution.py <ssid> <pcap_file> <password_list_type> <password_list_specifier>
```

#### Parameters:
- `<ssid>`: SSID of the WPA2 network.
- `<pcap_file>`: Path to the PCAP file to analyze.
- `<password_list_type>`: Type of password list to use (`guess_taz`, `password_file`, or `single_guess`).
- `<password_list_specifier>`: Specifier for the password list:
    - For `guess_taz`: Prefix for generating 9-digit IDs.
    - For `password_file`: Path to the password file.
    - For `single_guess`: The single password to test.

#### Example:
```bash
python solution.py groupname_wifi challenge.pcap password_file passwords.txt
```

---

## Example Workflow

1. **Generate the PCAP file**:
     ```bash
     python gen_basic_pcap_with_comments.py groupname challenge.pcap
     ```

2. **Crack the handshake using a password file**:
     ```bash
     python solution.py groupname_wifi challenge.pcap password_file passwords.txt
     ```

3. **Crack the handshake using a single guess**:
     ```bash
     python solution.py groupname_wifi challenge.pcap single_guess groupname_super_secret_password
     ```

4. **Crack the handshake using `guess_taz`**:
     ```bash
     python solution.py groupname_wifi challenge.pcap guess_taz 1234
     ```

---

## Notes

- The `gen_basic_pcap_with_comments.py` script is designed for educational purposes and should not be used for malicious activities.
- Ensure you have permission to analyze any PCAP files you work with.
- The challenge is intended to deepen your understanding of WPA2 security and cryptographic protocols.

---  