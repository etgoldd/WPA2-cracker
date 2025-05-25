from scapy.all import *
import binascii
import hashlib
import hmac
import scapy.packet
import sys
from typing import *

def get_handshake(packets: PacketList) -> List[scapy.packet]:
    handshake = []
    for packet in packets:
        if scapy.all.EAPOL in packet:
            handshake.append(packet)
    return handshake

def mac_string_to_bytes(mac_string: str) -> bytes:
    return binascii.unhexlify(mac_string.replace(":","", 5))

def get_eapol_bytes(packet: scapy.packet) -> bytes:
    return bytes(packet[EAPOL])


# Extracts the two nonces from the handshake data.
# Input: handshake_data - a list of bytes objects representing handshake packets.
# Output: a tuple containing two bytes objects: (anonce, snonce).
def extract_nonces(handshake_data: List[bytes]) -> Tuple[bytes, bytes]:
    NONCE_OFFSET = 17
    NONCE_LENGTH = 32
    NONCE_END = NONCE_OFFSET + NONCE_LENGTH
    anonce_packet_data = handshake_data[0]
    snonce_packet_data = handshake_data[1]
    anonce = anonce_packet_data[NONCE_OFFSET : NONCE_END]
    snonce = snonce_packet_data[NONCE_OFFSET : NONCE_END]
    return anonce, snonce


# Prepares the EAPOL frame for MIC calculation by zeroing out the MIC field.
# Input: handshake_data - a list of bytes objects representing handshake packets.
# Output: a bytes object representing the modified EAPOL frame.
def get_mic_frame(handshake_data: List[bytes]) -> bytes:
    mic_frame = handshake_data[1]
    mic_frame = mic_frame[:81] + b"\x00" * 16 + mic_frame[97:]
    return mic_frame


# Combines MAC addresses and nonces into a single key data structure.
# Input: ap_mac, cl_mac, anonce, snonce - all as bytes objects.
# Output: a bytes object containing the combined key data.
def get_key_data(ap_mac: bytes, cl_mac: bytes, anonce: bytes, snonce: bytes) -> bytes:
    mac_addresses_pair = b"".join(sorted([ap_mac, cl_mac]))
    nonce_pair = b"".join(sorted([anonce, snonce]))
    key_data = mac_addresses_pair + nonce_pair
    return key_data


# Extracts the MIC value from the handshake data.
# Input: handshake_data - a list of bytes objects representing handshake packets.
# Output: a bytes object containing the MIC.
def get_mic(handshake_data: List[bytes]) -> bytes:
    MIC_OFFSET = 81
    MIC_LENGTH = 16
    MIC_END = MIC_OFFSET + MIC_LENGTH
    mic_packet_data = handshake_data[1]
    mic = mic_packet_data[MIC_OFFSET : MIC_END]
    return mic


# Derives the Pairwise Master Key (PMK) from the SSID and password.
# Input: ssid and password as bytes objects.
# Output: a bytes object containing the PMK.
def calc_pmk(ssid: bytes, password: bytes) -> bytes:
    result = b""
    # Put your implementation here:

    return result


# Expands the PMK and key data into the Pairwise Transient Key (PTK).
# Input: pmk and key_data as bytes objects.
# Output: a bytes object containing the PTK.
def calc_ptk(pmk: bytes, key_data: bytes) -> bytes:
    result = b""
    # Put your implementation here:

    return result


# Calculates the MIC using the PTK and the prepared EAPOL frame.
# Input: ptk as bytes, mic_frame as bytes.
# Output: a bytes object containing the MIC.
def calc_mic(ptk: bytes, mic_frame: bytes) -> bytes:
    result = b""
    # Put your implementation here:

    return result

def crack_handshake(ap_ssid: str, handshake: List[scapy.packet], password_list, debug = False) -> None:
    handshake_data = [get_eapol_bytes(packet) for packet in handshake]
    ap_mac = mac_string_to_bytes(handshake[0].addr2)
    cl_mac = mac_string_to_bytes(handshake[0].addr1)
    anonce, snonce = extract_nonces(handshake_data)
    key_data = get_key_data(ap_mac, cl_mac, anonce, snonce)
    mic = get_mic(handshake_data)
    mic_frame = get_mic_frame(handshake_data)

    for password in password_list:
        pmk = # Your implementation here
        ptk = # Your implementation here
        new_mic = # Your implementation here

        if new_mic == mic:
            print("[+] Found a key!")
            print("[+] Password : ", password)
            print("[+] PMK : ", pmk.hex())
            print("[+] PTK : ", ptk.hex())
            print("[+] MIC : ", new_mic.hex())
        elif debug:
            print("[-] Checked password does not match :(")
            print("[?] Checked password : ", password)
            print("[?] Calculated PMK : ", pmk.hex())
            print("[?] Calculated PTK : ", ptk.hex())
            print("[?] Calculated MIC : ", new_mic.hex())
            print("[?] Actual MIC     : ", mic.hex())


def crack_eapol(ap_ssid: str, pcap_filename: str, password_list, debug = False):
    packets = rdpcap(pcap_filename)
    crack_handshake(ap_ssid, get_handshake(packets), password_list, debug)


def get_password_list(prefix: str):
    result = []
    # Your implementation here:

    return result


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: ", sys.argv[0], "<beacon ssid> <pcap filename> <password prefix>")
    ssid = sys.argv[1]
    filename = sys.argv[2]
    password_prefix = sys.argv[3]
    password_list = get_password_list(password_prefix)
    crack_eapol(ssid, filename, password_list)
