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

def extract_nonces(handshake_data: List[bytes]) -> Tuple[bytes, bytes]:
    NONCE_OFFSET = 17
    NONCE_LENGTH = 32
    NONCE_END = NONCE_OFFSET + NONCE_LENGTH
    anonce_packet_data = handshake_data[0]
    snonce_packet_data = handshake_data[1]
    anonce = anonce_packet_data[NONCE_OFFSET : NONCE_END]
    snonce = snonce_packet_data[NONCE_OFFSET : NONCE_END]
    return anonce, snonce

def get_mic_frame(handshake_data: List[bytes]) -> bytes:
    mic_frame = handshake_data[1]
    mic_frame = mic_frame[:81] + b"\x00" * 16 + mic_frame[97:]
    return mic_frame

def get_key_data(ap_mac: bytes, cl_mac: bytes, anonce: bytes, snonce: bytes) -> bytes:
    mac_addresses_pair = b"".join(sorted([ap_mac, cl_mac]))
    nonce_pair = b"".join(sorted([anonce, snonce]))
    key_data = mac_addresses_pair + nonce_pair
    return key_data

def get_mic(handshake_data: List[bytes]) -> bytes:
    MIC_OFFSET = 81
    MIC_LENGTH = 16
    MIC_END = MIC_OFFSET + MIC_LENGTH
    mic_packet_data = handshake_data[1]
    mic = mic_packet_data[MIC_OFFSET : MIC_END]
    return mic

def calc_pmk(ssid: bytes, password: bytes) -> bytes:
    pmk = hashlib.pbkdf2_hmac('sha1', password, ssid, 4096, 32)
    return pmk

def calc_ptk(pmk: bytes, key_data: bytes) -> bytes:
    pke = b"Pairwise key expansion"
    blen = 64
    i = 0
    ptk = b""

    while len(ptk) < blen:
        hmacsha1 = hmac.new(pmk, pke + b"\x00" + key_data + bytes([i]), hashlib.sha1)
        ptk += hmacsha1.digest()
        i += 1

    return ptk[:blen]

def calc_mic(ptk: bytes, mic_frame: bytes) -> bytes:
    mic = hmac.new(ptk[0:16], mic_frame, "sha1").digest()
    return mic[:-4]


if __name__ == "__main__":
    if len(sys.argv) <= 2:
        print("Usage: ", sys.argv[0], "<PTK> <FRAME_DATA>")
        sys.exit(1)
    ptk_hex = sys.argv[1]
    frame_data_hex = sys.argv[2]
    mic = calc_mic(
        binascii.unhexlify(ptk_hex),
        binascii.unhexlify(frame_data_hex)
    )
    print("mic: ", binascii.hexlify(mic).decode('utf-8'))

