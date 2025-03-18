from scapy.all import *
from scapy.layers.l2 import ARP, Ether, LLC, SNAP
import binascii
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dot11 import (
    Dot11,
    Dot11QoS,
    RadioTap,
    Dot11CCMP,
    Dot11Auth,
    Dot11AssoReq,
    Dot11AssoResp,
    Dot11Elt,
    Dot11WEP,
    Dot11FCS
)
import hashlib
import hmac
from Crypto.Cipher import AES
from scapy.packet import Raw, Packet
from scapy.layers.eap import EAPOL
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import struct
import os

def calc_pmk(ssid: bytes, password: bytes) -> bytes:
    pmk = hashlib.pbkdf2_hmac('sha1', password, ssid, 4096, 32)
    return pmk

def prf512(key, label, data):
    result = b''
    i = 0
    while len(result) < 64:
        hmac_sha1 = hmac.new(key, label.encode() + b'\x00' + data + bytes([i]), hashlib.sha1)
        result += hmac_sha1.digest()
        i += 1
    return result[:64]

def calc_ptk(pmk: bytes, key_data: bytes) -> bytes:
    return prf512(pmk, "Pairwise key expansion", key_data)

def get_key_data(ap_mac: bytes, cl_mac: bytes, anonce: bytes, snonce: bytes) -> bytes:
    mac_addresses_pair = b"".join(sorted([ap_mac, cl_mac]))
    nonce_pair = b"".join(sorted([anonce, snonce]))
    key_data = mac_addresses_pair + nonce_pair
    return key_data

def mac_string_to_bytes(mac_string: str) -> bytes:
    return binascii.unhexlify(mac_string.replace(":","", 5))

def construct_aad(frame):
    data = bytes(frame)
    return data[0:2] + data[4:22] + data[30:34]

def create_encrypted_packet(src_mac: str, dst_mac: str, anonce: bytes, snonce: bytes, ssid: str, passkey: str, header, payload):
    header_bytes = bytes(header)
    assert len(header_bytes) >= 34
    pmk = calc_pmk(ssid.encode('ascii'), passkey.encode("ascii"))
    key_data = get_key_data(mac_string_to_bytes(src_mac), mac_string_to_bytes(dst_mac), anonce, snonce)
    ptk = calc_ptk(pmk, key_data)
    tk = ptk[32:48]
    aad = construct_aad(header)
    ccmp_header = header[Dot11CCMP]
    packet_number = b"".join([i.to_bytes(1, 'little') for i in [ccmp_header.PN0, ccmp_header.PN1, ccmp_header.PN2, ccmp_header.PN3, ccmp_header.PN4, ccmp_header.PN5]])
    plaintext = bytes(payload)
    ccm_nonce = struct.pack(">B", 0) + mac_string_to_bytes(header.addr2) + packet_number[::-1]
    aes_ccm = AES.new(tk, AES.MODE_CCM, nonce=ccm_nonce, mac_len=8)
    aes_ccm.update(aad)
    ciphertext, mic = aes_ccm.encrypt_and_digest(plaintext)
    data_frame = header
    data_frame[Dot11CCMP].data = ciphertext + mic
    return data_frame

def gen_header(packet_number: int, src_mac: str, dst_mac: str, bssid: str):
    pn = packet_number.to_bytes(6, 'little')
    return (Dot11(proto = 0, addr1=dst_mac, addr2=src_mac, addr3=bssid, SC = 16, ID = 12288, FCfield="to-DS+protected", type = "Data", subtype = "QoS Data") 
        / Dot11QoS(A_MSDU_Present = 0, Ack_Policy = 0, EOSP = 0, TID = 0, TXOP = 0)
        / Dot11CCMP(PN0 = pn[0], PN1 = pn[1], PN2 = pn[2], PN3 = pn[3], PN4 = pn[4], PN5 = pn[5], ext_iv = 1))

dst_mac = "28:b3:71:34:f6:bc"
src_mac = "30:05:05:75:be:df"
bssid = "00:09:0f:09:00:1a"

ssid = "Building_G2"
passkey = "123456789"

anonce = binascii.a2b_hex("9a3a87b7947de01174fa0aa2e5a61dfa5a7b165d698e0b4624994817af48d7df")
snonce = binascii.a2b_hex("013a9e0394be853e01ce13c180052a4bf42f57c0dbe398fee3ba00269233ac60")

tcp_payload = b"Hello, this is a WPA2 encrypted TCP message!"
pn = b"\x03\x00\x00\x00\x00\x00"
header = gen_header(123, src_mac, dst_mac, bssid)
header.show()
alice_ip = "192.168.1.100"
bob_ip = "192.168.1.200"
payload = (IP(src=alice_ip, dst=bob_ip)
            / UDP(sport=34343, dport=43434)
            / tcp_payload)
my_packet = create_encrypted_packet(src_mac, dst_mac, anonce, snonce, ssid, passkey, header, payload)

pcap_writer = PcapWriter("./test.pcap", linktype=105)
pcap_writer.write(my_packet)
pcap_writer.close()


#create_encrypted_packet(tcp_payload, src_mac, dst_mac, bssid, iface)