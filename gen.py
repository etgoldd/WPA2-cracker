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

# WPA2 CCMP Parameters
TK = b'\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00'  # Temporal Key from PTK
PN = os.urandom(6)  # Randomized Packet Number (must increment for real use)
KEY_ID = 0  # Usually 0 in WPA2-CCMP

def construct_ccmp_header(pn, key_id=0):
    """ Create the CCMP header: 8 bytes """
    return struct.pack("<BB6s", key_id << 6, 0, pn)

def generate_aes_ctr_keystream(tk, pn, src_addr):
    """ Generate AES-CTR keystream block for CCMP """
    nonce = struct.pack(">6s6sB", pn, src_addr, 0)  # 13-byte nonce
    cipher = Cipher(algorithms.AES(tk), modes.CTR(nonce + b'\x00' * 3), backend=default_backend())
    return cipher.encryptor()

def encrypt_ccmp(tk, plaintext, pn, src_addr):
    """ Encrypt data using WPA2 AES-CCMP """
    aes_ctr = generate_aes_ctr_keystream(tk, pn, src_addr)
    return aes_ctr.update(plaintext)

def construct_mic(ptk, data):
    """ Compute MIC using AES-CMAC (WPA2 MIC) """
    cipher = Cipher(algorithms.AES(ptk[:16]), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data)[:8]  # MIC is 8 bytes

def calc_pmk(ssid: bytes, password: bytes) -> bytes:
    pmk = hashlib.pbkdf2_hmac('sha1', password, ssid, 4096, 32)
    return pmk

def calc_ptk(pmk: bytes, key_data: bytes) -> bytes:
    return hmac.new(pmk, key_data, hashlib.sha1).digest()

def get_key_data(ap_mac: bytes, cl_mac: bytes, anonce: bytes, snonce: bytes) -> bytes:
    mac_addresses_pair = b"".join([ap_mac, cl_mac])
    nonce_pair = b"".join([anonce, snonce])
    key_data = mac_addresses_pair + nonce_pair
    return key_data

def mac_string_to_bytes(mac_string: str) -> bytes:
    return binascii.unhexlify(mac_string.replace(":","", 5))

def construct_aad(frame):
    """
    Constructs Additional Authentication Data (AAD) from the given frame.
    """
    return b"cum in may abum"
    print(len(bytes(frame)))
    return bytes(frame)[:22]
    return aad

def create_encrypted_packet(payload, src_mac, dst_mac, bssid, iface):
    """ Construct and send an encrypted WPA2 packet """
    global PN  # Increment PN for each packet
    PN = (int.from_bytes(PN, 'big') + 1).to_bytes(6, 'big')

    # IEEE 802.11 Header
    dot11 = Dot11(addr1=dst_mac, addr2=src_mac, addr3=bssid)

    # Construct CCMP Header
    ccmp_header = construct_ccmp_header(PN, KEY_ID)

    # Encrypt the Payload
    encrypted_payload = encrypt_ccmp(TK, payload, PN, src_mac.encode())

    # Calculate MIC
    mic = construct_mic(TK, payload)
    pn = b"\x03\x00\x00\x20\x00\x00"
    pn2 = b"\x03\x00\x00\x00\x00\x00"
    #my_payload = pn + "\x00\x00"
    #extra = binascii.a2b_hex("bf1a12c4e1e47abdaae4ddd9fb256587f35e95234119dd0d926451bad5a274c98bc36c0b0239f0576689e7e3da4bf5a1568c860cf7326a2c4c7a8e6906520fa0bb2d619b754e8ba64732487410de4ef20f92cb5108e025776e1470e655159f445afc71e0ce7f2367659959fd03dd9afcdc62d14216717ab3aebd71a1a40b5c611246ac66f22fea19c4d91efdb6")
    anonce = binascii.a2b_hex("35150fb389271918e8eff0f4364108564b0761df4bfd626ab9e305633d1f3670")  # Authenticator Nonce
    snonce = binascii.a2b_hex("b775219afea457324ef8aee63c01333edda6aae0a6bf7eb968f0a5d870b99d96")  # Supplicant Nonce

    key_data = get_key_data(mac_string_to_bytes(src_mac), mac_string_to_bytes(dst_mac), anonce, snonce)

    pmk = calc_pmk("Verizon_W3HVD4".encode('ascii'), "strew6-quay-gnu".encode('ascii'))
    ptk = calc_ptk(pmk, key_data)

    plaintext = binascii.a2b_hex("aaaa0300000008004500007ddb520000ff113cd9c0a801a0e00000fb14e914e9006924d20000000000020000000000010f5f636f6d70616e696f6e2d6c696e6b045f746370056c6f63616c00000c80010c5f736c6565702d70726f7879045f756470c021000c800100002905a00000119400120004000e005f5aa878f114458ed339d74058")
    frame = (Dot11(proto = 0, addr1=dst_mac, addr2=src_mac, addr3=bssid, SC = 16, ID = 12288, FCfield="to-DS+protected+order", type = "Data", subtype = "QoS Data") 
        / Dot11QoS(A_MSDU_Present = 0, Ack_Policy = 0, EOSP = 1, TID = 6, TXOP = 11))
    # Construct the AAD (Additional Authentication Data)
    aad = construct_aad(frame)
    print(ptk.hex())
    for i in range(256):
        #key = ptk[:16]; payload= b"0xaa"*32;import hmac; import hashlib; print(hmac.new(key, plaintext, hashlib.sha1).digest()[:16])
        #ccm_nonce = struct.pack(">B", 0) + mac_string_to_bytes(frame.addr2) + pn2[0:6]
        ccm_nonce = struct.pack(">B", i) + mac_string_to_bytes(frame.addr2) + pn2[0:6]
        #plaintext = b"\x00" * 64
        ciphertext2 = binascii.a2b_hex("bf1a12c4e1e47abdaae4ddd9fb256587f35e95234119dd0d926451bad5a274c98bc36c0b0239f0576689e7e3da4bf5a1568c860cf7326a2c4c7a8e6906520fa0bb2d619b754e8ba64732487410de4ef20f92cb5108e025776e1470e655159f445afc71e0ce7f2367659959fd03dd9afcdc62d14216717ab3aebd71a1a40b5c611246ac66f22fea19c4")
        #cipher = AES.new(ptk[:16], AES.MODE_CCM, nonce=ccm_nonce, mac_len=8)
        #cipher.update(aad)
        #print(cipher(ciphertext2))
        # Compute CCM Nonce (13 Bytes) -> PN + Source MAC + Priority (0)
        #ccm_nonce = pn + mac_string_to_bytes(src_mac) + b"\x00"
        # Compute MIC (AES-CCM with PTK)
        aes_ccm = AES.new(ptk[:16], AES.MODE_CCM, nonce=ccm_nonce, mac_len=8)
        aes_ccm.update(aad)  # Additional Authentication Data (AAD)
        ciphertext, mic = aes_ccm.encrypt_and_digest(plaintext)
        cipher = AES.new(ptk[:16], AES.MODE_CCM, nonce=ccm_nonce, mac_len=8)
        cipher.update(aad)
        if ciphertext[0] == b"\xbf":
        #cipher.decrypt(ciphertext2)[0] == b"\xaa":
            print(i)
            print(cipher.decrypt(ciphertext2)[:16].hex())
            print(ciphertext[:8], mic)
        my_payload = pn + 2 * b"\x00" + ciphertext
        # Construct Full Encrypted Frame
        frame2 = (frame
            #/ Dot11CCMP(key_id = 0, ext_iv = 123213)
            #/ Dot11CCMP(PN0 = 12, PN1 = 7, res0 = 0, key_id = 1, ext_iv = 1, res1 = 0, PN2 = 2, PN3 = 0, PN4 = 255, PN5 = 255, data = my_payload)
            #/ Dot11WEP(iv = b"\x0F\xb2\x00\x00", keyid = 0, wepdata = my_payload, icv = int.from_bytes(mic, 'little'))
            / Raw(b"\x0F\xb2\x00\x00" + my_payload + mic)
        )

    # Send the Encrypted Packet
    pcap_writer = PcapWriter("./test.pcap", linktype=105)
    pcap_writer.write(frame2)
    pcap_writer.close()

# Example usage
#
src_mac = "8e:d3:39:d7:40:58"
dst_mac = "78:67:0e:bc:83:ab"
bssid = "01:00:5e:00:00:fb"
iface = "wlan0mon"

tcp_payload = b"Hello, this is a WPA2 encrypted TCP message!"
create_encrypted_packet(tcp_payload, src_mac, dst_mac, bssid, iface)