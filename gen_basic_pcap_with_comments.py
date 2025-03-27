import Crypto.Cipher.AES as AES
import hmac
import hashlib
import binascii
from scapy.all import *
from scapy.layers.l2 import ARP, Ether, LLC, SNAP
from io import BytesIO
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dot11 import (
    Dot11, Dot11QoS, RadioTap, Dot11CCMP, Dot11Auth, Dot11AssoReq, Dot11AssoResp,
    Dot11WEP, Dot11ReassoReq, Dot11Elt
)
from scapy.packet import Raw, Packet
from scapy.layers.eap import EAPOL
import random
import struct
from typing import Optional, List


def get_key_data(ap_mac: bytes, cl_mac: bytes, anonce: bytes, snonce: bytes) -> bytes:
    """
    Generates the key data used in PTK calculation based on MAC addresses and nonces.

    @param ap_mac: MAC address of the Access Point.
    @param cl_mac: MAC address of the client (e.g., Alice's device).
    @param anonce: AP nonce (random value).
    @param snonce: Client nonce (random value).

    @return: A byte string representing the concatenated sorted MAC and nonce data.
    """
    mac_addresses_pair = b"".join(sorted([ap_mac, cl_mac]))
    nonce_pair = b"".join(sorted([anonce, snonce]))
    return mac_addresses_pair + nonce_pair


def mac_string_to_bytes(mac_string: str) -> bytes:
    """
    Converts a MAC address from string format (e.g., '00:17:FA:65:43:21') to bytes.

    @param mac_string: MAC address as a string.

    @return: MAC address as bytes.
    """
    return binascii.unhexlify(mac_string.replace(":", "", 5))


def construct_aad(frame) -> bytes:
    """
    Constructs the Additional Authentication Data (AAD) used in CCM encryption.

    @param frame: The data frame to extract the AAD from.

    @return: A byte string representing the AAD.
    """
    data = bytes(frame)
    return data[0:2] + data[4:22] + data[30:34]


def encrypt_packet(
    src_mac: str, dst_mac: str, anonce: bytes, snonce: bytes, ssid: str,
    passkey: str, header, payload, faulty_mic: bool = False
):
    """
    Encrypts a data packet using WPA2 CCMP (AES in CCM mode) based on the PTK derived from the PMK.

    @param src_mac: Source MAC address.
    @param dst_mac: Destination MAC address.
    @param anonce: AP's nonce.
    @param snonce: Client's nonce.
    @param ssid: SSID of the WPA2 network.
    @param passkey: WPA2 password (pre-shared key).
    @param header: The packet header.
    @param payload: The data payload to encrypt.
    @param faulty_mic: Whether to simulate a faulty MIC (for testing).

    @return: The encrypted data frame with the MIC.
    """
    header_bytes = bytes(header)
    assert len(header_bytes) >= 34  # Ensure the header is at least 34 bytes long

    # Calculate the PMK (Pairwise Master Key) from the SSID and passkey.
    pmk = calc_pmk(ssid.encode("ascii"), passkey.encode("ascii"))

    # Generate key data from MAC addresses and nonces.
    key_data = get_key_data(
        mac_string_to_bytes(src_mac), mac_string_to_bytes(dst_mac), anonce, snonce
    )

    # Derive the PTK (Pairwise Transient Key) from the PMK and key data.
    ptk = calc_ptk(pmk, key_data)

    # The Temporal Key (TK) is the last 16 bytes of the PTK.
    tk = ptk[32:48]

    # Construct the AAD (Additional Authenticated Data) for the encryption.
    aad = construct_aad(header)

    # Extract the Packet Number (PN) from the CCMP header.
    ccmp_header = header[Dot11CCMP]
    packet_number = b"".join([i.to_bytes(1, "little") for i in [
        ccmp_header.PN0, ccmp_header.PN1, ccmp_header.PN2, ccmp_header.PN3,
        ccmp_header.PN4, ccmp_header.PN5]])

    # Prepare the plaintext and the nonce for AES CCM encryption.
    plaintext = bytes(payload)
    ccm_nonce = struct.pack(">B", 0) + mac_string_to_bytes(header.addr2) + packet_number[::-1]

    # Create the AES CCM cipher and encrypt the packet.
    aes_ccm = AES.new(tk, AES.MODE_CCM, nonce=ccm_nonce, mac_len=8)
    aes_ccm.update(aad)
    ciphertext, mic = aes_ccm.encrypt_and_digest(plaintext)

    # Optionally simulate a faulty MIC.
    if faulty_mic:
        mic = mic[::-1]

    # Replace the CCMP data with the ciphertext and MIC.
    data_frame = header
    data_frame[Dot11CCMP].data = ciphertext + mic
    return data_frame


def calc_mic(ptk: bytes, mic_frame: bytes) -> bytes:
    """
    Calculates the Message Integrity Code (MIC) for a frame using HMAC-SHA1.

    @param ptk: The Pairwise Transient Key (PTK).
    @param mic_frame: The frame data for which the MIC is being calculated.

    @return: The calculated MIC.
    """
    mic = hmac.new(ptk[0:16], mic_frame, "sha1").digest()
    return mic[:-4]  # MIC is 4 bytes less than the full SHA1 output


def calc_ptk(pmk: bytes, key_data: bytes) -> bytes:
    """
    Calculates the Pairwise Transient Key (PTK) using the PMK and key data.

    @param pmk: The Pairwise Master Key (PMK).
    @param key_data: The data used to derive the PTK (MAC addresses and nonces).

    @return: The calculated PTK.
    """
    pke = b"Pairwise key expansion"
    blen = 64  # PTK length is 64 bytes
    i = 0
    ptk = b""

    # Generate the PTK using HMAC-SHA1 and iterating with increasing counter 'i'.
    while len(ptk) < blen:
        hmacsha1 = hmac.new(pmk, pke + b"\x00" + key_data + bytes([i]), hashlib.sha1)
        ptk += hmacsha1.digest()
        i += 1

    return ptk[:blen]


def calc_pmk(ssid: bytes, password: bytes) -> bytes:
    """
    Calculates the Pairwise Master Key (PMK) using PBKDF2 with SHA-1.

    @param ssid: The SSID of the network.
    @param password: The WPA2 password (pre-shared key).

    @return: The calculated PMK.
    """
    pmk = hashlib.pbkdf2_hmac("sha1", password, ssid, 4096, 32)
    return pmk


def gen_header(packet_number: int, cl_mac: str, bssid: str, direction: str):
    """
    Generates the 802.11 header for a data frame.

    @param packet_number: The sequence number of the packet.
    @param cl_mac: The MAC address of the client (sender).
    @param bssid: The MAC address of the access point (AP).
    @param direction: The direction of the frame, either "to-DS" or "from-DS".

    @return: A Scapy Dot11 header object.
    """
    pn = packet_number.to_bytes(6, "little")
    assert direction in ["to-DS", "from-DS"]

    # Set source and destination MAC addresses based on direction.
    src_mac, dst_mac = (cl_mac, bssid) if direction == "to-DS" else (bssid, cl_mac)

    # Return the complete Dot11 header with QoS and CCMP encryption.
    return (
        Dot11(proto=0, addr1=dst_mac, addr2=src_mac, addr3=bssid, SC=16, ID=12288,
              FCfield=f"{direction}+protected", type="Data", subtype="QoS Data")
        / Dot11QoS(A_MSDU_Present=0, Ack_Policy=0, EOSP=0, TID=0, TXOP=0)
        / Dot11CCMP(PN0=pn[0], PN1=pn[1], PN2=pn[2], PN3=pn[3], PN4=pn[4], PN5=pn[5], ext_iv=1)
    )


def gen_eapol_load(
    key_descriptor_type,
    key_info,
    key_length,
    replay_counter,
    anonce,
    key_iv,
    key_rsc,
    key_id,
    key_mic,
    key_data_length,
    key_data,
) -> bytes:
    eapol_load = (
        key_descriptor_type
        + key_info
        + key_length
        + replay_counter
        + anonce
        + key_iv
        + key_rsc
        + key_id
        + key_mic
        + key_data_length
        + key_data
    )
    return eapol_load

def gen_simple_udp_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, message):
    dot11 = Dot11(type=2, addr1=dst_mac, addr2=src_mac, addr3=src_mac)
    llc = LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / SNAP(OUI=0x000000, code=0x0800)
    ip = IP(src=src_ip, dst=dst_ip)
    udp = UDP(sport=src_port, dport=dst_port)
    raw = Raw(load=message)
    packet = dot11 / llc / ip / udp / raw
    return packet

def gen_pcaps(
        group_name: str = "guacamole",
        bssid: str = "00:17:FA:65:43:21",
        ALICE_MAC: str = "00:03:93:12:34:56",
        BOB_MAC: str = "00:1A:2B:00:00:01",
        ALICE_IP: str = "196.162.0.5",
        BOB_IP: str = "196.162.0.9",
        ALICE_PORT: int = 12345,
        BOB_PORT: int = 54321,
        MESSAGES: List[str] = [
            "Hello Bob, how's it going?",
            "I'm doing well, thanks for asking Alice, how about yourself?",
            "I'm doing well too! I want to share this super secret message with you, but this unencrypted channel is not secure, let's move to a WPA2 network.",
            "Sounds good, I'll see you there!",
        ],
        faulty_mic: bool = False,
        anonce: Optional[bytes] = None,
        snonce: Optional[bytes] = None,
        ssid: Optional[str] = None,
        passkey: Optional[str] = None,
        PCAP_LOC: Optional[str] = None,
        flag: Optional[str] = None,
    ) -> Optional[BytesIO]:
    """
    @param group_name: str
        The name of the group or event for which the CTF is being created. Used to generate the SSID and passkey for the WPA2 network, and the flag.
        
    @param bssid: str
        The MAC address of the access point (router) in the WPA2 network. Used to simulate the router for the connection.
        
    @param ALICE_MAC: str
        The MAC address of Alice's device. Used to identify Alice during communication over UDP and the subsequent WPA2 network interaction.
        
    @param BOB_MAC: str
        The MAC address of Bob's device. Used to identify Bob during communication over UDP.
        
    @param ALICE_IP: str
        The IP address of Alice's device. Used during UDP message exchanges between Alice and Bob.
        
    @param BOB_IP: str
        The IP address of Bob's device. Used during UDP message exchanges between Alice and Bob.
        
    @param ALICE_PORT: int
        The port on Alice's device that will be used for sending UDP messages.
        
    @param BOB_PORT: int
        The port on Bob's device that will be used for receiving UDP messages.
        
    @param MESSAGES: List[str]
        A list of messages that Alice and Bob exchange. These messages are sent over an unencrypted UDP channel before the WPA2 connection and are followed by encrypted messages on the WPA2 network.
        
    @param faulty_mic: bool
        A flag indicating whether to simulate a faulty Message Integrity Code (MIC) in the WPA2 handshake. If set to True, the MIC will be tampered with.
        
    @param anonce: Optional[bytes]
        The nonce (random value) sent by the access point (AP) in the WPA2 handshake. If not provided, a random 32-byte value will be generated.
        
    @param snonce: Optional[bytes]
        The nonce (random value) sent by the client (Alice) in the WPA2 handshake. If not provided, a random 32-byte value will be generated.
        
    @param ssid: Optional[str]
        The Service Set Identifier (SSID) for the WPA2 network. If not provided, it will be derived from the `group_name`.
        
    @param passkey: Optional[str]
        The WPA2 network password (pre-shared key). If not provided, it will be derived from the `group_name`.
        
    @param PCAP_LOC: Optional[str]
        The file path where the generated PCAP file will be saved. If None, the PCAP will be returned as bytes.
        
    @param flag: Optional[str]
        The CTF flag to be sent over the encrypted channel after the WPA2 handshake. If not provided, it will be automatically generated from the `group_name`.
        
    @return: Optional[BytesIO]
        If `PCAP_LOC` is provided, the function returns None after saving the PCAP file to the specified location. If `PCAP_LOC` is None, the function returns a `BytesIO` object containing the generated PCAP data.
    """
    if anonce is None:
        anonce = bytes([random.randrange(0, 256) for _ in range(0, 32)])
    if snonce is None:
        snonce = bytes([random.randrange(0, 256) for _ in range(0, 32)])
    if ssid is None:
        ssid = f"{group_name}_wifi"
    if passkey is None:
        passkey = f"{group_name}_super_secret_password"
    if flag is None:
        flag = binascii.b2a_hex(hashlib.sha256(group_name.encode('ascii')).digest())[:32].decode('ascii')
    
    packets = []

    for i, msg in enumerate(MESSAGES):
        src_mac = [ALICE_MAC, BOB_MAC][i % 2]
        dst_mac = [BOB_MAC, ALICE_MAC][i % 2]
        src_ip = [ALICE_IP, BOB_IP][i % 2]
        dst_ip = [BOB_IP, ALICE_IP][i % 2]
        src_port = [ALICE_PORT, BOB_PORT][i % 2]
        dst_port = [BOB_PORT, ALICE_PORT][i % 2]
        packets.append(gen_simple_udp_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, msg))


    # Rassociation Request
    reassocaiton_request = (
        Dot11(
            type=0,
            subtype=2,
            addr1=bssid,
            addr2=ALICE_MAC,
            addr3=bssid,
            FCfield="to-DS",
        )
        / Dot11ReassoReq(cap=0x1111, listen_interval=14)
        / Dot11Elt(ID=0, info=ssid)
        / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
        / Dot11Elt(ID=2, info=bssid)
        / Dot11Elt(
            ID=33,
            len=2,
            info=b"\xf9\x15",
        )  # Supported rates
        / Dot11Elt(ID=36, len=10, info=b"\x24\x04\x34\x04\x64\x0c\x95\x04\xa5\x01")
        / Dot11Elt(
            ID=48,
            len=20,
            info=b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x0c\x00",
        )
        / Dot11Elt(ID=70, len=5, info=b"\x71\x08\x01\x00\x00")
        / Dot11Elt(
            ID=45,
            len=26,
            info=b"\x6f\x00\x1b\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        )
        / Dot11Elt(
            ID=191, len=12, info=b"\x32\x70\x80\x0f\xfe\xff\x00\x00\xfe\xff\x00\x00"
        )
        / Dot11Elt(  # This is super hacky, the ID and length are fake, its just to put in the bytes i want it to
            ID=0xFF,
            len=28,
            info=b"\x23\x01\x08\x08\x00\x00\x80\x44\x30\x02\x00\x1d\x00\x9f\x00\x00\x0c\x00\xfe\xff\xfe\xff\x39\x1c\xc7\x71\x1c\x07",
        )
        / Dot11Elt(ID=127, info=b"\x00" * 7 + b"\x40")
        / Dot11Elt(ID=221, len=11, info=b"\x00\x17\xf2\x0a\x00\x01\x04\x00\x00\x00\x00")
        / Dot11Elt(ID=221, len=5, info=b"\x00\x90\x4c\x04\x07")
        / Dot11Elt(ID=221, len=10, info=b"\x00\x10\x18\x02\x01\x00\x10\x00\x00\x02")
        / Dot11Elt(ID=221, len=7, info=b"\x00\x50\xf2\x02\x00\x01\x00")
    )

    # Add eapols
    # Frame 1: AP to Client (ANonce)
    key_iv = b"\x00" * 16
    key_info = b"\x00\x8a"
    key_length = b"\x00\x10"
    replay_counter = b"\x00" * 7 + b"\x01"
    key_rsc = b"\x00" * 8
    key_id = b"\x00" * 8
    dummy_key_mic = b"\x00" * 16
    key_descriptor_type = b"\x02"
    key_data_length = b"\x00" * 2
    key_data = b"\x00" * 1
    frame1 = (
        Dot11(
            type=2,
            subtype=8,
            addr1=ALICE_MAC,
            addr2=bssid,
            addr3=bssid,
            FCfield="from-DS",
        )
        / Dot11QoS(TID=6)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0x000000, code=0x888E)
        / EAPOL(version=2, type=3)
        / Raw(
            load=gen_eapol_load(
                key_descriptor_type,
                key_info,
                key_length,
                replay_counter,
                anonce,
                key_iv,
                key_rsc,
                key_id,
                b"\x00" * 16, #dummy_key_mic,
                key_data_length,
                key_data,
            )
        )
    )

    key_data2 = get_key_data(mac_string_to_bytes(ALICE_MAC), mac_string_to_bytes(bssid), anonce, snonce)
    
    frame1_mic = b"\x00" * 16

    frame1[Raw].load = gen_eapol_load(
        key_descriptor_type,
        key_info,
        key_length,
        replay_counter,
        anonce,
        key_iv,
        key_rsc,
        key_id,
        frame1_mic,
        key_data_length,
        key_data,
    )

    # Frame 2: Client to AP (SNonce)
    key_data = b"\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x0c\x00"
    key_info = b"\x01\x0a"
    frame2 = (
        Dot11(
            type=2,
            subtype=8,
            addr1=bssid,
            addr2=ALICE_MAC,
            addr3=bssid,
            FCfield="to-DS",
        )
        / Dot11QoS(TID=0, EOSP=1, TXOP=18)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0, code=0x888E)
        / EAPOL(version=2, type=3)
        / Raw(
            load=gen_eapol_load(
                key_descriptor_type,
                key_info,
                key_length,
                replay_counter,
                snonce,
                key_iv,
                key_rsc,
                key_id,
                dummy_key_mic,
                len(key_data).to_bytes(2, "big"),
                key_data,
            )
        )
    )
    
    
    frame2_mic = calc_mic(
        calc_ptk(calc_pmk(ssid.encode("ascii"), passkey.encode("ascii")), key_data2),
        frame2[EAPOL].build(),
    )

    if faulty_mic:
        frame2_mic = frame2_mic[::-1]

    frame2[Raw].load = gen_eapol_load(
        key_descriptor_type,
        key_info,
        key_length,
        replay_counter,
        snonce,
        key_iv,
        key_rsc,
        key_id,
        frame2_mic,
        len(key_data).to_bytes(2, "big"),
        key_data,
    )

    # # Frame 3: AP to Client (MIC)
    key_info = b"\x13\xca"
    key_data = b"\xa0\x14\xaa\x8d\xa8\x3a\xeb\xfb\xb5\x9e\xed\x08\xf8\x9e\x7f\xd3\x37\x39\x7f\xef\x67\x3f\x9d\x41\xa8\x6f\x19\x42\xac\xbb\xe6\xd3\xf2\x6f\x0b\x66\x29\x37\xb6\x91\x9c\x0b\xb8\x38\xef\xfc\xce\x3e\x8b\xf6\xef\xf9\xaa\x08\x6b\x31"
    frame3 = (
        Dot11(
            type=2,
            subtype=8,
            addr1=ALICE_MAC,
            addr2=bssid,
            addr3=bssid,
            FCfield="from-DS",
        )
        / Dot11QoS(TID=6)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0, code=0x888E)
        / EAPOL(version=2, type=3)
        / Raw(
            load=gen_eapol_load(
                key_descriptor_type,
                key_info,
                key_length,
                replay_counter,
                anonce,
                key_iv,
                key_rsc,
                key_id,
                dummy_key_mic,
                len(key_data).to_bytes(2, "big"),
                key_data,
            )
        )
    )
    frame3_mic = calc_mic(
        calc_ptk(calc_pmk(ssid.encode("utf-8"), passkey.encode("utf-8")), key_data2),
        frame3[EAPOL].build(),
    )

    if faulty_mic:
        frame3_mic = frame3_mic[::-1]

    frame3[Raw].load = gen_eapol_load(
        key_descriptor_type,
        key_info,
        key_length,
        replay_counter,
        anonce,
        key_iv,
        key_rsc,
        key_id,
        frame3_mic,
        len(key_data).to_bytes(2, "big"),
        key_data,
    )

    # # Frame 4: Client to AP (MIC)
    key_data = b"\x00" * 0
    key_info = b"\x03\x0a"
    frame4 = (
        Dot11(
            type=2,
            subtype=8,
            addr1=bssid,
            addr2=ALICE_MAC,
            addr3=bssid,
            FCfield="to-DS",
        )
        / Dot11QoS(TID=0, EOSP=1, TXOP=16)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0, code=0x888E)
        / EAPOL(version=2, type=3)
        / Raw(
            load=gen_eapol_load(
                key_descriptor_type,
                key_info,
                key_length,
                replay_counter,
                b"\x00" * 32,
                key_iv,
                key_rsc,
                key_id,
                dummy_key_mic,
                len(key_data).to_bytes(2, "big"),
                key_data,
            )
        )
    )
    frame4_mic = calc_mic(
        calc_ptk(calc_pmk(ssid.encode("utf-8"), passkey.encode("utf-8")), key_data2),
        frame4[EAPOL].build(),
    )

    if faulty_mic:
        frame4_mic = frame4_mic[::-1]

    frame4[Raw].load = gen_eapol_load(
        key_descriptor_type,
        key_info,
        key_length,
        replay_counter,
        b"\x00" * 32,
        key_iv,
        key_rsc,
        key_id,
        frame4_mic,
        len(key_data).to_bytes(2, "big"),
        key_data,
    )

    initial_encrypted_packets = [
        (
            IP(src=ALICE_IP, dst=BOB_IP)
            / UDP(sport=ALICE_PORT, dport=BOB_PORT)
            / Raw(
                load="Hey now that we're over an encrypted channel, can you tell me the flag?"
            ),
            "to-DS"
        ),
        (
            IP(src=BOB_IP, dst=ALICE_IP)
            / UDP(sport=BOB_PORT, dport=ALICE_PORT)
            / Raw(load=f"Sure! The flag is: WPA2CTF{{{flag}}}"),
            "from-DS"
        )
    ]

    packets += [reassocaiton_request, frame1, frame2, frame3, frame4]
    #src_mac, dst_mac = ALICE_MAC, BOB_MAC
    for i, data in enumerate(initial_encrypted_packets):
        _packet, dir = data
        packets.append(
            encrypt_packet(
                ALICE_MAC,
                bssid,
                anonce,
                snonce,
                ssid,
                passkey,
                gen_header(i, ALICE_MAC, bssid, dir),
                _packet.build(),
                faulty_mic
            )
        )

    if PCAP_LOC is None:
        stream = BytesIO()
        pcap_writer = PcapWriter(stream, linktype=127)
        for pkt in packets:
            pcap_writer.write((RadioTap() / pkt).build())
        pcap_writer.close()
        return stream
    else:
        pcap_writer = PcapWriter(PCAP_LOC, linktype=127)
        for pkt in packets:
            pcap_writer.write((RadioTap() / pkt).build())
        pcap_writer.close()
        return None


if __name__ == "__main__":
    if len(sys.argv) not in [3, 4, 5]:
        print("Usage: ", sys.argv[0], "<team name> <pcap filename> [faulty_mic] [flag]")
        exit(1)
    team_name = sys.argv[1]
    filename = sys.argv[2]
    faulty_mic = False
    if len(sys.argv) >= 4:
        faulty_mic = bool(sys.argv[3])
    flag = None
    if len(sys.argv) >= 5:
        flag = sys.argv[3]
    gen_pcaps(team_name, PCAP_LOC=filename, flag=flag, faulty_mic=faulty_mic)
