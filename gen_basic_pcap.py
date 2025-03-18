from scapy.all import *
from scapy.layers.l2 import ARP, Ether, LLC, SNAP

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dot11 import (
    Dot11,
    Dot11QoS,
    RadioTap,
    Dot11CCMP,
    Dot11Auth,
    Dot11AssoReq,
    Dot11AssoResp,
    Dot11WEP,
    Dot11ReassoReq,
    Dot11Elt,
)
from scapy.packet import Raw, Packet
from scapy.layers.eap import EAPOL

PCAP_LOC = "assets/template.pcap"

ALICE_IP = "196.162.0.5"
BOB_IP = "196.162.0.9"
ALICE_MAC = "AA:AA:AA:AA:AA:AA"
BOB_MAC = "BB:BB:BB:BB:BB:BB"

bssid = "be:09:77:06:31:96"
client_mac = "24:16:1b:ca:e0:c0"
anonce = b"\xaa" * 32  # Example ANonce
snonce = b"\x11" * 32  # Example SNonce
ptk = b"\x33" * 48  # Example PTK
eapol_load = b"\x02\x00\x8a\x00\x10\x00\x00\x00\x00\x00\x00\x00\x02\x7e\x9e\x4a\x5a\x45\x11\x80\x61\x99\x69\x46\xa2\xcd\xe3\x60\x60\xdb\xd7\xab\x3c\x65\x5e\x3c\x03\x54\xbe\x29\xd5\xa5\x75\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x16\xdd\x14\x00\x0f\xac\x04\x77\xe7\x6a\x18\xbc\x30\x6a\x97\xec\xb8\x2f\xcc\x80\xf0\x50\xad"

MESSAGES = [
    "Hello Bob, how's it going?",
    "I'm doing well, thanks for asking Alice, how about yourself?",
    "I'm doing well too! I want to share this super secret message with you, but this unencrypted channel is not secure, let's move to a WPA2 network.",
    "Sounds good, I'll see you there!",
]


def gen_mic() -> bytes:
    return b"\xff" * 16


# header is of type Dot11() / Dot11QoS()
def encrypt_packet(
    anonce, snonce, src_mac, dst_mac, ssid, passkey, data, header
) -> Packet:
    pass


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


def gen_pcaps(group_name):
    ssid = f"{group_name}_wifi"
    passkey = math.pow(hash(f"{group_name}_password"), 2, 10**8)
    flag = hex(hash(group_name))[:16]
    packets = []

    # Rassociation Request
    reassocaiton_request = (
        Dot11(
            type=0,
            subtype=2,
            addr1=bssid,
            addr2=client_mac,
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
    key_mic = b"\xbb" * 16
    key_descriptor_type = b"\x02"
    key_data_length = b"\x00" * 2
    key_data = b"\x00" * 1
    frame1 = (
        Dot11(
            type=2, subtype=8, addr1=ssid, addr2=bssid, addr3=bssid, FCfield="from-DS"
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
                key_mic,
                key_data_length,
                key_data,
            )
        )
    )
    # Frame 2: Client to AP (SNonce)
    key_data = b"\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x0c\x00"
    key_info = b"\x01\x0a"
    frame2 = (
        Dot11(type=2, subtype=8, addr1=bssid, addr2=ssid, addr3=bssid, FCfield="to-DS")
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
                gen_mic(),
                len(key_data).to_bytes(2, "big"),
                key_data,
            )
        )
    )

    # # Frame 3: AP to Client (MIC)
    key_info = b"\x13\xca"
    key_data = b"\xa0\x14\xaa\x8d\xa8\x3a\xeb\xfb\xb5\x9e\xed\x08\xf8\x9e\x7f\xd3\x37\x39\x7f\xef\x67\x3f\x9d\x41\xa8\x6f\x19\x42\xac\xbb\xe6\xd3\xf2\x6f\x0b\x66\x29\x37\xb6\x91\x9c\x0b\xb8\x38\xef\xfc\xce\x3e\x8b\xf6\xef\xf9\xaa\x08\x6b\x31"
    frame3 = (
        Dot11(
            type=2, subtype=8, addr1=ssid, addr2=bssid, addr3=bssid, FCfield="from-DS"
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
                gen_mic(),
                len(key_data).to_bytes(2, "big"),
                key_data,
            )
        )
    )

    # # Frame 4: Client to AP (MIC)
    key_data = b"\x00" * 0
    key_info = b"\x03\x0a"
    frame4 = (
        Dot11(type=2, subtype=8, addr1=bssid, addr2=ssid, addr3=bssid, FCfield="to-DS")
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
                gen_mic(),
                len(key_data).to_bytes(2, "big"),
                key_data,
            )
        )
    )

    initial_encrypted_packets = [
        Ether(src=ALICE_MAC, dst=BOB_MAC)
        / IP(src=ALICE_IP, dst=BOB_IP)
        / UDP(sport=12345, dport=54321)
        / Raw(
            load="Hey now that we're over an encrypted channel, can you tell me the flag?"
        ),
        Ether(src=BOB_MAC, dst=ALICE_MAC)
        / IP(src=BOB_IP, dst=ALICE_IP)
        / UDP(sport=54321, dport=12345)
        / Raw(load=f"Sure! The flag is: WPA2CTF\{{{flag}\}}"),
    ]

    packets += [reassocaiton_request, frame1, frame2, frame3, frame4]
    packets += [
        encrypt_packet(
            anonce,
            snonce,
            ALICE_MAC,
            BOB_MAC,
            ssid,
            passkey,
            _packet.build(),
            _packet[Dot11],
        )
        for _packet in initial_encrypted_packets
    ]
    pcap_writer = PcapWriter(PCAP_LOC, linktype=105)
    for pkt in packets:
        pcap_writer.write(pkt.build())
    pcap_writer.close()


if __name__ == "__main__":
    gen_pcap()
