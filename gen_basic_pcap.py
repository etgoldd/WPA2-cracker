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
    Dot11Elt,
)
from scapy.packet import Raw, Packet
from scapy.layers.eap import EAPOL

PCAP_LOC = "assets/template.pcap"

ALICE_IP = "196.162.0.5"
BOB_IP = "196.162.0.9"
ALICE_MAC = "AA:AA:AA:AA:AA:AA"
BOB_MAC = "BB:BB:BB:BB:BB:BB"

ssid = "24:16:1b:ca:e0:c0"
password = "yourPassword"
bssid = "be:09:77:06:31:96"
client_mac = "24:16:1b:ca:e0:c0"
anonce = b"\x00" * 32  # Example ANonce
snonce = b"\x11" * 32  # Example SNonce
mic = b"\x22" * 16  # Example MIC
ptk = b"\x33" * 48  # Example PTK
eapol_load = b"\x02\x00\x8a\x00\x10\x00\x00\x00\x00\x00\x00\x00\x02\x7e\x9e\x4a\x5a\x45\x11\x80\x61\x99\x69\x46\xa2\xcd\xe3\x60\x60\xdb\xd7\xab\x3c\x65\x5e\x3c\x03\x54\xbe\x29\xd5\xa5\x75\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x16\xdd\x14\x00\x0f\xac\x04\x77\xe7\x6a\x18\xbc\x30\x6a\x97\xec\xb8\x2f\xcc\x80\xf0\x50\xad"

MESSAGES = [
    "Hello Bob, how's it going?",
    "I'm doing well, thanks for asking Alice, how about yourself?",
    "I'm doing well too! I want to share this super secret message with you, but this unencrypted channel is not secure, let's move to a WPA2 network.",
    "Sounds good, I'll see you there!",
]


def gen_mic() -> bytes:
    pass


def gen_pcap():
    packets = []
    sender = (ALICE_IP, ALICE_MAC)
    receiver = (BOB_IP, BOB_MAC)
    for message in MESSAGES:
        pkt = (
            Ether(src=sender[1], dst=receiver[1])
            / IP(src=sender[0], dst=receiver[0])
            / UDP(sport=34343, dport=43434)
            / message
        ).build()
        packets.append(pkt)
        sender, receiver = receiver, sender
    # Add eapols
    # Frame 1: AP to Client (ANonce)
    dot11 = Dot11(
        type=2,
        subtype=8,
        addr1=ssid,
        addr2=bssid,
        addr3=bssid,
        FCfield="from-DS",
    )
    qos = Dot11QoS(TID=7)

    # LLC/SNAP headers for EAPOL
    llc = LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(OUI=0x000000, code=0x888E)

    # EAPOL Key frame (simplified, actual handshake values will vary)
    # eapol = EAPOL(version=2, type=3, len=117) / Raw(
    #     load=b"\x02\x00\x8a\x00\x10\x00\x00\x00\x00\x00\x00\x00\x02\x7e\x9e\x4a\x5a\x45\x11\x80\x61\x99\x69\x46\xa2\xcd\xe3\x60\x60\xdb\xd7\xab\x3c\x65\x5e\x3c\x03\x54\xbe\x29\xd6\x75\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x16\xdd\x14\x00\x0f\xac\x04\x77\xe7\x6a\x18\xbc\x30\x6a\x97\xec\xb8\x2f\xf0\x50\xad"
    # )
    key_iv = b"\x00" * 16
    key_rsc = b"\x00" * 8
    key_id = b"\x00" * 8
    key_mic = b"\x00" * 16
    eapol_load = key_iv + key_rsc + key_id + key_mic + ptk
    key_data_length = len(key_id + key_mic + ptk)
    frame1 = dot11 / qos / llc / EAPOL(version=2, type=3) / Raw(load=anonce)
    print(frame1)
    print(frame1.show())
    # # Frame 2: Client to AP (SNonce)
    # frame2 = (
    #     RadioTap()
    #     / Dot11(addr1=bssid, addr2=client_mac, addr3=bssid)
    #     / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
    #     / SNAP(OUI=0, code=0x888E)
    #     / EAPOL(version=1, type=3)
    #     / Raw(load=snonce)
    # )

    # # Frame 3: AP to Client (MIC)
    # frame3 = (
    #     RadioTap()
    #     / Dot11(addr1=client_mac, addr2=bssid, addr3=bssid)
    #     / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
    #     / SNAP(OUI=0, code=0x888E)
    #     / EAPOL(version=1, type=3)
    #     / Raw(load=mic)
    # )

    # # Frame 4: Client to AP (MIC)
    # frame4 = (
    #     RadioTap()
    #     / Dot11(addr1=bssid, addr2=client_mac, addr3=bssid)
    #     / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
    #     / SNAP(OUI=0, code=0x888E)
    #     / EAPOL(version=1, type=3)
    #     / Raw(load=mic)
    # )

    packets = [frame1.build()]  # frame2.build()]
    pcap_writer = PcapWriter(PCAP_LOC, linktype=105)
    pcap_writer.write(frame1)
    pcap_writer.close()


if __name__ == "__main__":
    gen_pcap()
