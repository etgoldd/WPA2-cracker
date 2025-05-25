import hashlib
import sys

def calc_pmk(ssid: bytes, password: bytes) -> bytes:
    pmk = hashlib.pbkdf2_hmac('sha1', password, ssid, 4096, 32)
    return pmk


if __name__ == "__main__":
    if len(sys.argv) <= 2:
        print("Usage: ", sys.argv[0], "<password> <ssid>")
        sys.exit(1)
    password = sys.argv[1]
    ssid = sys.argv[2]
    ssid_bytes = ssid.encode('ascii')
    pmk = calc_pmk(ssid_bytes, password.encode('ascii'))
    print("PMK: ", pmk.hex())
    

