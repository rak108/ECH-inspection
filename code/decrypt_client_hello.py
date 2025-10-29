import pyshark
import base64

# from tls_parser import TLSParser
# from pyhpke import KEM, KDF, AEAD, CipherSuite
# from pyhpke import setup_base_r
# from cryptography.hazmat.primitives import serialization
from pyhpke import CipherSuite, KEMKey, KEMId, KDFId, AEADId

public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VuAyEAoMfvlI5DN08JRFP2fhWvZ6vBEl28yFeS9O9YQUjNyCY=\n-----END PUBLIC KEY-----"
private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VuBCIEIMAXvyHjAeXy9x4MXF6rwGbDKw7crgDriFTFXO+XsS1F\n-----END PRIVATE KEY-----"

config = "AEX+DQBBeAAgACCgx++UjkM3TwlEU/Z+Fa9nq8ESXbzIV5L071hBSM3IJgAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="
echconfig_bytes = base64.b64decode(config)
info = b"tls ech" + b"\x00" + echconfig_bytes[2:]  # ech_config_bytes = serialized ECHConfig
# print(info)

def decrypt_client_hello(aaad, enc,payload ):
    print(len(payload))
    print(payload)
    print(enc)
    print(len(enc))

    skr = KEMKey.from_pem(private_key_pem)
    suite = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM)
    print(f"\nInfo parameter: {info.hex()}")
    recipient = suite.create_recipient_context(enc, skr, info=info)
    pt = recipient.open(payload,aad=aaad)
    hexdump(pt)
    return pt


def get_aad(client_hello_packet):
    pass

def print_payload(client_hello_packet):
    tls_layer = pkt.tls
    print(getattr(tls_layer, "ech_enc"))
    print(getattr(tls_layer, "ech_payload"))


def hexdump(data: bytes, width: int = 16):
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        ascii_bytes = "".join((chr(b) if 32 <= b <= 126 else ".") for b in chunk)
        print(f"{i:08x}: {hex_bytes:<{width*3}}  {ascii_bytes}")



def parse_ech_from_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="tls.handshake.type == 1")  # ClientHello

    pkt = cap[0]
    tls_layer = pkt.tls
    print(getattr(tls_layer, "ech_enc"))
    print(getattr(tls_layer, "ech_payload"))
    # for pkt in cap:
    #     try:
    #         tls_layer = pkt.tls
    #         for field in tls_layer.field_names:
    #             # print(field)
    #             # if "ech" in field:
    #             #     # print(field)
    #             if "tls.handshake.extensions_type" in field:
    #                 if getattr(tls_layer, field) == "0xfe0d":  # ECH extension
    #                     enc = getattr(tls_layer, "tls.handshake.extensions_ech.enc", None)
    #                     payload = getattr(tls_layer, "tls.handshake.extensions_ech.payload", None)
    #                     print("🔐 Encrypted Client Hello:")
    #                     print(f"enc: {enc}")
    #                     print(f"payload: {payload}")
    #                     return pkt
    #     except AttributeError:
    #         continue
    # print("No ECH found.")
    return None

# tls_pkt = parse_ech_from_pcap("client_hello_ECH.pcap")




# print_payload(aad)

pcap_file = "./pcaps/mada_test_client_hello_second.pcap"
cap = pyshark.FileCapture(pcap_file, display_filter="tls.handshake.type == 1",  use_json=True,include_raw=True)  # ClientHello
pkt = cap[0]

offset = 81 #--> 0303

### FIrst success##
# payload_len = 399
# enc_offset = 1696
# payload_offset = 1730

payload_len = 175
enc_offset = 0x1cf
payload_offset = 0x1f1

raw_pkt = bytearray(pkt.get_raw_packet())
raw_pkt = raw_pkt[offset:]
# hexdump(raw_pkt)
print(len(raw_pkt))
aad_pkt = raw_pkt.copy()

#payload starts at 0x6c2
zeroes = bytearray(payload_len)
aad_pkt[payload_offset-offset:payload_offset-offset+payload_len] = zeroes
print(len(aad_pkt))
# hexdump(aad_pkt)
print(f"Zeroed region: {aad_pkt[payload_offset-offset:payload_offset-offset+16].hex()}")
print(f"AAD starts with (first 8 bytes): {aad_pkt[:8].hex()}")
# private_pem =-1
# with open("new_priv.pem", "rb") as f:
#     private_pem = f.read()

# cap = pyshark.FileCapture(pcap_file, display_filter="tls.handshake.type == 1")  # ClientHello
# pkt = cap[0]
# tls_layer = pkt.tls
# print(getattr(tls_layer, "ech_enc"))
# print(getattr(tls_layer, "ech_payload"))

# enc = getattr(tls_layer)

enc = raw_pkt[enc_offset-offset: enc_offset -offset +32]
payload = raw_pkt[payload_offset-offset:payload_offset-offset+payload_len] # oayload starts at 0x6c2
decrypt_client_hello(aad_pkt,bytes(enc),bytes(payload))


#notes
## the first and second client hellos decrypted  with the injected key