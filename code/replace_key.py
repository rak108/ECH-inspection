import base64
import struct
import sys
   
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from pyhpke import CipherSuite, KEMKey, KEMId, KDFId, AEADId

public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VuAyEAoMfvlI5DN08JRFP2fhWvZ6vBEl28yFeS9O9YQUjNyCY=\n-----END PUBLIC KEY-----"
private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VuBCIEIMAXvyHjAeXy9x4MXF6rwGbDKw7crgDriFTFXO+XsS1F\n-----END PRIVATE KEY-----"
pkr = KEMKey.from_pem(public_key_pem)
skr = KEMKey.from_pem(private_key_pem)
# print(type(pkr.to_public_bytes()))
# skr.to_private_bytes()
pk = pkr.to_public_bytes()
sk = skr.to_private_bytes()


# def get_keypair():
    
#     # Generate a private key
#     private_key = x25519.X25519PrivateKey.generate()

#     # Derive the public key
#     public_key = private_key.public_key()

#     # Export raw bytes
#     private_bytes = private_key.private_bytes(
#         encoding=serialization.Encoding.Raw,
#         format=serialization.PrivateFormat.Raw,
#         encryption_algorithm=serialization.NoEncryption()
#     )

#     public_bytes = public_key.public_bytes(
#         encoding=serialization.Encoding.Raw,
#         format=serialization.PublicFormat.Raw
#     )

#     return private_bytes, public_bytes

#     # print("Private key (hex):", private_bytes.hex())
#     # print("Public key (hex):", public_bytes.hex())


def replace_key(data):
    # sk,pk = get_keypair()
    # print(type(pk))
    ## FIX
    # sk_pem = (b"-----BEGIN PRIVATE KEY-----\n" + base64.encodebytes(sk) + b"-----END PRIVATE KEY-----\n")

    # with open("new_priv.pem", "wb") as file:
    #     # Write the bytes data to the file 
    #     file.write(sk_pem)

   
    offset = 0
    
    offset+=2
    # Version (2 bytes)
    if len(data) < offset + 2:
        print(data)
        return result
    version = struct.unpack('>H', data[offset:offset+2])[0]
    
    offset+=2

    # Length (2 bytes)
    if len(data) < offset + 2:
        return result
    length = struct.unpack('>H', data[offset:offset+2])[0]
  
    offset += 2
    contents_start = offset
    contents = data[offset:offset+length]
    
    c_offset = 0

    # Contents
    # if len(data) < offset + length:
    #     result['note'] = 'Truncated data'
    #     return result
    
    contents = data[offset:offset+length]
  


    c_offset = 0
    
    pk_start = -1
    # Config ID (1 byte)
    if len(contents) > c_offset:
        # result['config_id'] = contents[c_offset]
        c_offset += 1
    
    # KEM ID (2 bytes)
    if len(contents) >= c_offset + 2:
        kem_id = struct.unpack('>H', contents[c_offset:c_offset+2])[0]
        # result['kem_id'] = f"0x{kem_id:04x}"
        c_offset += 2


    if len(contents) >= c_offset + 2:
        pk_len = struct.unpack('>H', contents[c_offset:c_offset+2])[0]
        # result['public_key_length'] = pk_len
        c_offset += 2
    
        # Public Key data
        if len(contents) >= c_offset + pk_len:
            pk_start = c_offset + offset
            # result['public_key_hex'] = contents[c_offset:c_offset+pk_len].hex()
            c_offset += pk_len


    data_arr = bytearray(data)
    pk_arr = bytearray(pk)
    
    
    data_arr[pk_start:pk_start+pk_len] = pk


    return bytes(data_arr)




def parse_echconfig(data):
    result = {}
    offset = 0
    
    offset+=2
    # Version (2 bytes)
    if len(data) < offset + 2:
        return result
    version = struct.unpack('>H', data[offset:offset+2])[0]
    result['version'] = f"0x{version:04x}"
    offset+=2

    # Length (2 bytes)
    if len(data) < offset + 2:
        return result
    length = struct.unpack('>H', data[offset:offset+2])[0]
    result['length'] = length
    offset += 2

    # Contents
    if len(data) < offset + length:
        result['note'] = 'Truncated data'
        return result
    
    contents = data[offset:offset+length]
    result['contents_hex'] = contents.hex()


    c_offset = 0
    
    # Config ID (1 byte)
    if len(contents) > c_offset:
        result['config_id'] = contents[c_offset]
        c_offset += 1
    
    # KEM ID (2 bytes)
    if len(contents) >= c_offset + 2:
        kem_id = struct.unpack('>H', contents[c_offset:c_offset+2])[0]
        result['kem_id'] = f"0x{kem_id:04x}"
        c_offset += 2


    if len(contents) >= c_offset + 2:
        pk_len = struct.unpack('>H', contents[c_offset:c_offset+2])[0]
        result['public_key_length'] = pk_len
        c_offset += 2
    
        # Public Key data
        if len(contents) >= c_offset + pk_len:
            result['public_key_hex'] = contents[c_offset:c_offset+pk_len].hex()
            c_offset += pk_len



    if len(contents) >= c_offset + 2:
        cs_len = struct.unpack('>H', contents[c_offset:c_offset+2])[0]
        result['cipher_suites_length'] = cs_len
        c_offset += 2
        
        # Parse cipher suites
        if len(contents) >= c_offset + cs_len:
            cipher_suites = []
            cs_data = contents[c_offset:c_offset+cs_len]
            cs_offset = 0
            while cs_offset + 4 <= len(cs_data):
                kdf_id = struct.unpack('>H', cs_data[cs_offset:cs_offset+2])[0]
                aead_id = struct.unpack('>H', cs_data[cs_offset+2:cs_offset+4])[0]
                cipher_suites.append({
                    'kdf_id': f"0x{kdf_id:04x}",
                    'aead_id': f"0x{aead_id:04x}"
                })
                cs_offset += 4
            result['cipher_suites'] = cipher_suites
            c_offset += cs_len

    if len(contents) >= c_offset + 1:
        result['maximum_name_length'] = contents[c_offset]
        c_offset += 1

    if len(contents) >= c_offset + 1:
        pn_len = contents[c_offset]
        result['public_name_length'] = pn_len
        c_offset += 1
        
        # Public Name data
        if len(contents) >= c_offset + pn_len:
            try:
                result['public_name'] = contents[c_offset:c_offset+pn_len].decode('utf-8')
            except:
                result['public_name_hex'] = contents[c_offset:c_offset+pn_len].hex()
            c_offset += pn_len


    if len(contents) >= c_offset + 2:
        ext_len = struct.unpack('>H', contents[c_offset:c_offset+2])[0]
        result['extensions_length'] = ext_len
        c_offset += 2
        
        if ext_len > 0 and len(contents) >= c_offset + ext_len:
            # Parse individual extensions
            extensions = []
            ext_data = contents[c_offset:c_offset+ext_len]
            ext_offset = 0
            while ext_offset + 4 <= len(ext_data):
                # Extension type (2 bytes)
                ext_type = struct.unpack('>H', ext_data[ext_offset:ext_offset+2])[0]
                ext_offset += 2
                # Extension data length (2 bytes)
                ext_data_len = struct.unpack('>H', ext_data[ext_offset:ext_offset+2])[0]
                ext_offset += 2
                # Extension data
                if ext_offset + ext_data_len <= len(ext_data):
                    extensions.append({
                        'type': f"0x{ext_type:04x}",
                        'data_length': ext_data_len,
                        'data_hex': ext_data[ext_offset:ext_offset+ext_data_len].hex()
                    })
                    ext_offset += ext_data_len
                else:
                    break
            if extensions:
                result['extensions'] = extensions
            c_offset += ext_len

    return result


def print_echconfig(parsed):
    """Pretty print parsed ECHConfig"""
    print("=" * 60)
    print("ECHConfig Parsed Data")
    print("=" * 60)
    
    for key, value in parsed.items():
        if key == 'cipher_suites':
            print(f"\nCipher Suites:")
            for i, cs in enumerate(value):
                print(f"  Suite {i + 1}:")
                print(f"    KDF ID:  {cs['kdf_id']}")
                print(f"    AEAD ID: {cs['aead_id']}")
        elif key in ['contents_hex', 'public_key_hex', 'extensions_hex']:
            print(f"\n{key.replace('_', ' ').title()}:")
            # Print hex in chunks of 64 chars
            hex_str = str(value)
            for i in range(0, len(hex_str), 64):
                print(f"  {hex_str[i:i+64]}")
        else:
            print(f"{key.replace('_', ' ').title()}: {value}")
    
    print("=" * 60)
# print("Enter ECHConfig in base64 (press Enter when done):")
# b64_input = input().strip()
b64_input = sys.argv[1].strip()
echconfig_bytes = base64.b64decode(b64_input)

# print(f"Raw hex: {echconfig_bytes.hex()}\n")

parsed = parse_echconfig(echconfig_bytes)
        
# Print results
# print_echconfig(parsed)
        
# print("################################NEW KEY ################################")

new_conf = replace_key(echconfig_bytes)

new_parsed = parse_echconfig(new_conf)

# print_echconfig(new_parsed)



config_64 = base64.b64encode(new_conf)
print(config_64.decode())