import base64
import struct
import sys


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
print("Enter ECHConfig in base64 (press Enter when done):")
b64_input = input().strip()
echconfig_bytes = base64.b64decode(b64_input)

print(f"Raw hex: {echconfig_bytes.hex()}\n")

parsed = parse_echconfig(echconfig_bytes)
        
# Print results
print_echconfig(parsed)
