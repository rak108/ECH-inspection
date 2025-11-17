import csv
import base64
import struct
import os
from collections import defaultdict, OrderedDict

# INPUT_FILE = "../dataset/configs.csv"             # domain,echconfig
# OUTPUT_FILE = "../dataset/ech_config_analysis.csv"    # echconfig, versions, cipher_suites, public_names, domain_count, example_domains

INPUT_DIR = "../dataset/country_wise_ech"
OUTPUT_DIR = "../output/country_wise_ech_analysis"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def _b64fix(s: str) -> str:
    s = s.strip().strip('"').strip("'")
    pad = (-len(s)) % 4
    return s + ("=" * pad)

def _read_u8(b, i):
    if i + 1 > len(b): raise ValueError("u8 out of range")
    return b[i], i + 1

def _read_u16(b, i):
    if i + 2 > len(b): raise ValueError("u16 out of range")
    return struct.unpack_from("!H", b, i)[0], i + 2

def _read_bytes(b, i, n):
    if i + n > len(b): raise ValueError("bytes out of range")
    return b[i:i+n], i + n

def parse_echconfig_list_or_single(b64blob: str):
    """
    Returns a list of parsed ECHConfig entries (could be 1+) from either:
      - ECHConfigList (uint16 len + [ECHConfig...])
      - bare ECHConfig (no list length)
    Each entry is a dict with: version, kem_id, public_name, cipher_suites (list of "kdf-aead" hex strings)
    """
    out = []

    raw = base64.b64decode(_b64fix(b64blob), validate=False)

    def parse_one_config(buf, pos):
        # ECHConfig:
        #   uint16 version
        #   opaque contents<1..2^16-1>
        version, pos = _read_u16(buf, pos)
        cont_len, pos = _read_u16(buf, pos)
        contents, pos = _read_bytes(buf, pos, cont_len)

        c = 0
        # ECHConfigContents:
        #   uint8  config_id
        #   uint16 kem_id
        #   opaque public_key<1..2^16-1>
        #   HpkeSymmetricCipherSuite cipher_suites<2..2^16-2> (pairs of uint16)
        #   uint8  maximum_name_length
        #   opaque public_name<1..255>
        #   Extension extensions<0..2^16-1>

        # config_id
        _, c = _read_u8(contents, c)

        # kem_id
        kem_id, c = _read_u16(contents, c)

        # public_key
        pk_len, c = _read_u16(contents, c)
        _, c = _read_bytes(contents, c, pk_len)

        # cipher_suites
        cs_len, c = _read_u16(contents, c)
        cs_buf, c = _read_bytes(contents, c, cs_len)
        suites = []
        CIPHER_SUITE_MAP = {
            ("0001", "0001"): "HKDF-SHA256 + AES-128-GCM",
            ("0001", "0002"): "HKDF-SHA256 + AES-256-GCM",
            ("0001", "0003"): "HKDF-SHA256 + ChaCha20-Poly1305",
            ("0002", "0001"): "HKDF-SHA384 + AES-128-GCM",
            ("0002", "0002"): "HKDF-SHA384 + AES-256-GCM",
        }

        # --- inside your cipher suite loop ---
        for j in range(0, len(cs_buf), 4):
            if j + 4 <= len(cs_buf):
                kdf, aead = struct.unpack_from("!HH", cs_buf, j)
                kdf_hex, aead_hex = f"{kdf:04x}", f"{aead:04x}"
                suites.append(
                    CIPHER_SUITE_MAP.get((kdf_hex, aead_hex), f"{kdf_hex}-{aead_hex}")
                )

        # maximum_name_length
        _, c = _read_u8(contents, c)

        # public_name
        pn_len, c = _read_u8(contents, c)
        public_name_b, c = _read_bytes(contents, c, pn_len)
        try:
            public_name = public_name_b.decode("utf-8", errors="strict")
        except UnicodeError:
            public_name = public_name_b.decode("utf-8", errors="ignore")

        # extensions (skip)
        if c + 2 <= len(contents):
            ext_len, c = _read_u16(contents, c)
            # ignore body safely if present
            _ = contents[c:c+ext_len]

        return {
            "version": f"0x{version:04x}",
            "kem_id": f"0x{kem_id:04x}",
            "cipher_suites": suites,
            "public_name": public_name
        }, pos

    # Heuristic: detect list vs single
    # ECHConfigList starts with uint16 total_length; then first two bytes AFTER that should be version (0xfe0d today).
    # If raw[0:2] looks like a plausible total_length and raw[2:4] == version, treat as list.
    is_list = False
    if len(raw) >= 6:
        total_len = struct.unpack_from("!H", raw, 0)[0]
        # sanity: total_len fits in remaining buffer and next u16 looks like a version (non-zero)
        if 2 + total_len <= len(raw):
            ver_candidate = struct.unpack_from("!H", raw, 2)[0]
            # Most deployed ECH use 0xfe0d; allow any non-zero to be safe.
            if ver_candidate != 0:
                is_list = True

    try:
        if is_list:
            pos = 0
            list_len, pos = _read_u16(raw, pos)
            end = pos + list_len
            while pos < end:
                entry, pos = parse_one_config(raw, pos)
                out.append(entry)
        else:
            # treat as a single ECHConfig without a list-length prefix
            entry, _ = parse_one_config(raw, 0)
            out.append(entry)
    except Exception:
        # Return empty list on parse failure
        return []

    return out

def analyze_csv(infile, outfile):
    # 1) Read input CSV and group by echconfig (string-equal)
    groups = defaultdict(list)  # ech_b64 -> [domain,...]
    with open(infile, newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            domain = row["domain"].strip()
            ech_b64 = row["echconfig"].strip()
            groups[ech_b64].append(domain)

    print(f"Unique ECH config blobs: {len(groups)}")

    # 2) For each unique echconfig, parse and merge fields across all configs in the list
    rows_out = []
    for ech_b64, domains in groups.items():
        parsed_list = parse_echconfig_list_or_single(ech_b64)

        versions = OrderedDict()
        public_names = OrderedDict()
        cipher_suites = OrderedDict()

        for p in parsed_list:
            versions[p["version"]] = True
            if p.get("public_name"):
                public_names[p["public_name"]] = True
            for cs in p.get("cipher_suites", []):
                cipher_suites[cs] = True

        version_str = "|".join(versions.keys()) if versions else ""
        public_name_str = "|".join(public_names.keys()) if public_names else ""
        cipher_suites_str = "|".join(cipher_suites.keys()) if cipher_suites else ""

        example = ", ".join(domains[:5])

        rows_out.append({
            "echconfig": ech_b64,
            "versions": version_str,
            "cipher_suites": cipher_suites_str,
            "public_names": public_name_str,
            "domain_count": len(domains),
            "example_domains": example
        })

    # 3) Write summary CSV
    with open(outfile, "w", newline="") as f:
        fieldnames = ["echconfig", "versions", "cipher_suites", "public_names", "domain_count", "example_domains"]
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in rows_out:
            w.writerow(row)

    print(f"Saved: {outfile}")

def main():
    csv_files = [f for f in os.listdir(INPUT_DIR) if f.endswith(".csv")]
    failed = []

    for fname in csv_files:
        infile = os.path.join(INPUT_DIR, fname)
        outfile = os.path.join(OUTPUT_DIR, fname.replace(".csv", "_config_analysis.csv"))
        success = analyze_csv(infile, outfile)
        if not success:
            failed.append(fname)

    if failed:
        print("\n[SUMMARY] Files with no valid ECH configs:")
        for f in failed:
            print(" -", f)
    else:
        print("\n[SUMMARY] All files processed successfully.")


if __name__ == "__main__":
    main()
