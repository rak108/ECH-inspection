import csv
import subprocess
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

INPUT_DIR = "../dataset/country_wise_ech"  # directory with existing domain,rank,echconfig CSVs
MAX_WORKERS = 50
TIMEOUT = 2


def get_echconfig(domain):
    """
    Runs 'dig +short https <domain>' and extracts the valid uppercase ECHConfigList (Base64).
    Returns None if not found or malformed.
    """
    try:
        result = subprocess.run(
            ["dig", "+short", "https", domain],
            capture_output=True,
            text=True,
            timeout=TIMEOUT
        )
        out = result.stdout.strip()
        if not out:
            return None

        # Use regex to capture ECH base64 cleanly (case-preserving)
        match = re.search(r'ech=([A-Za-z0-9+/=_-]+)', out, re.IGNORECASE)
        if match:
            ech_value = match.group(1)
            # Normalize URL-safe variants
            ech_value = ech_value.replace("-", "+").replace("_", "/")
            # Add proper padding
            pad = (-len(ech_value)) % 4
            ech_value += "=" * pad
            # Clean trailing punctuation
            return ech_value.strip('" ,')
        return None

    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def refresh_ech_for_row(row):
    domain = row["domain"].strip()
    rank = row.get("rank", "")
    new_ech = get_echconfig(domain)
    return {"domain": domain, "rank": rank, "echconfig": new_ech or ""}

def refresh_csv(file_path):
    """Recomputes echconfig for every domain in an existing CSV and overwrites the same file."""
    print(f"[INFO] Refreshing {os.path.basename(file_path)}...")

    with open(file_path, newline="") as infile:
        reader = csv.DictReader(infile)
        rows = list(reader)

    total = len(rows)
    updated_rows = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(refresh_ech_for_row, row) for row in rows]
        for i, future in enumerate(as_completed(futures), 1):
            updated_rows.append(future.result())
            if i % 100 == 0:
                print(f"[{os.path.basename(file_path)}] Updated {i}/{total} domains...")

    # Overwrite same file with refreshed echconfig values
    with open(file_path, "w", newline="") as outfile:
        writer = csv.DictWriter(outfile, fieldnames=["domain", "rank", "echconfig"])
        writer.writeheader()
        writer.writerows(updated_rows)

    print(f"[DONE] Refreshed {total} domains in {os.path.basename(file_path)}")
    return True


def main():
    csv_files = [f for f in os.listdir(INPUT_DIR) if f.endswith(".csv")]
    failed = []

    print(f"[NOTICE] Refreshing ECHConfig values in {len(csv_files)} existing CSV files...\n")

    for filename in csv_files:
        file_path = os.path.join(INPUT_DIR, filename)
        try:
            refresh_csv(file_path)
        except Exception as e:
            print(f"[ERROR] Failed to refresh {filename}: {e}")
            failed.append(filename)

    if failed:
        print("\n[SUMMARY] Some files failed:")
        for f in failed:
            print(" -", f)
    else:
        print("\n[SUMMARY] All files refreshed successfully.")

if __name__ == "__main__":
    main()
