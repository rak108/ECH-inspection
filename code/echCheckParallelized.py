import csv
import subprocess
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

INPUT_FILE = "dataset/top1m_all_unique.csv"
OUTPUT_FILE = "ech_supported.csv"
MAX_WORKERS = 200
TIMEOUT = 2

def extract_domain(origin):
    try:
        parsed = urlparse(origin.strip())
        return parsed.netloc or parsed.path
    except Exception:
        return origin.strip()

def has_ech(domain):
    try:
        result = subprocess.run(
            ["dig", "type65", "+short", domain],
            capture_output=True,
            text=True,
            timeout=TIMEOUT
        )
        return "ech=" in result.stdout.lower()
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False

def check_domain(row):
    origin = row["origin"]
    rank = row.get("rank", "")
    domain = extract_domain(origin)
    ech = has_ech(domain)
    print(domain, ech)
    return (domain, rank, ech)

def main():
    with open(INPUT_FILE, newline='') as infile, open(OUTPUT_FILE, "w", newline='') as outfile:
        reader = csv.DictReader(infile)
        writer = csv.DictWriter(outfile, fieldnames=["domain", "rank"])
        writer.writeheader()

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(check_domain, row) for row in reader]

            for i, future in enumerate(as_completed(futures), 1):
                domain, rank, ech = future.result()
                if ech:
                    writer.writerow({"domain": domain, "rank": rank})
                if i % 1000 == 0:
                    print(f"Processed {i} domains...")

    print(f"\nECH check complete. Results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
