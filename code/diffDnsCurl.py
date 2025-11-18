import csv
from urllib.parse import urlparse

FILE_A = "../dataset/retry_configs.csv"
FILE_B = "../dataset/configs.csv"
OUTPUT = "diff_a_minus_b.csv"

def extract_domain(s):
    s = s.strip()
    parsed = urlparse(s)
    return parsed.netloc or parsed.path

def load_domains_normalized(path):
    domains = set()
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = extract_domain(row["domain"])
            domains.add(domain)
    return domains

def load_rows_with_normalized(path):
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            norm = extract_domain(row["domain"])
            rows.append({
                "original_domain": row["domain"].strip(),
                "normalized": norm,
                "echconfig": row["echconfig"].strip(),
            })
    return rows

def main():

    domains_a_norm = load_domains_normalized(FILE_A)
    domains_b_norm = load_domains_normalized(FILE_B)
    rows_a = load_rows_with_normalized(FILE_A)

    diff_norm = domains_a_norm - domains_b_norm

    print(f"Normalized domains in A: {len(domains_a_norm)}")
    print(f"Normalized domains in B: {len(domains_b_norm)}")
    print(f"Domains only in A (normalized): {len(diff_norm)}")

    with open(OUTPUT, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "echconfig"])
        writer.writeheader()

        for row in rows_a:
            if row["normalized"] in diff_norm:
                writer.writerow({
                    "domain": row["original_domain"],
                    "echconfig": row["echconfig"]
                })

    print(f"Saved output to {OUTPUT}")

if __name__ == "__main__":
    main()