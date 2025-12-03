#!/usr/bin/env bash

# INPUT: The file with "domain, ECH config" (likely the output of your previous script)
CSV_FILE="retry_configs.csv"
OUT_FILE="domain_asn.csv"
COUNT_FILE="resume_asn.count"

# Ensure output header
if [[ ! -f "$OUT_FILE" ]]; then
  echo "domain,asn_info" > "$OUT_FILE"
fi

# Resume logic
if [[ -f "$COUNT_FILE" ]]; then
  count=$(<"$COUNT_FILE")
else
  count=0
fi
[[ -z "${count//[0-9]/}" ]] || count=0

total=$(( $(wc -l < "$CSV_FILE") - 1 ))
echo "Total rows (excluding header): $total"
echo "Resuming at data row index: $count"

start_line=$((2 + count))

export HOME

process_domain() {
    raw_domain=$1
    
    # 1. Remove quotes (just in case)
    domain=${raw_domain//\"/}
    
    # 2. Remove 'https://' prefix
    domain=${domain#https://}

    # 3. Run the requested command pipeline
    # We check if dig returns an IP first to prevent xargs/whois errors on empty input
    ip=$(dig +short "$domain" | head -n 1)

    if [[ -n "$ip" ]]; then
        # Run the specific pipeline command requested
        # We pipe the IP into the whois command using the logic you provided
        result=$(echo "$ip" | xargs -I {} whois -h whois.cymru.com " -v {}" | awk -F '|' 'NR>1 {print $NF}')
        
        # Trim leading/trailing whitespace from the result (awk output often has spaces)
        result=$(echo "$result" | xargs)

        if [[ -n "$result" ]]; then
             printf "FOUND:%s,\"%s\"\n" "$domain" "$result"
        fi
    fi

    echo "TICK"
}

export -f process_domain

# Parallel Execution
# -j 32: Run 32 jobs in parallel
# -k: Keep order (crucial for resume accuracy)
# --colsep ',': Split CSV line, passing the first column (domain) as {1}
tail -n +"$start_line" "$CSV_FILE" | parallel -j 32 -k --colsep ',' --line-buffer process_domain {1} | {
    
    # Trap Ctrl+C to save progress before exiting
    trap '' INT
    
    while read -r line; do
        if [[ "$line" == "TICK" ]]; then
            count=$((count + 1))
            
            # Save progress every line
            echo "$count" > "$COUNT_FILE"
            
            if [ $((count % 100)) -eq 0 ]; then
                echo "[${count}/${total}] processed..."
            fi
        elif [[ "$line" == FOUND:* ]]; then
            echo "${line#FOUND:}" >> "$OUT_FILE"
        fi
    done
    
    echo "$count" > "$COUNT_FILE"
    echo "Stopped. Final progress saved at row $count."
}