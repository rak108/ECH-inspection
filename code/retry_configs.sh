#!/usr/bin/env bash

CSV_FILE="/home/samy/Documents/8803-EMS/ECH-inspection/dataset/crux_raw/top1m_all_unique.csv"
OUT_FILE="retry_configs.csv"
COUNT_FILE="resume.count"    # stores total processed data rows (header excluded)

# ensure header (idempotent)
if [[ ! -f "$OUT_FILE" ]]; then
  echo "domain,echconfig" > "$OUT_FILE"
fi

if [[ -f "$COUNT_FILE" ]]; then
  count=$(<"$COUNT_FILE")
else
  count=0
fi
# sanity default
[[ -z "${count//[0-9]/}" ]] || count=0


total=$(( $(wc -l < "$CSV_FILE") - 1 ))
echo "Total rows (excluding header): $total"
echo "Resuming at data row index: $count  (CSV line $((count + 2)))"

start_line=$((2 + count))  # header is line 1, so data starts at 2

echo "$start_line"

# skip header
tail -n +"$start_line" "$CSV_FILE" | while IFS=, read -r domain rank; do
    # trim possible quotes/spaces
    count=$((count + 1))
        if [ $((count % 100)) -eq 0 ]; then
        echo "[${count}/${total}] processed..."
    fi

    # echo "Processing: $domain"


    domain=${domain//\"/}

    curl_out=$(LD_LIBRARY_PATH="$HOME/code/openssl" /home/samy/code/curl/src/curl -v --ech "ecl:AEX+DQBBVgAgACCgx++UjkM3TwlEU/Z+Fa9nq8ESXbzIV5L071hBSM3IJgAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=" "${domain}" -m 4 2>&1)
    # echo "$curl_out"

    
    retry_line=$(grep 'retry_configs' <<< "$curl_out")

    retry_cfg=$(sed -n 's/.*retry_configs[[:space:]]\+\([A-Za-z0-9+/=]\+\)[[:space:]]*$/\1/p' <<< "$retry_line")
    retry_cfg=${retry_cfg//$'\n'/}
    retry_cfg=${retry_cfg//$'\r'/}
    # echo "$retry_line"
    # echo "$retry_cfg"


    # # ----- compare command 3 with command 2 -----
    if [ "$retry_cfg" != "" ]; then
       # record domain and config
        printf '%s,"%s"\n' "$domain" "$retry_cfg" >> "$OUT_FILE"
        
    fi

    echo "$count" > "$COUNT_FILE"






done
