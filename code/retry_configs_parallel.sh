#!/usr/bin/env bash

CSV_FILE="/home/samy/Documents/8803-EMS/ECH-inspection/dataset/crux_raw/top1m_all_unique.csv"
OUT_FILE="retry_configs.csv"
COUNT_FILE="resume.count"

if [[ ! -f "$OUT_FILE" ]]; then
  echo "domain,echconfig" > "$OUT_FILE"
fi

if [[ -f "$COUNT_FILE" ]]; then
  count=$(<"$COUNT_FILE")
else
  count=0
fi

[[ -z "${count//[0-9]/}" ]] || count=0

total=$(( $(wc -l < "$CSV_FILE") - 1 ))
echo "Total rows (excluding header): $total"
echo "Resuming at data row index: $count  (CSV line $((count + 2)))"

start_line=$((2 + count))

export HOME LD_LIBRARY_PATH

check_domain() {
    domain=$1
    domain=${domain//\"/}

    curl_out=$(LD_LIBRARY_PATH="$HOME/code/openssl" /home/samy/code/curl/src/curl -v --ech "ecl:AEX+DQBBVgAgACCgx++UjkM3TwlEU/Z+Fa9nq8ESXbzIV5L071hBSM3IJgAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=" "${domain}" -m 4 2>&1)
    
    retry_line=$(grep 'retry_configs' <<< "$curl_out")

    retry_cfg=$(sed -n 's/.*retry_configs[[:space:]]\+\([A-Za-z0-9+/=]\+\)[[:space:]]*$/\1/p' <<< "$retry_line")
    retry_cfg=${retry_cfg//$'\n'/}
    retry_cfg=${retry_cfg//$'\r'/}

    if [ "$retry_cfg" != "" ]; then
        printf "FOUND:%s,\"%s\"\n" "$domain" "$retry_cfg"
    fi
    echo "TICK"
}

export -f check_domain

tail -n +"$start_line" "$CSV_FILE" | parallel -j 100 -k --colsep ',' --line-buffer check_domain {1} | {
    
    trap '' INT
    
    while read -r line; do
        if [[ "$line" == "TICK" ]]; then
            count=$((count + 1))
            
            # Saves progress to disk on every single entry
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