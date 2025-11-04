#!/usr/bin/env bash

CSV_FILE="/home/samy/Documents/8803-EMS/ECH-inspection/dataset/ech_supported_top1m.csv"
OUT_FILE="configs.csv"
NOT_EQUAL_FILE="not_equal_configs.txt"
echo "domain,echconfig" > "$OUT_FILE"

count=0
# skip header
tail -n +2 "$CSV_FILE" | while IFS=, read -r domain rank; do
    # trim possible quotes/spaces
    count=$((count + 1))
        if [ $((count % 100)) -eq 0 ]; then
        echo "[${count}/${total}] processed..."
    fi

    domain=${domain//\"/}
    # rank=${rank//\"/}

    # echo "Processing: $domain"dig 

    # ----- command 1 -----
    # replace this with your actual command
    dig_output=$(dig @1.1.1.1 +short HTTPS "$domain")

    # echo "$dig_output"
    real_config=$(awk '/ech=/{sub(/.*ech=/,"");sub(/[[:space:]].*/,"");print;exit}' <<< "$dig_output")
    # echo "$real_config"
    printf '%s,"%s"\n' "$domain" "$real_config" >> "$OUT_FILE"
    if [ -z "$real_config" ]; then
        # nothing to do for this domain
        continue
    fi

    # # ----- command 2 -----
    # cmd2_output=$(COMMAND_2_HERE "$domain")
    mod_config=$(python3 /home/samy/Documents/8803-EMS/ECH-inspection/code/replace_key.py "$real_config") 
    # echo "$mod_config"


    

    # # ----- command 3 -----
    # cmd3_output=$(COMMAND_3_HERE "$domain")
    curl_out=$(LD_LIBRARY_PATH="$HOME/code/openssl" /home/samy/code/curl/src/curl -v --ech "ecl:${mod_config}" "https://${domain}" 2>&1)
    # echo "$curl_out"

    retry_line=$(grep 'retry_configs' <<< "$curl_out")
    retry_cfg=$(sed -n 's/.*retry_configs[[:space:]]\+\([A-Za-z0-9+/=]\+\)[[:space:]]*$/\1/p' <<< "$retry_line")
    retry_cfg=${retry_cfg//$'\n'/}
    retry_cfg=${retry_cfg//$'\r'/}
    # echo "$retry_line"
    
    
    # echo "$retry_cfg"



    # # ----- compare command 3 with command 2 -----
    if [ "$real_config" != "$retry_cfg" ]; then
       echo "$domain" >> "$NOT_EQUAL_FILE"
        
    fi


    # echo
done

