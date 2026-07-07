#!/bin/bash

IFACE="${1:-enp0s20u9}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/out/dns_results.txt"
TMPFILE=$(mktemp)

LOCAL_IP=$(ip -4 addr show "$IFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
OPERATOR_DNS=$(nmcli dev show "$IFACE" 2>/dev/null | grep DNS | head -1 | awk '{print $2}')
[ -z "$OPERATOR_DNS" ] && OPERATOR_DNS=$(grep -E '^nameserver 10\.' /etc/resolv.conf | head -1 | awk '{print $2}')

DNS_SERVERS=("${OPERATOR_DNS}:Operator" "8.8.8.8:Google" "77.88.8.8:Yandex")

TEST_DOMAINS=(ya.ru vk.com mail.ru google.com telegram.org youtube.com github.com twitter.com)

echo "DNS check via $IFACE ($LOCAL_IP)"
echo ""

> "$OUT"
echo "Interface: $IFACE ($LOCAL_IP)" >> "$OUT"
echo "" >> "$OUT"

for dns_entry in "${DNS_SERVERS[@]}"; do
    dns_ip="${dns_entry%%:*}"
    dns_name="${dns_entry##*:}"
    [ -z "$dns_ip" ] && continue

    echo "=== $dns_name ($dns_ip) ===" | tee -a "$OUT"
    printf "%-20s %-20s %-10s\n" "DOMAIN" "IP" "HTTPS" | tee -a "$OUT"

    # Resolve all domains via nmap's dns-brute isn't suitable here,
    # use nmap --resolve-all with specific DNS
    for domain in "${TEST_DOMAINS[@]}"; do
        # Resolve using nmap's built-in resolver with specified DNS
        ip=$(nmap --dns-servers "$dns_ip" -sL "$domain" 2>/dev/null | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)

        if [ -n "$ip" ]; then
            echo "https://$ip" >> "$TMPFILE"
            printf "%-20s %-20s" "$domain" "$ip"
            printf "%-20s %-20s" "$domain" "$ip" >> "$OUT"

            # Quick httpx check for this single IP
            result=$(echo "https://$ip" | httpx-toolkit -silent -status-code -no-color -tls-grab 2>/dev/null | head -1)
            if [ -n "$result" ]; then
                printf " %-10s\n" "OK" | tee -a "$OUT"
            else
                printf " %-10s\n" "BLOCKED" | tee -a "$OUT"
            fi
        else
            printf "%-20s %-20s %-10s\n" "$domain" "TIMEOUT" "-" | tee -a "$OUT"
        fi
    done
    echo "" | tee -a "$OUT"
    > "$TMPFILE"
done

rm -f "$TMPFILE"
echo "Results: $OUT"
