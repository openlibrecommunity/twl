#!/bin/bash

IFACE="wlan0"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/out/dns_results.txt"

DNS_SERVERS=(
    "8.8.8.8:Google"
    "8.8.4.4:Google2"
    "1.1.1.1:Cloudflare"
    "1.0.0.1:Cloudflare2"
    "9.9.9.9:Quad9"
    "208.67.222.222:OpenDNS"
    "77.88.8.8:Yandex"
    "77.88.8.1:Yandex2"
    "77.88.8.88:YandexSafe"
    "94.140.14.14:AdGuard"
    "94.140.15.15:AdGuard2"
    "76.76.2.0:ControlD"
    "185.228.168.9:CleanBrowsing"
)

TEST_DOMAINS=(
    "ya.ru"
    "google.com"
    "telegram.org"
    "youtube.com"
    "zhuvpn.online"
    "github.com"
    "vk.com"
    "mail.ru"
)

LOCAL_IP=$(ip -4 addr show "$IFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

echo "DNS check via $IFACE ($LOCAL_IP)"
echo ""

> "$OUT"

for dns_entry in "${DNS_SERVERS[@]}"; do
    dns_ip="${dns_entry%%:*}"
    dns_name="${dns_entry##*:}"

    printf "%-15s " "$dns_name"

    if timeout 2 bash -c "echo >/dev/tcp/$dns_ip/53" 2>/dev/null; then
        echo -n "OPEN  "
        echo "$dns_name ($dns_ip): OPEN" >> "$OUT"

        ok=0
        fail=0
        for domain in "${TEST_DOMAINS[@]}"; do
            result=$(timeout 2 dig +short @"$dns_ip" "$domain" -b "$LOCAL_IP" 2>/dev/null | head -1)
            if [ -n "$result" ]; then
                ((ok++))
                echo "  $domain: $result" >> "$OUT"
            else
                ((fail++))
                echo "  $domain: FAIL" >> "$OUT"
            fi
        done
        echo "$ok/${#TEST_DOMAINS[@]} resolved"
    else
        echo "BLOCKED"
        echo "$dns_name ($dns_ip): BLOCKED" >> "$OUT"
    fi
done

echo ""
echo "Results: $OUT"
