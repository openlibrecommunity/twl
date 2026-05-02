#!/bin/bash

IFACE="enp0s20u1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/out/dns_results.txt"

LOCAL_IP=$(ip -4 addr show "$IFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
OPERATOR_DNS=$(nmcli dev show "$IFACE" 2>/dev/null | grep DNS | head -1 | awk '{print $2}')

if [ -z "$OPERATOR_DNS" ]; then
    OPERATOR_DNS=$(grep nameserver /etc/resolv.conf | grep -E '^nameserver 10\.' | head -1 | awk '{print $2}')
fi

DNS_SERVERS=(
    "$OPERATOR_DNS:Operator"
    "8.8.8.8:Google"
    "77.88.8.8:Yandex"
)

TEST_DOMAINS=(
    "ya.ru"
    "vk.com"
    "mail.ru"
    "google.com"
    "telegram.org"
    "youtube.com"
    "github.com"
    "twitter.com"
)

echo "DNS check via $IFACE ($LOCAL_IP)"
echo ""

> "$OUT"
echo "Interface: $IFACE ($LOCAL_IP)" >> "$OUT"
echo "" >> "$OUT"

for dns_entry in "${DNS_SERVERS[@]}"; do
    dns_ip="${dns_entry%%:*}"
    dns_name="${dns_entry##*:}"

    [ -z "$dns_ip" ] && continue

    echo " $dns_name ($dns_ip) "
    echo " $dns_name ($dns_ip) " >> "$OUT"
    printf "%-20s %-20s %-10s\n" "DOMAIN" "IP" "TCP:443"
    echo "" >> "$OUT"

    for domain in "${TEST_DOMAINS[@]}"; do
        ip=$(dig @"$dns_ip" "$domain" +short -b "$LOCAL_IP" +time=2 2>/dev/null | grep -E '^[0-9]+\.' | head -1)

        if [ -n "$ip" ]; then
            tcp_ok=$(curl --interface "$IFACE" -s -o /dev/null -w "%{http_code}" --connect-timeout 2 "https://$ip" -k 2>/dev/null)
            if [ "$tcp_ok" != "000" ]; then
                tcp_status="OK"
            else
                tcp_status="BLOCKED"
            fi
            printf "%-20s %-20s %-10s\n" "$domain" "$ip" "$tcp_status"
            echo "$domain $ip $tcp_status" >> "$OUT"
        else
            printf "%-20s %-20s %-10s\n" "$domain" "TIMEOUT" "-"
            echo "$domain TIMEOUT -" >> "$OUT"
        fi
    done
    echo ""
    echo "" >> "$OUT"
done

echo "Results: $OUT"
