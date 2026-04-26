#!/bin/bash

IFACE="enp0s20u5"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/out/drop_analysis.txt"

WL_IP="77.88.55.242"    # ya.ru
NW_IP="149.154.167.99"  # telegram

echo "Drop analysis via $IFACE"
echo ""

> "$OUT"
echo "Interface: $IFACE" >> "$OUT"
echo "Whitelist IP: $WL_IP" >> "$OUT"
echo "Non-whitelist IP: $NW_IP" >> "$OUT"
echo "" >> "$OUT"

echo "=== SYN Scan (-sS) ===" | tee -a "$OUT"
echo "WL:" | tee -a "$OUT"
sudo nmap -sS -p443 -e "$IFACE" --reason -Pn "$WL_IP" 2>/dev/null | grep -E "443|Host" | tee -a "$OUT"
echo "NW:" | tee -a "$OUT"
sudo nmap -sS -p443 -e "$IFACE" --reason -Pn "$NW_IP" 2>/dev/null | grep -E "443|Host" | tee -a "$OUT"
echo "" | tee -a "$OUT"

echo "=== ACK Scan (-sA) ===" | tee -a "$OUT"
echo "WL:" | tee -a "$OUT"
sudo nmap -sA -p443 -e "$IFACE" --reason -Pn "$WL_IP" 2>/dev/null | grep -E "443|Host" | tee -a "$OUT"
echo "NW:" | tee -a "$OUT"
sudo nmap -sA -p443 -e "$IFACE" --reason -Pn "$NW_IP" 2>/dev/null | grep -E "443|Host" | tee -a "$OUT"
echo "" | tee -a "$OUT"

echo "=== FIN Scan (-sF) ===" | tee -a "$OUT"
echo "WL:" | tee -a "$OUT"
sudo nmap -sF -p443 -e "$IFACE" --reason -Pn "$WL_IP" 2>/dev/null | grep -E "443|Host" | tee -a "$OUT"
echo "NW:" | tee -a "$OUT"
sudo nmap -sF -p443 -e "$IFACE" --reason -Pn "$NW_IP" 2>/dev/null | grep -E "443|Host" | tee -a "$OUT"
echo "" | tee -a "$OUT"

echo "=== NULL Scan (-sN) ===" | tee -a "$OUT"
echo "WL:" | tee -a "$OUT"
sudo nmap -sN -p443 -e "$IFACE" --reason -Pn "$WL_IP" 2>/dev/null | grep -E "443|Host" | tee -a "$OUT"
echo "NW:" | tee -a "$OUT"
sudo nmap -sN -p443 -e "$IFACE" --reason -Pn "$NW_IP" 2>/dev/null | grep -E "443|Host" | tee -a "$OUT"
echo "" | tee -a "$OUT"

echo "=== Timing (hping3) ===" | tee -a "$OUT"
echo "WL SYN timing:" | tee -a "$OUT"
sudo timeout 5 hping3 -S -p 443 -c 3 -I "$IFACE" "$WL_IP" 2>&1 | grep -E "rtt|flags" | tee -a "$OUT"
echo "NW SYN timing:" | tee -a "$OUT"
sudo timeout 5 hping3 -S -p 443 -c 3 -I "$IFACE" "$NW_IP" 2>&1 | grep -E "rtt|flags|timeout" | tee -a "$OUT"
echo "" | tee -a "$OUT"

echo "=== ICMP check ===" | tee -a "$OUT"
echo "WL:" | tee -a "$OUT"
ping -c 2 -W 2 -I "$IFACE" "$WL_IP" 2>&1 | tail -3 | tee -a "$OUT"
echo "NW:" | tee -a "$OUT"
ping -c 2 -W 2 -I "$IFACE" "$NW_IP" 2>&1 | tail -3 | tee -a "$OUT"

echo ""
echo "Results: $OUT"
