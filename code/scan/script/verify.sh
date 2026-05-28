#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"
VERIFY_DIR="$BASE_DIR/out/verify"

IFACE="${1:-enp0s20u1}"
INPUT="$VERIFY_DIR/input.txt"
NMAP_XML="$VERIFY_DIR/nmap.xml"
NMAP_OPEN="$VERIFY_DIR/nmap_open.txt"
HTTPX_OUT="$VERIFY_DIR/httpx.json"
VERIFIED="$VERIFY_DIR/verified.txt"

if [ ! -f "$INPUT" ]; then
    echo "Error: $INPUT not found"
    echo "Run dedupe.sh first"
    exit 1
fi

IP_COUNT=$(wc -l < "$INPUT")
echo "=== Nmap + httpx Verification ==="
echo "Interface: $IFACE"
echo "Input: $INPUT ($IP_COUNT IPs)"
echo ""

# Step 1: nmap SYN scan, output XML for reliable parsing
echo "[1/2] Nmap SYN scan..."
sudo nmap -sS -p443 -Pn -n \
    -e "$IFACE" \
    --min-rate 500 --max-rate 1000 \
    --max-retries 3 \
    --host-timeout 20s \
    -iL "$INPUT" \
    -oX "$NMAP_XML"

# Parse open ports from XML (no awk hacks)
grep -oP 'addr="\K[0-9.]+(?=".*state="open")' "$NMAP_XML" > "$NMAP_OPEN" 2>/dev/null || \
    xmlstarlet sel -t -m '//host[ports/port/state[@state="open"]]' -v 'address[@addrtype="ipv4"]/@addr' -n "$NMAP_XML" > "$NMAP_OPEN" 2>/dev/null || \
    grep -B5 'state="open"' "$NMAP_XML" | grep -oP 'addr="\K[0-9.]+' | sort -u > "$NMAP_OPEN"

NMAP_COUNT=$(wc -l < "$NMAP_OPEN")
echo "  Nmap open: $NMAP_COUNT"

# Step 2: httpx-toolkit verifies actual HTTPS response
echo "[2/2] httpx-toolkit HTTPS probe..."
httpx-toolkit -l "$NMAP_OPEN" -p 443 -tls-grab -status-code -no-color -silent \
    -o "$HTTPX_OUT" -json 2>/dev/null

# Extract IPs that responded with any HTTP status
jq -r 'select(.status_code != null) | .input' "$HTTPX_OUT" | sort -u > "$VERIFIED"

VERIFIED_COUNT=$(wc -l < "$VERIFIED")
DROPPED=$((IP_COUNT - VERIFIED_COUNT))

echo ""
echo "=== Results ==="
echo "Input:      $IP_COUNT"
echo "Nmap open:  $NMAP_COUNT"
echo "HTTP alive: $VERIFIED_COUNT"
echo "Dropped:    $DROPPED"
echo "Output:     $VERIFIED"
