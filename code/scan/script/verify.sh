#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"
VERIFY_DIR="$BASE_DIR/out/verify"

IFACE="${1:-wlan0}"
INPUT="$VERIFY_DIR/input.txt"
NMAP_OUT="$VERIFY_DIR/nmap.txt"
VERIFIED="$VERIFY_DIR/verified.txt"

if [ ! -f "$INPUT" ]; then
    echo "Error: $INPUT not found"
    echo "Run dedupe.sh first"
    exit 1
fi

IP_COUNT=$(wc -l < "$INPUT")
echo "=== Nmap Verification ==="
echo "Interface: $IFACE"
echo "Input: $INPUT ($IP_COUNT IPs)"
echo "Output: $NMAP_OUT"
echo ""

sudo nmap -sS -p443 -Pn -n \
    -e "$IFACE" \
    --min-rate 500 --max-rate 1000 \
    --max-retries 3 \
    --host-timeout 20s \
    --reason \
    -iL "$INPUT" \
    -oG "$NMAP_OUT"

echo ""
echo "Parsing results..."

awk '/443\/open/ {print $2}' "$NMAP_OUT" | sort -u > "$VERIFIED"

VERIFIED_COUNT=$(wc -l < "$VERIFIED")
DROPPED=$((IP_COUNT - VERIFIED_COUNT))

echo ""
echo "=== Results ==="
echo "Input:    $IP_COUNT"
echo "Verified: $VERIFIED_COUNT"
echo "Dropped:  $DROPPED"
echo "Output:   $VERIFIED"
