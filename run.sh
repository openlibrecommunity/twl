#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WL_IFACE="${1:-wlan0}"
DIRECT_IFACE="${2:-tun0}"
WHITELIST="$SCRIPT_DIR/code/scan/out/whitelist_ips.txt"
VERIFIED="$SCRIPT_DIR/code/scan/out/verify/verified.txt"
MMDB="$SCRIPT_DIR/code/sort/data/GeoLite2-ASN.mmdb"

if [ ! -f "$WHITELIST" ]; then
    echo "Error: $WHITELIST not found"
    echo "Run scan first: ./code/scan/script/scan.sh"
    exit 1
fi

IP_COUNT=$(grep -c "^open" "$WHITELIST" 2>/dev/null || echo "0")
VERIFIED_COUNT=0
if [ -f "$VERIFIED" ]; then
    VERIFIED_COUNT=$(wc -l < "$VERIFIED")
fi

echo "=== Whitelist Analysis ==="
echo "Input: $WHITELIST ($IP_COUNT IPs)"
echo "Verified: $VERIFIED ($VERIFIED_COUNT IPs)"
echo "Whitelist interface: $WL_IFACE"
echo "Direct interface:    $DIRECT_IFACE"
echo "Started: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

cd "$SCRIPT_DIR/code"

echo "[1/6] Deduplicating IPs..."
bash scan/script/dedupe.sh
echo ""

echo "[2/6] Verifying with nmap..."
bash scan/script/verify.sh "$WL_IFACE"
echo ""

echo "[3/6] Running sort (ASN grouping)..."
if [ -f "$MMDB" ]; then
    go run sort/main.go "$MMDB" "$WHITELIST" "$VERIFIED"
    echo "  -> sort/out/sorted.json (raw)"
    echo "  -> sort/out/sorted.c.json (verified)"
else
    echo "  -> SKIP (no $MMDB)"
fi

echo "[4/6] Running subnet analysis..."
go run subnet/main.go "$WHITELIST" > subnet/out/subnets.json
if [ -f "$VERIFIED" ]; then
    go run subnet/main.go "$VERIFIED" > subnet/out/subnets.c.json
    echo "  -> subnet/out/subnets.json + subnets.c.json"
else
    echo "  -> subnet/out/subnets.json"
fi

echo "[5/6] Running SNI check (compare mode)..."
go run sni/main.go "$WHITELIST" "$WL_IFACE" "$DIRECT_IFACE" > sni/out/domains.json
echo "  -> sni/out/domains.json"

echo "[6/6] Running SNI blocking test..."
go run sni/snicheck.go "$WL_IFACE" > sni/out/snicheck.json
echo "  -> sni/out/snicheck.json"

cd "$SCRIPT_DIR"

VERIFIED_COUNT=$(wc -l < "$VERIFIED" 2>/dev/null || echo "0")

echo ""
echo "=== Committing results ==="
TIMESTAMP=$(date '+%Y-%m-%d_%H-%M')
git add -A
git commit -m "results: $TIMESTAMP ($VERIFIED_COUNT verified IPs)" || echo "Nothing to commit"

echo ""
echo "=== Done ==="
echo "Finished: $(date '+%Y-%m-%d %H:%M:%S')"
echo "Raw IPs: $IP_COUNT"
echo "Verified IPs: $VERIFIED_COUNT"
