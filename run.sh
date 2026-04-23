#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IFACE="${1:-wlan0}"
WHITELIST="$SCRIPT_DIR/code/scan/out/whitelist_ips.txt"
MMDB="$SCRIPT_DIR/code/sort/data/GeoLite2-ASN.mmdb"

if [ ! -f "$WHITELIST" ]; then
    echo "Error: $WHITELIST not found"
    echo "Run scan first: ./code/scan/script/scan.sh"
    exit 1
fi

IP_COUNT=$(grep -c "^open" "$WHITELIST" 2>/dev/null || echo "0")
echo "=== Whitelist Analysis ==="
echo "Input: $WHITELIST ($IP_COUNT IPs)"
echo "Interface: $IFACE"
echo "Started: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

cd "$SCRIPT_DIR/code"

echo "[1/4] Running sort (ASN grouping)..."
if [ -f "$MMDB" ]; then
    go run sort/main.go "$MMDB" "$WHITELIST" > sort/out/sorted.json
    echo "  -> sort/out/sorted.json"
else
    echo "  -> SKIP (no $MMDB)"
fi

echo "[2/4] Running subnet analysis..."
go run subnet/main.go "$WHITELIST" > subnet/out/subnets.json
echo "  -> subnet/out/subnets.json"

echo "[3/4] Running SNI check..."
go run sni/main.go "$WHITELIST" > sni/out/domains.json
echo "  -> sni/out/domains.json"

echo "[4/4] Running probe..."
go run probe/main.go "$WHITELIST" "$IFACE"
echo "  -> probe/out/probe_results.json"

cd "$SCRIPT_DIR"

echo ""
echo "=== Committing results ==="
TIMESTAMP=$(date '+%Y-%m-%d_%H-%M')
git add -A
git commit -m "results: $TIMESTAMP ($IP_COUNT IPs)" || echo "Nothing to commit"

echo ""
echo "=== Done ==="
echo "Finished: $(date '+%Y-%m-%d %H:%M:%S')"
