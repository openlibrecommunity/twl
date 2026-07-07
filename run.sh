#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

MODE=""
WL_IFACE="enp0s20u9"
DIRECT_IFACE="enp7s0"

if [ "$1" = "all" ]; then
    MODE="all"
    WL_IFACE="${2:-enp0s20u9}"
    DIRECT_IFACE="${3:-enp7s0}"
else
    WL_IFACE="${1:-enp0s20u9}"
    DIRECT_IFACE="${2:-enp7s0}"
fi

WHITELIST="$SCRIPT_DIR/code/scan/out/whitelist_ips.txt"
VERIFIED="$SCRIPT_DIR/code/scan/out/verify/verified.txt"
MMDB="$SCRIPT_DIR/code/sort/data/geo.mmdb"
RANGES="$SCRIPT_DIR/code/scan/data/ruranges4.txt"
PPS=1000

# === FULL SCAN MODE ===
if [ "$MODE" = "all" ]; then
    echo "=========================================="
    echo "=== FULL PIPELINE (from scratch) ==="
    echo "=========================================="
    echo "Whitelist interface: $WL_IFACE"
    echo "Direct interface:    $DIRECT_IFACE"
    echo "Started: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""

    if [ ! -f "$RANGES" ]; then
        echo "Error: $RANGES not found"
        exit 1
    fi

    mkdir -p "$SCRIPT_DIR/code/scan/out/verify"
    mkdir -p "$SCRIPT_DIR/code/sort/out"
    mkdir -p "$SCRIPT_DIR/code/subnet/out"
    mkdir -p "$SCRIPT_DIR/code/sni/out"
    mkdir -p "$SCRIPT_DIR/code/probe/out"
    mkdir -p "$SCRIPT_DIR/code/dns/out"

    RANGE_COUNT=$(wc -l < "$RANGES" | tr -d ' ')
    echo "[0/7] Running masscan (port 443 scan)..."
    echo "  Ranges: $RANGE_COUNT subnets"
    echo "  Rate: $PPS pps"
    sudo masscan --adapter "$WL_IFACE" -p443 -iL "$RANGES" --rate $PPS -oL "$WHITELIST" --retries 3 --resume paused.conf
    echo ""
fi

# === NORMAL MODE ===
if [ ! -f "$WHITELIST" ]; then
    echo "Error: $WHITELIST not found"
    echo "Run: ./run.sh all"
    exit 1
fi

IP_COUNT=$(wc -l < "$WHITELIST" | tr -d ' ')
VERIFIED_COUNT=0
[ -f "$VERIFIED" ] && VERIFIED_COUNT=$(wc -l < "$VERIFIED" | tr -d ' ')

echo "=== Whitelist Analysis ==="
echo "Input: $WHITELIST ($IP_COUNT IPs)"
echo "Verified: $VERIFIED ($VERIFIED_COUNT IPs)"
echo "Whitelist interface: $WL_IFACE"
echo "Direct interface:    $DIRECT_IFACE"
echo "Started: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

cd "$SCRIPT_DIR/code"

echo "[1/7] Deduplicating IPs..."
bash scan/script/dedupe.sh
echo ""

echo "[2/7] Verifying with nmap + httpx-toolkit..."
bash scan/script/verify.sh "$WL_IFACE"
echo ""

echo "[3/7] Running sort (ASN grouping)..."
if [ -f "$MMDB" ]; then
    go run sort/main.go "$MMDB" "$WHITELIST" "$VERIFIED"
else
    echo "  -> SKIP (no $MMDB)"
fi

echo "[4/7] Running subnet analysis..."
go run subnet/main.go "$WHITELIST" > subnet/out/subnets.json
[ -f "$VERIFIED" ] && go run subnet/main.go "$VERIFIED" > subnet/out/subnets.c.json

echo "[5/7] Running SNI check (compare mode)..."
go run sni/main.go "$WHITELIST" "$WL_IFACE" "$DIRECT_IFACE" > sni/out/domains.json

echo "[6/7] Running SNI blocking test..."
go run sni/snicheck/main.go "$WL_IFACE" > sni/out/snicheck.json

echo "[7/7] Running probe..."
go run probe/main.go "$WHITELIST" "$WL_IFACE"

cd "$SCRIPT_DIR"

VERIFIED_COUNT=$(wc -l < "$VERIFIED" 2>/dev/null | tr -d ' ' || echo "0")

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
