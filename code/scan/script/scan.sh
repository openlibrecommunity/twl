#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"

IFACE="wlan0"
RANGES="$BASE_DIR/data/ruranges_v4.txt"
OUTPUT="$BASE_DIR/out/whitelist_ips.txt"
RATE=10000

if [ ! -f "$RANGES" ]; then
    echo "Error: $RANGES not found"
    exit 1
fi

echo "Starting masscan on $IFACE..."
echo "Ranges: $(wc -l < $RANGES) subnets"
echo "Rate: $RATE pps"
echo "Output: $OUTPUT"
echo ""

sudo masscan --adapter $IFACE -p443 -iL $RANGES --rate $RATE -oL $OUTPUT
