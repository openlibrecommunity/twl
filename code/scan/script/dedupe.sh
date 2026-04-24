#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"
VERIFY_DIR="$BASE_DIR/out/verify"

INPUT="$BASE_DIR/out/whitelist_ips.txt"
OUTPUT="$VERIFY_DIR/input.txt"

mkdir -p "$VERIFY_DIR"

if [ ! -f "$INPUT" ]; then
    echo "Error: $INPUT not found"
    exit 1
fi

echo "Extracting unique IPs..."

# Detect format: masscan or plain IP list
if grep -q "^open" "$INPUT" 2>/dev/null; then
    # masscan format: open tcp 443 IP timestamp
    grep "^open" "$INPUT" | awk '{print $4}' | sort -u > "$OUTPUT"
    TOTAL=$(grep -c "^open" "$INPUT")
else
    # plain IP list
    grep -v "^#" "$INPUT" | grep -v "^$" | sort -u > "$OUTPUT"
    TOTAL=$(grep -v "^#" "$INPUT" | grep -v "^$" | wc -l)
fi

UNIQUE=$(wc -l < "$OUTPUT")

echo "Total entries: $TOTAL"
echo "Unique IPs:    $UNIQUE"
echo "Duplicates:    $((TOTAL - UNIQUE))"
echo "Output: $OUTPUT"
