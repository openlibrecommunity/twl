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

echo "Extracting unique IPs from masscan output..."

grep "^open" "$INPUT" | awk '{print $4}' | sort -u > "$OUTPUT"

TOTAL=$(grep -c "^open" "$INPUT" 2>/dev/null || echo "0")
UNIQUE=$(wc -l < "$OUTPUT")

echo "Total entries: $TOTAL"
echo "Unique IPs:    $UNIQUE"
echo "Duplicates:    $((TOTAL - UNIQUE))"
echo "Output: $OUTPUT"
