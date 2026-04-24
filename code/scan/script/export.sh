#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"
VERIFY_DIR="$BASE_DIR/out/verify"

VERIFIED="$VERIFY_DIR/verified.txt"
OUTPUT="$BASE_DIR/out/whitelist_ips.c.txt"

if [ ! -f "$VERIFIED" ]; then
    echo "Error: $VERIFIED not found"
    echo "Run verify.sh first"
    exit 1
fi

cp "$VERIFIED" "$OUTPUT"

COUNT=$(wc -l < "$OUTPUT")
echo "Exported $COUNT verified IPs to $OUTPUT"
