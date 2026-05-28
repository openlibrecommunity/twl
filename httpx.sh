#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

INPUT="${1:-$SCRIPT_DIR/code/scan/out/verify/verified.txt}"
OUTPUT="${2:-$SCRIPT_DIR/code/scan/out/verify/httpx_full.json}"
THREADS="${3:-50}"

if [ ! -f "$INPUT" ]; then
    echo "Error: $INPUT not found"
    echo "Usage: $0 [input_file] [output_file] [threads]"
    exit 1
fi

IP_COUNT=$(wc -l < "$INPUT")
echo "=== httpx-toolkit full scan ==="
echo "Input:   $INPUT ($IP_COUNT IPs)"
echo "Output:  $OUTPUT"
echo "Threads: $THREADS"
echo ""

httpx-toolkit -l "$INPUT" -p 443 -threads "$THREADS" \
    -status-code -tech-detect -title -web-server \
    -ip -cname -asn -cdn -tls-grab \
    -response-time -method -websocket \
    -json -no-color -silent \
    -o "$OUTPUT"

RESULT_COUNT=$(wc -l < "$OUTPUT" 2>/dev/null || echo 0)
echo ""
echo "Done: $RESULT_COUNT responses saved to $OUTPUT"
