package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"math/bits"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type rangeEntry struct {
	start uint32
	count uint32
}

// fetchASNPrefixes fetches IPv4 prefixes for a given ASN from bgp.tools
func fetchASNPrefixes(asn string) ([]rangeEntry, error) {
	url := fmt.Sprintf("https://bgp.tools/table.txt?asn=%s", asn)
	client := &http.Client{Timeout: 90 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "olc-asncidrs/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var entries []rangeEntry
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip IPv6 prefixes
		if strings.Contains(line, ":") {
			continue
		}
		_, ipnet, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		count := uint32(1) << (32 - ones)
		entries = append(entries, rangeEntry{
			start: binary.BigEndian.Uint32(ip4),
			count: count,
		})
	}
	return entries, scanner.Err()
}

// rangeToCIDRs converts (start, count) where count is arbitrary to a list of CIDRs.
func rangeToCIDRs(start, count uint32) []string {
	var out []string
	for count > 0 {
		// Largest power of 2 aligned at `start` and <= count
		var maxAlign uint32 = 32
		if start != 0 {
			maxAlign = uint32(bits.TrailingZeros32(start))
		}
		var maxSize uint32 = 31 - uint32(bits.LeadingZeros32(count))
		size := maxAlign
		if maxSize < size {
			size = maxSize
		}
		prefix := 32 - size
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, start)
		out = append(out, fmt.Sprintf("%s/%d", ip.String(), prefix))
		block := uint32(1) << size
		start += block
		count -= block
		if start == 0 && count > 0 {
			// wrapped past 255.255.255.255, stop
			break
		}
	}
	return out
}

func mergeAndSort(entries []rangeEntry) []rangeEntry {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].start < entries[j].start
	})
	merged := make([]rangeEntry, 0, len(entries))
	for _, e := range entries {
		if len(merged) == 0 {
			merged = append(merged, e)
			continue
		}
		last := &merged[len(merged)-1]
		lastEnd := last.start + last.count
		eEnd := e.start + e.count
		if lastEnd >= e.start {
			// Overlapping or adjacent — merge
			if eEnd > lastEnd {
				last.count = eEnd - last.start
			}
		} else {
			merged = append(merged, e)
		}
	}
	return merged
}

func writeCIDRs(path string, entries []rangeEntry) (int, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()
	n := 0
	for _, e := range entries {
		for _, c := range rangeToCIDRs(e.start, e.count) {
			fmt.Fprintln(w, c)
			n++
		}
	}
	return n, nil
}

func main() {
	asnsFlag := flag.String("asn", "",
		"comma-separated ASN numbers (e.g., AS12345,AS67890 or 12345,67890)")
	outDir := flag.String("out", "scan/data", "output directory")
	combined := flag.Bool("combined", false, "write all ASNs to a single combined.txt file")
	flag.Parse()

	if *asnsFlag == "" {
		fmt.Fprintln(os.Stderr, "usage: cccidrs -asn AS12345,AS67890 [-out dir] [-combined]")
		os.Exit(1)
	}

	var asnList []string
	for _, asn := range strings.Split(*asnsFlag, ",") {
		asn = strings.ToUpper(strings.TrimSpace(asn))
		if asn == "" {
			continue
		}
		// Normalize: remove "AS" prefix if present for the API call
		asnList = append(asnList, asn)
	}
	if len(asnList) == 0 {
		fmt.Fprintln(os.Stderr, "no ASNs provided")
		os.Exit(1)
	}

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}

	collected := map[string][]rangeEntry{}
	var allEntries []rangeEntry

	for _, asn := range asnList {
		// Normalize ASN for API (remove AS prefix if present)
		asnNum := strings.TrimPrefix(asn, "AS")
		fmt.Printf("fetching %s...\n", asn)
		entries, err := fetchASNPrefixes(asnNum)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v (skipped)\n", asn, err)
			continue
		}
		collected[asn] = entries
		allEntries = append(allEntries, entries...)
		fmt.Printf("  %s: fetched %d prefixes\n", asn, len(entries))
	}

	if *combined {
		// Write all ASNs to a single file
		entries := mergeAndSort(allEntries)
		fname := filepath.Join(*outDir, "combined.txt")
		n, err := writeCIDRs(fname, entries)
		if err != nil {
			fmt.Fprintf(os.Stderr, "combined: write: %v\n", err)
			os.Exit(1)
		}
		var totalIPs uint64
		for _, e := range entries {
			totalIPs += uint64(e.count)
		}
		fmt.Printf("combined: %d ranges, %d CIDRs, %d IPs -> %s\n",
			len(entries), n, totalIPs, fname)
	} else {
		// Write each ASN to its own file
		totalCIDRs := 0
		for _, asn := range asnList {
			entries := mergeAndSort(collected[asn])
			asnLower := strings.ToLower(strings.TrimPrefix(asn, "AS"))
			fname := filepath.Join(*outDir, "as"+asnLower+".txt")
			n, err := writeCIDRs(fname, entries)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: write: %v\n", asn, err)
				continue
			}
			var totalIPs uint64
			for _, e := range entries {
				totalIPs += uint64(e.count)
			}
			fmt.Printf("%s: %d ranges, %d CIDRs, %d IPs -> %s\n",
				asn, len(entries), n, totalIPs, fname)
			totalCIDRs += n
		}
		fmt.Printf("total CIDRs written: %d\n", totalCIDRs)
	}
}
