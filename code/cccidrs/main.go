package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math/bits"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Sources: delegated stats from each RIR.
// We pull all of them to cover every country code, then filter.
var rirSources = map[string]string{
	"ripencc": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
	"arin":    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
	"apnic":   "https://ftp.apnic.net/pub/stats/apnic/delegated-apnic-extended-latest",
	"lacnic":  "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
	"afrinic": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
}

type rangeEntry struct {
	start uint32
	count uint32
}

func fetch(url string) (io.ReadCloser, error) {
	client := &http.Client{Timeout: 90 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "olc-cccidrs/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return resp.Body, nil
}

func parseDelegated(r io.Reader, want map[string]bool, out map[string][]rangeEntry) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1<<16), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) < 7 {
			continue
		}
		// registry|cc|type|start|value|date|status|...
		if fields[2] != "ipv4" {
			continue
		}
		cc := fields[1]
		if !want[cc] {
			continue
		}
		ip := net.ParseIP(fields[3])
		if ip == nil {
			continue
		}
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		count, err := strconv.ParseUint(fields[4], 10, 32)
		if err != nil || count == 0 {
			continue
		}
		out[cc] = append(out[cc], rangeEntry{
			start: binary.BigEndian.Uint32(ip4),
			count: uint32(count),
		})
	}
	return scanner.Err()
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
		if last.start+last.count == e.start {
			last.count += e.count
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
	ccsFlag := flag.String("cc", "RU,BY,KZ,AM,KG,UZ,TJ,AZ,MD",
		"comma-separated country codes (default: RU + CIS/EAEU set)")
	outDir := flag.String("out", "scan/data", "output directory")
	flag.Parse()

	want := map[string]bool{}
	var ccList []string
	for _, cc := range strings.Split(*ccsFlag, ",") {
		cc = strings.ToUpper(strings.TrimSpace(cc))
		if cc != "" {
			want[cc] = true
			ccList = append(ccList, cc)
		}
	}
	if len(want) == 0 {
		fmt.Fprintln(os.Stderr, "no country codes")
		os.Exit(1)
	}

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}

	collected := map[string][]rangeEntry{}

	for name, url := range rirSources {
		fmt.Printf("fetching %s...\n", name)
		body, err := fetch(url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v (skipped)\n", name, err)
			continue
		}
		err = parseDelegated(body, want, collected)
		body.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s: parse: %v\n", name, err)
		}
	}

	sort.Strings(ccList)
	totalCIDRs := 0
	for _, cc := range ccList {
		entries := mergeAndSort(collected[cc])
		fname := filepath.Join(*outDir, strings.ToLower(cc)+"ranges4.txt")
		n, err := writeCIDRs(fname, entries)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: write: %v\n", cc, err)
			continue
		}
		var totalIPs uint64
		for _, e := range entries {
			totalIPs += uint64(e.count)
		}
		fmt.Printf("%s: %d ranges, %d CIDRs, %d IPs -> %s\n",
			cc, len(entries), n, totalIPs, fname)
		totalCIDRs += n
	}
	fmt.Printf("total CIDRs written: %d\n", totalCIDRs)
}
