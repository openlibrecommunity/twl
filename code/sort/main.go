package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/oschwald/maxminddb-golang"
)

type GeoRecord struct {
	ASN uint   `maxminddb:"autonomous_system_number"`
	Org string `maxminddb:"autonomous_system_organization"`
}

type OrgGroup struct {
	Name  string   `json:"name"`
	ASN   uint     `json:"asn,omitempty"`
	Count int      `json:"count"`
	IPs   []string `json:"ips"`
}

func processFile(db *maxminddb.Reader, inputPath string, isMasscan bool) []*OrgGroup {
	file, err := os.Open(inputPath)
	if err != nil {
		return nil
	}
	defer file.Close()

	byOrg := make(map[string]*OrgGroup)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}

		var ipStr string
		if isMasscan {
			// masscan format: open tcp 443 IP timestamp
			parts := strings.Fields(line)
			if len(parts) < 4 {
				continue
			}
			ipStr = parts[3]
		} else {
			// plain IP list (verified)
			ipStr = strings.TrimSpace(line)
			if ipStr == "" {
				continue
			}
		}

		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		var record GeoRecord
		err := db.Lookup(ip, &record)
		if err != nil {
			continue
		}

		org := record.Org
		if org == "" {
			org = "Unknown"
		}

		key := fmt.Sprintf("%d_%s", record.ASN, org)

		if _, exists := byOrg[key]; !exists {
			byOrg[key] = &OrgGroup{
				Name: org,
				ASN:  record.ASN,
				IPs:  []string{},
			}
		}
		byOrg[key].IPs = append(byOrg[key].IPs, ipStr)
		byOrg[key].Count++
	}

	var groups []*OrgGroup
	for _, g := range byOrg {
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Count > groups[j].Count
	})

	return groups
}

func writeJSON(groups []*OrgGroup, outputPath string) error {
	output, err := json.MarshalIndent(groups, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, output, 0644)
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <geo.mmdb> <whitelist_ips.txt> [verified.txt]\n", os.Args[0])
		os.Exit(1)
	}

	db, err := maxminddb.Open(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open mmdb: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	exe, _ := os.Executable()
	outDir := filepath.Join(filepath.Dir(exe), "out")
	if _, err := os.Stat(outDir); os.IsNotExist(err) {
		outDir = "out"
	}

	// Process raw masscan output -> sorted.json
	rawInput := os.Args[2]
	rawGroups := processFile(db, rawInput, true)
	if rawGroups != nil {
		rawOut := filepath.Join(outDir, "sorted.json")
		if err := writeJSON(rawGroups, rawOut); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write sorted.json: %v\n", err)
		} else {
			totalRaw := 0
			for _, g := range rawGroups {
				totalRaw += g.Count
			}
			fmt.Printf("sorted.json: %d IPs in %d orgs\n", totalRaw, len(rawGroups))
		}
	}

	// Process verified IPs -> sorted.c.json
	var verifiedInput string
	if len(os.Args) >= 4 {
		verifiedInput = os.Args[3]
	} else {
		// Try default path
		verifiedInput = filepath.Join(filepath.Dir(rawInput), "verify", "verified.txt")
	}

	if _, err := os.Stat(verifiedInput); err == nil {
		verifiedGroups := processFile(db, verifiedInput, false)
		if verifiedGroups != nil {
			verifiedOut := filepath.Join(outDir, "sorted.c.json")
			if err := writeJSON(verifiedGroups, verifiedOut); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to write sorted.c.json: %v\n", err)
			} else {
				totalVerified := 0
				for _, g := range verifiedGroups {
					totalVerified += g.Count
				}
				fmt.Printf("sorted.c.json: %d IPs in %d orgs\n", totalVerified, len(verifiedGroups))
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "No verified.txt found, skipping sorted.c.json\n")
	}
}
