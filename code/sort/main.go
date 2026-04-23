package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/oschwald/maxminddb-golang"
)

type GeoRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Traits struct {
		AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
		AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
		ISP                          string `maxminddb:"isp"`
		Organization                 string `maxminddb:"organization"`
	} `maxminddb:"traits"`
}

type OrgGroup struct {
	Name  string   `json:"name"`
	ASN   uint     `json:"asn,omitempty"`
	Count int      `json:"count"`
	IPs   []string `json:"ips"`
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <geo.mmdb> <whitelist_ips.txt>\n", os.Args[0])
		os.Exit(1)
	}

	db, err := maxminddb.Open(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open mmdb: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	file, err := os.Open(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open input: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	byOrg := make(map[string]*OrgGroup)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}

		// masscan format: open tcp 443 IP timestamp
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}
		ipStr := parts[3]

		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		var record GeoRecord
		err := db.Lookup(ip, &record)
		if err != nil {
			continue
		}

		org := record.Traits.AutonomousSystemOrganization
		if org == "" {
			org = record.Traits.Organization
		}
		if org == "" {
			org = record.Traits.ISP
		}
		if org == "" {
			org = "Unknown"
		}

		key := fmt.Sprintf("%d_%s", record.Traits.AutonomousSystemNumber, org)

		if _, exists := byOrg[key]; !exists {
			byOrg[key] = &OrgGroup{
				Name: org,
				ASN:  record.Traits.AutonomousSystemNumber,
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

	output, _ := json.MarshalIndent(groups, "", "  ")
	fmt.Println(string(output))
}
