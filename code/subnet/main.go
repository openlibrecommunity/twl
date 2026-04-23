package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

type Subnet struct {
	CIDR  string   `json:"cidr"`
	Count int      `json:"count"`
	Total int      `json:"total"`
	Pct   float64  `json:"percent"`
	IPs   []string `json:"ips"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <whitelist_ips.txt>\n", os.Args[0])
		os.Exit(1)
	}

	file, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open input: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	// Group by /24
	subnets := make(map[string][]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}
		ipStr := parts[3]

		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		// Get /24 prefix
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		prefix := fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
		subnets[prefix] = append(subnets[prefix], ipStr)
	}

	// Convert to slice and calc stats
	var result []Subnet
	for cidr, ips := range subnets {
		result = append(result, Subnet{
			CIDR:  cidr,
			Count: len(ips),
			Total: 256,
			Pct:   float64(len(ips)) / 256 * 100,
			IPs:   ips,
		})
	}

	// Sort by count desc
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	output, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(output))
}
