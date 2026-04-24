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

func parseIPs(filename string, isMasscan bool) []Subnet {
	file, err := os.Open(filename)
	if err != nil {
		return nil
	}
	defer file.Close()

	subnets := make(map[string][]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}

		var ipStr string
		if isMasscan {
			parts := strings.Fields(line)
			if len(parts) < 4 {
				continue
			}
			ipStr = parts[3]
		} else {
			ipStr = strings.TrimSpace(line)
			if ipStr == "" {
				continue
			}
		}

		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		prefix := fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
		subnets[prefix] = append(subnets[prefix], ipStr)
	}

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

	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	return result
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <whitelist_ips.txt|verified.txt>\n", os.Args[0])
		os.Exit(1)
	}

	filename := os.Args[1]

	// Detect format: masscan has "open tcp 443", plain list doesn't
	file, err := os.Open(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open input: %v\n", err)
		os.Exit(1)
	}

	scanner := bufio.NewScanner(file)
	isMasscan := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "open") {
			isMasscan = true
		}
		break
	}
	file.Close()

	result := parseIPs(filename, isMasscan)
	output, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(output))
}
