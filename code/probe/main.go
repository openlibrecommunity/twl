package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type ProbeResult struct {
	IP        string            `json:"ip"`
	Whitelist bool              `json:"whitelist"`
	Tests     map[string]string `json:"tests"`
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <whitelist_ips.txt> <interface>\n", os.Args[0])
		os.Exit(1)
	}

	whitelistFile := os.Args[1]
	iface := os.Args[2]

	localIP := getInterfaceIP(iface)
	if localIP == "" {
		fmt.Fprintf(os.Stderr, "Cannot get IP for %s\n", iface)
		os.Exit(1)
	}

	fmt.Printf("Probe via %s (%s)\n\n", iface, localIP)

	whitelistIPs := loadIPs(whitelistFile)

	guaranteedWhitelist := []string{
		"77.88.55.242",  // ya.ru
		"87.240.132.78", // vk.com
		"217.20.147.1",  // max.ru
	}

	nonWhitelistIPs := []string{
		"149.154.167.99",  // telegram
		"142.250.185.14",  // google
		"104.244.42.193",  // twitter
	}

	rand.Seed(time.Now().UnixNano())
	selectedWhitelist := append(guaranteedWhitelist, randomSample(whitelistIPs, 3)...)

	var wg sync.WaitGroup
	results := make(chan ProbeResult, 20)

	for _, ip := range selectedWhitelist {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			results <- probeIP(ip, iface, true)
		}(ip)
	}

	for _, ip := range nonWhitelistIPs {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			results <- probeIP(ip, iface, false)
		}(ip)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var all []ProbeResult
	for r := range results {
		all = append(all, r)
		printResult(r)
	}

	output, _ := json.MarshalIndent(all, "", "  ")
	os.WriteFile("out/probe_results.json", output, 0644)
	fmt.Println("\nResults: out/probe_results.json")
}

func probeIP(ip string, iface string, whitelist bool) ProbeResult {
	r := ProbeResult{
		IP:        ip,
		Whitelist: whitelist,
		Tests:     make(map[string]string),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	tests := []struct {
		name string
		fn   func() string
	}{
		{"icmp", func() string { return testICMP(ip, iface) }},
		{"tcp_80", func() string { return testTCPCurl(ip, "80", iface) }},
		{"tcp_443", func() string { return testTCPCurl(ip, "443", iface) }},
		{"tcp_22", func() string { return testTCPCurl(ip, "22", iface) }},
		{"udp_443", func() string { return testUDP(ip, "443", iface) }},
		{"udp_53", func() string { return testUDP(ip, "53", iface) }},
		{"udp_51820", func() string { return testUDP(ip, "51820", iface) }},
	}

	for _, t := range tests {
		wg.Add(1)
		go func(name string, fn func() string) {
			defer wg.Done()
			result := fn()
			mu.Lock()
			r.Tests[name] = result
			mu.Unlock()
		}(t.name, t.fn)
	}

	wg.Wait()
	return r
}

func testICMP(ip string, iface string) string {
	cmd := exec.Command("ping", "-c", "1", "-W", "2", "-I", iface, ip)
	err := cmd.Run()
	if err != nil {
		return "FAIL"
	}
	return "OK"
}

func testTCPCurl(ip string, port string, iface string) string {
	proto := "http"
	if port == "443" {
		proto = "https"
	}
	url := fmt.Sprintf("%s://%s:%s", proto, ip, port)

	cmd := exec.Command("curl", "--interface", iface, "-k", "-s", "-o", "/dev/null",
		"-w", "%{http_code}", "--connect-timeout", "2", url)
	out, err := cmd.Output()
	if err != nil {
		return "FAIL"
	}
	code := strings.TrimSpace(string(out))
	if code != "000" {
		return "OK"
	}
	return "FAIL"
}

func testUDP(ip string, port string, iface string) string {
	localIP := getInterfaceIP(iface)
	laddr := &net.UDPAddr{IP: net.ParseIP(localIP)}
	raddr := &net.UDPAddr{IP: net.ParseIP(ip), Port: atoi(port)}

	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return "FAIL"
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))
	conn.Write([]byte{0x00})

	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err != nil {
		return "NO_RESP"
	}
	return "OK"
}

func loadIPs(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		return nil
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 4 {
			ips = append(ips, parts[3])
		}
	}
	return ips
}

func randomSample(ips []string, n int) []string {
	if len(ips) <= n {
		return ips
	}
	perm := rand.Perm(len(ips))
	var result []string
	for i := 0; i < n; i++ {
		result = append(result, ips[perm[i]])
	}
	return result
}

func getInterfaceIP(name string) string {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return ""
}

func atoi(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}

func printResult(r ProbeResult) {
	tag := "WL"
	if !r.Whitelist {
		tag = "NW"
	}
	fmt.Printf("[%s] %-18s icmp:%-4s tcp80:%-4s tcp443:%-4s udp443:%-7s udp53:%-7s\n",
		tag, r.IP,
		r.Tests["icmp"],
		r.Tests["tcp_80"],
		r.Tests["tcp_443"],
		r.Tests["udp_443"],
		r.Tests["udp_53"])
}
