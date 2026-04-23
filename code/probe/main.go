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
	if len(whitelistIPs) == 0 {
		fmt.Fprintf(os.Stderr, "No IPs loaded\n")
		os.Exit(1)
	}

	nonWhitelistIPs := []string{
		"149.154.167.99",  // telegram
		"142.250.185.14",  // google
		"151.101.1.140",   // reddit
		"104.244.42.193",  // twitter
		"157.240.1.35",    // facebook
		"52.94.236.248",   // aws
		"13.107.42.14",    // microsoft
		"185.199.108.153", // github pages
		"104.16.132.229",  // cloudflare
		"8.8.8.8",         // google dns
	}

	rand.Seed(time.Now().UnixNano())

	guaranteedWhitelist := []string{
		"77.88.55.242",  // ya.ru
		"87.240.132.78", // vk.com
		"217.20.147.1",  // max.ru
	}

	selectedWhitelist := append(guaranteedWhitelist, randomSample(whitelistIPs, 3)...)

	var results []ProbeResult

	fmt.Println("=== Whitelist IPs ===")
	for _, ip := range selectedWhitelist {
		r := probeIP(ip, iface, true)
		results = append(results, r)
		printResult(r)
	}

	fmt.Println("\n=== Non-Whitelist IPs ===")
	for _, ip := range nonWhitelistIPs {
		r := probeIP(ip, iface, false)
		results = append(results, r)
		printResult(r)
	}

	output, _ := json.MarshalIndent(results, "", "  ")
	os.WriteFile("out/probe_results.json", output, 0644)
	fmt.Println("\nResults: out/probe_results.json")
}

func probeIP(ip string, iface string, whitelist bool) ProbeResult {
	r := ProbeResult{
		IP:        ip,
		Whitelist: whitelist,
		Tests:     make(map[string]string),
	}

	// ICMP
	r.Tests["icmp"] = testICMP(ip, iface)

	// TCP ports
	r.Tests["tcp_80"] = testTCP(ip, "80", iface)
	r.Tests["tcp_443"] = testTCP(ip, "443", iface)
	r.Tests["tcp_22"] = testTCP(ip, "22", iface)
	r.Tests["tcp_53"] = testTCP(ip, "53", iface)

	// UDP
	r.Tests["udp_443"] = testUDP(ip, "443", iface)
	r.Tests["udp_53"] = testUDP(ip, "53", iface)
	r.Tests["udp_51820"] = testUDP(ip, "51820", iface)

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

func testTCP(ip string, port string, iface string) string {
	localIP := getInterfaceIP(iface)
	dialer := &net.Dialer{
		Timeout:   2 * time.Second,
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(localIP)},
	}
	conn, err := dialer.Dial("tcp", ip+":"+port)
	if err != nil {
		return "FAIL"
	}
	conn.Close()
	return "OK"
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
	_, err = conn.Write([]byte{0x00})
	if err != nil {
		return "FAIL"
	}

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
