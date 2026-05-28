package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
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

	iface := os.Args[2]
	localIP := resolveIface(iface)
	if localIP == "" {
		fmt.Fprintf(os.Stderr, "Cannot get IP for %s\n", iface)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Probe via %s (%s)\n\n", iface, localIP)

	whitelistIPs := loadIPs(os.Args[1])

	targets := append(
		[]string{"77.88.55.242", "87.240.132.78", "217.20.147.1"},
		randomSample(whitelistIPs, 3)...,
	)
	nonWL := []string{"149.154.167.99", "142.250.185.14", "104.244.42.193"}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var all []ProbeResult

	probe := func(ip string, wl bool) {
		defer wg.Done()
		r := probeIP(ip, localIP, wl)
		mu.Lock()
		all = append(all, r)
		mu.Unlock()
		printResult(r)
	}

	for _, ip := range targets {
		wg.Add(1)
		go probe(ip, true)
	}
	for _, ip := range nonWL {
		wg.Add(1)
		go probe(ip, false)
	}
	wg.Wait()

	output, _ := json.MarshalIndent(all, "", "  ")
	os.WriteFile("probe/out/probe_results.json", output, 0644)
	fmt.Fprintf(os.Stderr, "\nResults: probe/out/probe_results.json\n")
}

func probeIP(ip, localIP string, whitelist bool) ProbeResult {
	r := ProbeResult{IP: ip, Whitelist: whitelist, Tests: make(map[string]string)}
	var wg sync.WaitGroup
	var mu sync.Mutex

	tests := []struct {
		name string
		fn   func() string
	}{
		{"icmp", func() string { return testICMP(ip) }},
		{"tcp_80", func() string { return testTCP(ip, "80", localIP) }},
		{"tcp_443", func() string { return testTLS(ip, localIP) }},
		{"tcp_22", func() string { return testTCP(ip, "22", localIP) }},
		{"udp_443", func() string { return testUDP(ip, "443", localIP) }},
		{"udp_53", func() string { return testUDP(ip, "53", localIP) }},
		{"udp_51820", func() string { return testUDP(ip, "51820", localIP) }},
	}

	for _, t := range tests {
		wg.Add(1)
		go func(name string, fn func() string) {
			defer wg.Done()
			res := fn()
			mu.Lock()
			r.Tests[name] = res
			mu.Unlock()
		}(t.name, t.fn)
	}
	wg.Wait()
	return r
}

func testICMP(ip string) string {
	conn, err := net.DialTimeout("ip4:icmp", ip, 2*time.Second)
	if err != nil {
		return "FAIL"
	}
	conn.Close()
	return "OK"
}

func testTCP(ip, port, localIP string) string {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	if localIP != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(localIP)}
	}
	conn, err := dialer.Dial("tcp", ip+":"+port)
	if err != nil {
		return "FAIL"
	}
	conn.Close()
	return "OK"
}

func testTLS(ip, localIP string) string {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	if localIP != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(localIP)}
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", ip+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return "FAIL"
	}
	conn.Close()
	return "OK"
}

func testUDP(ip, port, localIP string) string {
	laddr := &net.UDPAddr{IP: net.ParseIP(localIP)}
	raddr, _ := net.ResolveUDPAddr("udp", ip+":"+port)
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
	file, _ := os.Open(filename)
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
	result := make([]string, n)
	for i := range result {
		result[i] = ips[perm[i]]
	}
	return result
}

func resolveIface(name string) string {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return ""
	}
	addrs, _ := iface.Addrs()
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return ""
}

func printResult(r ProbeResult) {
	tag := "WL"
	if !r.Whitelist {
		tag = "NW"
	}
	fmt.Fprintf(os.Stderr, "[%s] %-18s icmp:%-4s tcp80:%-4s tcp443:%-4s udp443:%-7s udp53:%-7s\n",
		tag, r.IP, r.Tests["icmp"], r.Tests["tcp_80"], r.Tests["tcp_443"], r.Tests["udp_443"], r.Tests["udp_53"])
}
