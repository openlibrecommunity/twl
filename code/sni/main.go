package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type HostInfo struct {
	IP     string   `json:"ip"`
	CN     string   `json:"cn,omitempty"`
	SANs   []string `json:"sans,omitempty"`
	Issuer string   `json:"issuer,omitempty"`
	Error  string   `json:"error,omitempty"`
}

type CompareResult struct {
	IP          string   `json:"ip"`
	CN          string   `json:"cn,omitempty"`
	SANs        []string `json:"sans,omitempty"`
	Issuer      string   `json:"issuer,omitempty"`
	Whitelisted bool     `json:"whitelisted"`
	Blocked     bool     `json:"blocked"`
	ErrorWL     string   `json:"error_wl,omitempty"`
	ErrorDirect string   `json:"error_direct,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <whitelist_ips.txt> [wl_interface] [direct_interface]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Single interface: %s ips.txt\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Compare mode:     %s ips.txt enp0s20u5 enp7s0\n", os.Args[0])
		os.Exit(1)
	}

	file, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open input: %v\n", err)
		os.Exit(1)
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

	if len(os.Args) >= 4 {
		wlIface := os.Args[2]
		directIface := os.Args[3]
		runCompareMode(ips, wlIface, directIface)
	} else {
		runSingleMode(ips, "")
	}
}

func runSingleMode(ips []string, iface string) {
	fmt.Fprintf(os.Stderr, "Checking %d IPs...\n", len(ips))

	results := checkAllIPs(ips, iface)

	output, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(output))
}

func runCompareMode(ips []string, wlIface, directIface string) {
	fmt.Fprintf(os.Stderr, "Compare mode: %d IPs\n", len(ips))
	fmt.Fprintf(os.Stderr, "  Whitelist interface: %s\n", wlIface)
	fmt.Fprintf(os.Stderr, "  Direct interface:    %s\n", directIface)
	fmt.Fprintf(os.Stderr, "\n")

	fmt.Fprintf(os.Stderr, "[1/2] Checking via %s (whitelist)...\n", wlIface)
	wlResults := checkAllIPs(ips, wlIface)
	wlMap := make(map[string]HostInfo)
	for _, r := range wlResults {
		wlMap[r.IP] = r
	}

	fmt.Fprintf(os.Stderr, "[2/2] Checking via %s (direct)...\n", directIface)
	directResults := checkAllIPs(ips, directIface)

	var compared []CompareResult
	var blockedCount int

	for _, direct := range directResults {
		wl := wlMap[direct.IP]

		result := CompareResult{
			IP:          direct.IP,
			CN:          direct.CN,
			SANs:        direct.SANs,
			Issuer:      direct.Issuer,
			Whitelisted: wl.Error == "" && wl.CN != "",
			ErrorDirect: direct.Error,
			ErrorWL:     wl.Error,
		}

		// Blocked = works via direct but fails via whitelist interface
		if direct.Error == "" && wl.Error != "" {
			result.Blocked = true
			blockedCount++
		}

		compared = append(compared, result)
	}

	fmt.Fprintf(os.Stderr, "\nResults: %d total, %d blocked via %s\n", len(compared), blockedCount, wlIface)

	output, _ := json.MarshalIndent(compared, "", "  ")
	fmt.Println(string(output))
}

func checkAllIPs(ips []string, iface string) []HostInfo {
	workers := 100
	timeout := 5 * time.Second
	jobs := make(chan string, 1000)
	results := make(chan HostInfo, 1000)

	var wg sync.WaitGroup
	var checked uint64

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				info := checkTLS(ip, iface, timeout)
				atomic.AddUint64(&checked, 1)
				results <- info
			}
		}()
	}

	go func() {
		total := uint64(len(ips))
		for {
			time.Sleep(3 * time.Second)
			c := atomic.LoadUint64(&checked)
			fmt.Fprintf(os.Stderr, "  Progress: %d/%d (%.1f%%)\n", c, total, float64(c)/float64(total)*100)
			if c >= total {
				break
			}
		}
	}()

	var all []HostInfo
	done := make(chan struct{})
	go func() {
		for info := range results {
			all = append(all, info)
		}
		close(done)
	}()

	for _, ip := range ips {
		jobs <- ip
	}
	close(jobs)
	wg.Wait()
	close(results)
	<-done

	return all
}

func checkTLS(ip string, iface string, timeout time.Duration) HostInfo {
	info := HostInfo{IP: ip}

	dialer := &net.Dialer{Timeout: timeout}

	if iface != "" {
		localIP := getInterfaceIP(iface)
		if localIP != "" {
			dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(localIP)}
		}
	}

	conn, err := tls.DialWithDialer(
		dialer,
		"tcp",
		ip+":443",
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		info.Error = "no certificates"
		return info
	}

	cert := certs[0]
	info.CN = cert.Subject.CommonName
	info.SANs = cert.DNSNames
	info.Issuer = cert.Issuer.CommonName

	return info
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
