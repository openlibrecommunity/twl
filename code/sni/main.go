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

const (
	workers = 500
	timeout = 3 * time.Second
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <ips.txt> [wl_iface] [direct_iface]\n", os.Args[0])
		os.Exit(1)
	}

	ips := loadIPs(os.Args[1])

	if len(os.Args) >= 4 {
		runCompareMode(ips, os.Args[2], os.Args[3])
	} else {
		runSingleMode(ips, "")
	}
}

func loadIPs(path string) []string {
	file, _ := os.Open(path)
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

func runSingleMode(ips []string, iface string) {
	fmt.Fprintf(os.Stderr, "Checking %d IPs (%d workers)...\n", len(ips), workers)
	localIP := resolveIface(iface)
	results := checkAllIPs(ips, localIP)
	output, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(output))
}

func runCompareMode(ips []string, wlIface, directIface string) {
	fmt.Fprintf(os.Stderr, "Compare mode: %d IPs (%d workers)\n", len(ips), workers)

	wlIP := resolveIface(wlIface)
	directIP := resolveIface(directIface)

	fmt.Fprintf(os.Stderr, "[1/2] Checking via %s...\n", wlIface)
	wlResults := checkAllIPs(ips, wlIP)
	wlMap := make(map[string]HostInfo, len(wlResults))
	for _, r := range wlResults {
		wlMap[r.IP] = r
	}

	fmt.Fprintf(os.Stderr, "[2/2] Checking via %s...\n", directIface)
	directResults := checkAllIPs(ips, directIP)

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
		if direct.Error == "" && wl.Error != "" {
			result.Blocked = true
			blockedCount++
		}
		compared = append(compared, result)
	}

	fmt.Fprintf(os.Stderr, "\nResults: %d total, %d blocked\n", len(compared), blockedCount)
	output, _ := json.MarshalIndent(compared, "", "  ")
	fmt.Println(string(output))
}

func checkAllIPs(ips []string, localIP string) []HostInfo {
	jobs := make(chan string, workers*2)
	results := make([]HostInfo, len(ips))
	var wg sync.WaitGroup
	var checked uint64
	total := uint64(len(ips))

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				idx := atomic.AddUint64(&checked, 1) - 1
				results[idx] = checkTLS(ip, localIP)
			}
		}()
	}

	// Progress reporter
	go func() {
		for {
			time.Sleep(5 * time.Second)
			c := atomic.LoadUint64(&checked)
			fmt.Fprintf(os.Stderr, "  %d/%d (%.0f%%)\n", c, total, float64(c)/float64(total)*100)
			if c >= total {
				return
			}
		}
	}()

	for _, ip := range ips {
		jobs <- ip
	}
	close(jobs)
	wg.Wait()

	return results[:checked]
}

func checkTLS(ip string, localIP string) HostInfo {
	info := HostInfo{IP: ip}

	dialer := &net.Dialer{Timeout: timeout}
	if localIP != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(localIP)}
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", ip+":443", &tls.Config{InsecureSkipVerify: true})
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

	info.CN = certs[0].Subject.CommonName
	info.SANs = certs[0].DNSNames
	info.Issuer = certs[0].Issuer.CommonName
	return info
}

func resolveIface(name string) string {
	if name == "" {
		return ""
	}
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
