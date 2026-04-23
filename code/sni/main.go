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
	IP      string   `json:"ip"`
	CN      string   `json:"cn,omitempty"`
	SANs    []string `json:"sans,omitempty"`
	Issuer  string   `json:"issuer,omitempty"`
	Error   string   `json:"error,omitempty"`
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

	fmt.Fprintf(os.Stderr, "Checking %d IPs...\n", len(ips))

	workers := 100
	timeout := 5 * time.Second
	jobs := make(chan string, 1000)
	results := make(chan HostInfo, 1000)

	var wg sync.WaitGroup
	var checked uint64

	// Workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				info := checkTLS(ip, timeout)
				atomic.AddUint64(&checked, 1)
				results <- info
			}
		}()
	}

	// Progress
	go func() {
		total := uint64(len(ips))
		for {
			time.Sleep(3 * time.Second)
			c := atomic.LoadUint64(&checked)
			fmt.Fprintf(os.Stderr, "Progress: %d/%d (%.1f%%)\n", c, total, float64(c)/float64(total)*100)
			if c >= total {
				break
			}
		}
	}()

	// Collector
	var all []HostInfo
	done := make(chan struct{})
	go func() {
		for info := range results {
			all = append(all, info)
		}
		close(done)
	}()

	// Feed jobs
	for _, ip := range ips {
		jobs <- ip
	}
	close(jobs)
	wg.Wait()
	close(results)
	<-done

	// Output JSON
	output, _ := json.MarshalIndent(all, "", "  ")
	fmt.Println(string(output))
}

func checkTLS(ip string, timeout time.Duration) HostInfo {
	info := HostInfo{IP: ip}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
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
