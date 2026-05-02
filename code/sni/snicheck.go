package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

type SNITestResult struct {
	WhitelistIP    string `json:"whitelist_ip"`
	BlockedSNI     string `json:"blocked_sni"`
	TestNoSNI      string `json:"test_no_sni"`
	TestBlockedSNI string `json:"test_blocked_sni"`
	TestWhiteSNI   string `json:"test_whitelist_sni"`
}

var whitelistIPs = []string{
	"77.88.55.242",  // ya.ru
	"87.240.132.78", // vk.com
	"217.20.147.1",  // mail.ru
}

var blockedSNIs = []string{
	"telegram.org",
	"twitter.com",
	"youtube.com",
	"google.com",
}

var whitelistSNIs = []string{
	"ya.ru",
	"vk.com",
	"mail.ru",
}

func main() {
	iface := "enp0s20u1"
	if len(os.Args) > 1 {
		iface = os.Args[1]
	}

	fmt.Fprintf(os.Stderr, "SNI blocking test via %s (curl)\n\n", iface)
	fmt.Fprintf(os.Stderr, "If blocked_sni=OK → IP-only blocking\n")
	fmt.Fprintf(os.Stderr, "If blocked_sni=FAIL → SNI filtering active\n\n")

	type job struct {
		idx        int
		ip         string
		blockedSNI string
		whiteSNI   string
	}

	var jobs []job
	for _, ip := range whitelistIPs {
		for i, blockedSNI := range blockedSNIs {
			whiteSNI := ""
			if i < len(whitelistSNIs) {
				whiteSNI = whitelistSNIs[i]
			}
			jobs = append(jobs, job{len(jobs), ip, blockedSNI, whiteSNI})
		}
	}

	results := make([]SNITestResult, len(jobs))
	var wg sync.WaitGroup

	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()

			r := SNITestResult{
				WhitelistIP: j.ip,
				BlockedSNI:  j.blockedSNI,
			}

			var inner sync.WaitGroup
			inner.Add(3)

			go func() {
				defer inner.Done()
				r.TestNoSNI = curlTest(j.ip, "", iface)
			}()

			go func() {
				defer inner.Done()
				r.TestBlockedSNI = curlTest(j.ip, j.blockedSNI, iface)
			}()

			go func() {
				defer inner.Done()
				if j.whiteSNI != "" {
					r.TestWhiteSNI = curlTest(j.ip, j.whiteSNI, iface)
				}
			}()

			inner.Wait()
			results[j.idx] = r

			fmt.Fprintf(os.Stderr, "[%s] SNI=%-15s no_sni:%-4s blocked:%-4s white:%-4s\n",
				j.ip, j.blockedSNI, r.TestNoSNI, r.TestBlockedSNI, r.TestWhiteSNI)
		}(j)
	}

	wg.Wait()

	output, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(output))
}

func curlTest(ip string, sni string, iface string) string {
	args := []string{
		"--interface", iface,
		"-k", "-s", "-o", "/dev/null",
		"-w", "%{http_code}",
		"--connect-timeout", "3",
	}

	var url string
	if sni != "" {
		args = append(args, "--resolve", fmt.Sprintf("%s:443:%s", sni, ip))
		url = fmt.Sprintf("https://%s/", sni)
	} else {
		url = fmt.Sprintf("https://%s/", ip)
	}

	args = append(args, url)

	cmd := exec.Command("curl", args...)
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
