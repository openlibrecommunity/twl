package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"golang.org/x/net/proxy"
)

const (
	Token       = "8659094651:AAGt_Zj5tD-pQIGZrsOEqxiNqAUpVnzc85o"
	ProxyAddr   = "127.0.0.1:8888"
	WLFile      = "out/beget_up.txt"
	SubnetsFile = "selectel_up.tx"
	Interface   = "enp0s20u1"
)

type ScanResult struct {
	Port    int
	Status  string
	Elapsed time.Duration
}

type HTTPResult struct {
	Available    bool
	StatusCode   int
	TTL          int
	ResponseTime time.Duration
	Server       string
	ContentLen   int64
	TLSVersion   string
	Error        string
}

var localAddr *net.TCPAddr

func main() {
	log.Println("[INIT] Starting bot...")

	// Get interface IP for binding
	iface, err := net.InterfaceByName(Interface)
	if err != nil {
		log.Fatalf("[FATAL] Interface %s not found: %v", Interface, err)
	}
	addrs, err := iface.Addrs()
	if err != nil || len(addrs) == 0 {
		log.Fatalf("[FATAL] Failed to get IP for interface %s: %v", Interface, err)
	}
	var ifaceIP net.IP
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			ifaceIP = ipnet.IP
			break
		}
	}
	if ifaceIP == nil {
		log.Fatalf("[FATAL] IPv4 address not found on interface %s", Interface)
	}
	localAddr = &net.TCPAddr{IP: ifaceIP}
	log.Printf("[INIT] Using interface %s with IP %s", Interface, ifaceIP)

	log.Printf("[INIT] Connecting to SOCKS5 proxy: %s", ProxyAddr)
	dialer, err := proxy.SOCKS5("tcp", ProxyAddr, nil, proxy.Direct)
	if err != nil {
		log.Fatalf("[FATAL] Proxy error: %v", err)
	}
	log.Println("[INIT] Proxy connected")

	httpTransport := &http.Transport{
		Dial: dialer.Dial,
	}
	httpClient := &http.Client{
		Transport: httpTransport,
		Timeout:   30 * time.Second,
	}

	log.Println("[INIT] Initializing Telegram Bot API...")
	bot, err := tgbotapi.NewBotAPIWithClient(Token, tgbotapi.APIEndpoint, httpClient)
	if err != nil {
		log.Fatalf("[FATAL] Bot init failed: %v", err)
	}

	bot.Debug = false
	log.Printf("[INIT] Bot authorized: @%s", bot.Self.UserName)

	log.Printf("[INIT] Loading subnets from %s...", SubnetsFile)
	subnets := loadSubnets(SubnetsFile)
	log.Printf("[INIT] Loaded %d subnets", len(subnets))

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := bot.GetUpdatesChan(u)

	log.Println("[INIT] Bot started, waiting for messages...")

	for update := range updates {
		if update.Message == nil {
			continue
		}

		input := strings.TrimSpace(update.Message.Text)
		chatID := update.Message.Chat.ID
		userName := update.Message.From.UserName

		log.Printf("[MSG] Message from @%s: %s", userName, input)

		ip := net.ParseIP(input)
		if ip == nil {
			log.Printf("[ERR] Invalid IP from @%s: %s", userName, input)
			bot.Send(tgbotapi.NewMessage(chatID, "Ошибка: Неверный формат IPv4 адреса."))
			continue
		}

		if ip.IsPrivate() {
			log.Printf("[ERR] Private IP from @%s: %s", userName, input)
			bot.Send(tgbotapi.NewMessage(chatID, "Ошибка: Это приватный адрес (RFC 1918). Анализ отменен."))
			continue
		}

		log.Printf("[SCAN] Starting analysis %s for @%s", input, userName)
		go processTarget(bot, chatID, input, subnets, userName)
	}
}

func loadSubnets(filename string) []*net.IPNet {
	var subnets []*net.IPNet

	file, err := os.Open(filename)
	if err != nil {
		log.Printf("[WARN] Не удалось открыть файл подсетей: %v", err)
		return subnets
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		_, network, err := net.ParseCIDR(line)
		if err != nil {
			log.Printf("[WARN] Невалидная подсеть: %s", line)
			continue
		}
		subnets = append(subnets, network)
	}

	return subnets
}

func processTarget(bot *tgbotapi.BotAPI, chatID int64, targetIP string, subnets []*net.IPNet, userName string) {
	startTime := time.Now()

	// 1. Проверка в белом списке
	log.Printf("[%s] Проверка в белом списке...", targetIP)
	inWhitelist := checkWhitelist(targetIP)
	if inWhitelist {
		log.Printf("[%s] IP найден в белом списке", targetIP)
	} else {
		log.Printf("[%s] IP НЕ найден в белом списке", targetIP)
	}

	// 2. Проверка подсети
	log.Printf("[%s] Проверка подсети в базе...", targetIP)
	inSubnet, matchedSubnet := checkSubnet(targetIP, subnets)
	if inSubnet {
		log.Printf("[%s] Подсеть найдена: %s", targetIP, matchedSubnet)
	} else {
		log.Printf("[%s] Подсеть НЕ найдена в базе", targetIP)
	}

	// 3. ICMP ping
	log.Printf("[%s] Отправка ICMP ping через %s...", targetIP, Interface)
	latency, ttl := executePing(targetIP)
	log.Printf("[%s] Ping: latency=%s, TTL=%d", targetIP, latency, ttl)

	// 4. TCP сканирование (параллельно)
	ports := []int{22, 80, 443, 8080, 3389, 53}
	log.Printf("[%s] Сканирование TCP портов: %v", targetIP, ports)
	scanResults := scanPortsParallel(targetIP, ports)
	for _, r := range scanResults {
		log.Printf("[%s] Порт %d: %s (%v)", targetIP, r.Port, r.Status, r.Elapsed.Truncate(time.Millisecond))
	}

	// 5. HTTP/HTTPS проверка (параллельно)
	log.Printf("[%s] Проверка HTTP/HTTPS...", targetIP)
	var httpResult, httpsResult HTTPResult
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		httpResult = checkHTTP(targetIP, false)
		log.Printf("[%s] HTTP: code=%d, ttl=%d, time=%v", targetIP, httpResult.StatusCode, httpResult.TTL, httpResult.ResponseTime.Truncate(time.Millisecond))
	}()
	go func() {
		defer wg.Done()
		httpsResult = checkHTTP(targetIP, true)
		log.Printf("[%s] HTTPS: code=%d, ttl=%d, time=%v, tls=%s", targetIP, httpsResult.StatusCode, httpsResult.TTL, httpsResult.ResponseTime.Truncate(time.Millisecond), httpsResult.TLSVersion)
	}()
	wg.Wait()

	// 6. Reverse DNS
	log.Printf("[%s] Reverse DNS lookup...", targetIP)
	rdns := reverseDNS(targetIP)
	log.Printf("[%s] RDNS: %s", targetIP, rdns)

	elapsed := time.Since(startTime)
	log.Printf("[%s] Анализ завершен за %v", targetIP, elapsed.Truncate(time.Millisecond))

	output := formatReport(targetIP, inWhitelist, inSubnet, matchedSubnet, latency, ttl, scanResults, httpResult, httpsResult, rdns, elapsed)

	msg := tgbotapi.NewMessage(chatID, output)
	msg.ParseMode = "HTML"
	_, err := bot.Send(msg)
	if err != nil {
		log.Printf("[ERR] Ошибка отправки @%s: %v", userName, err)
	} else {
		log.Printf("[%s] Отчет отправлен @%s", targetIP, userName)
	}
}

func checkWhitelist(ip string) bool {
	file, err := os.Open(WLFile)
	if err != nil {
		log.Printf("[WARN] Не удалось открыть %s: %v", WLFile, err)
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, ip) {
			return true
		}
	}
	return false
}

func checkSubnet(ip string, subnets []*net.IPNet) (bool, string) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, ""
	}

	for _, subnet := range subnets {
		if subnet.Contains(parsedIP) {
			return true, subnet.String()
		}
	}
	return false, ""
}

func executePing(ip string) (string, int) {
	cmd := exec.Command("ping", "-I", Interface, "-c", "1", "-W", "2", ip)
	out, err := cmd.CombinedOutput()
	sOut := string(out)

	if err != nil {
		log.Printf("[%s] Ping ошибка: %v", ip, err)
	}

	reTime := regexp.MustCompile(`time=([0-9.]+) ms`)
	reTTL := regexp.MustCompile(`ttl=([0-9]+)`)

	mTime := reTime.FindStringSubmatch(sOut)
	mTTL := reTTL.FindStringSubmatch(sOut)

	latency := "Н/Д"
	if len(mTime) > 1 {
		latency = mTime[1] + " мс"
	}

	ttl := 0
	if len(mTTL) > 1 {
		fmt.Sscanf(mTTL[1], "%d", &ttl)
	}

	if strings.Contains(sOut, "100% packet loss") || latency == "Н/Д" {
		latency = "ТАЙМАУТ"
	}

	if ttl == 0 {
		ttl = fallbackTTL(ip)
		if ttl > 0 {
			log.Printf("[%s] TTL получен через fallback: %d", ip, ttl)
		}
	}

	return latency, ttl
}

func fallbackTTL(ip string) int {
	// 1) hping3 ICMP через default route
	if t := hping3TTL(ip, "-1", 0); t > 0 {
		return t
	}
	// 2) hping3 SYN на популярные порты через default route
	for _, p := range []int{443, 80, 53, 22} {
		if t := hping3TTL(ip, "-S", p); t > 0 {
			return t
		}
	}
	return 0
}

func hping3TTL(ip string, mode string, port int) int {
	args := []string{"-n", "hping3", mode, "-c", "1", "-W", "1"}
	if port > 0 {
		args = append(args, "-p", fmt.Sprintf("%d", port))
	}
	args = append(args, ip)
	cmd := exec.Command("sudo", args...)
	out, _ := cmd.CombinedOutput()
	re := regexp.MustCompile(`ttl=(\d+)`)
	m := re.FindStringSubmatch(string(out))
	if len(m) > 1 {
		var ttl int
		fmt.Sscanf(m[1], "%d", &ttl)
		return ttl
	}
	return 0
}

func scanPortsParallel(ip string, ports []int) []ScanResult {
	results := make([]ScanResult, len(ports))
	var wg sync.WaitGroup

	for i, port := range ports {
		wg.Add(1)
		go func(idx, p int) {
			defer wg.Done()
			status, elapsed := probeTCP(ip, p)
			results[idx] = ScanResult{Port: p, Status: status, Elapsed: elapsed}
		}(i, port)
	}

	wg.Wait()
	return results
}

func probeTCP(ip string, port int) (string, time.Duration) {
	start := time.Now()

	// Use curl with interface binding for TCP check
	cmd := exec.Command("curl", "--interface", Interface, "-s", "-o", "/dev/null",
		"--connect-timeout", "2", "--max-time", "2",
		fmt.Sprintf("http://%s:%d/", ip, port))
	err := cmd.Run()
	elapsed := time.Since(start)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			switch exitErr.ExitCode() {
			case 7: // Connection refused or failed
				if elapsed < 500*time.Millisecond {
					return "ЗАКРЫТ", elapsed
				}
				return "ФИЛЬТР", elapsed
			case 28: // Timeout
				return "ФИЛЬТР", elapsed
			}
		}
		return "ФИЛЬТР", elapsed
	}
	return "ОТКРЫТ", elapsed
}

func checkHTTP(ip string, https bool) HTTPResult {
	result := HTTPResult{}

	scheme := "http"
	port := 80
	if https {
		scheme = "https"
		port = 443
	}

	url := fmt.Sprintf("%s://%s/", scheme, ip)

	// Get TTL via hping3
	result.TTL = getTCPTTL(ip, port)

	// Separator for parsing
	const sep = "###CURL_STATS###"

	start := time.Now()
	args := []string{
		"--interface", Interface,
		"-s",
		"-o", "/dev/null",
		"-w", sep + "%{http_code}|%{size_download}|%{ssl_version}",
		"--connect-timeout", "5",
		"--max-time", "5",
		"-k",
		"-D", "-",
		url,
	}
	cmd := exec.Command("curl", args...)
	out, err := cmd.Output()
	result.ResponseTime = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		return result
	}

	output := string(out)

	// Split: headers before sep, stats after
	idx := strings.Index(output, sep)
	if idx >= 0 {
		headers := output[:idx]
		stats := output[idx+len(sep):]

		parts := strings.Split(stats, "|")
		if len(parts) >= 3 {
			fmt.Sscanf(parts[0], "%d", &result.StatusCode)
			fmt.Sscanf(parts[1], "%d", &result.ContentLen)
			if https && parts[2] != "" {
				result.TLSVersion = parts[2]
			}
		}

		reServer := regexp.MustCompile(`(?i)Server:\s*(.+)`)
		if m := reServer.FindStringSubmatch(headers); len(m) > 1 {
			result.Server = strings.TrimSpace(m[1])
		}
	}

	if result.StatusCode > 0 {
		result.Available = true
	}

	return result
}

func getTCPTTL(ip string, port int) int {
	// hping3 без интерфейса - через дефолтный маршрут для получения TTL
	cmd := exec.Command("sudo", "-n", "hping3", "-S", "-p", fmt.Sprintf("%d", port), "-c", "1", ip)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0
	}

	re := regexp.MustCompile(`ttl=(\d+)`)
	match := re.FindStringSubmatch(string(out))
	if len(match) > 1 {
		var ttl int
		fmt.Sscanf(match[1], "%d", &ttl)
		return ttl
	}
	return 0
}

func reverseDNS(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return "Н/Д"
	}
	return strings.TrimSuffix(names[0], ".")
}

func calculateHops(ttl int) int {
	if ttl <= 0 {
		return 0
	}
	if ttl <= 64 {
		return 64 - ttl
	}
	if ttl <= 128 {
		return 128 - ttl
	}
	return 255 - ttl
}

func formatReport(ip string, wl bool, inSubnet bool, matchedSubnet string, lat string, ttl int, tcpResults []ScanResult, httpRes, httpsRes HTTPResult, rdns string, totalTime time.Duration) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("<b>🔍 Анализ: %s</b>\n\n", ip))

	// Reverse DNS
	sb.WriteString(fmt.Sprintf("<b>📛 Имя:</b> %s\n\n", rdns))

	// База данных
	sb.WriteString("<b>📋 База данных</b>\n")
	if wl {
		sb.WriteString("├ Белый список: ✅ Найден\n")
	} else {
		sb.WriteString("├ Белый список: ❌ Нет\n")
	}
	if inSubnet {
		sb.WriteString(fmt.Sprintf("└ Подсеть: ✅ %s\n", matchedSubnet))
	} else {
		sb.WriteString("└ Подсеть: ❌ Не найдена\n")
	}

	// ICMP
	sb.WriteString("\n<b>📡 ICMP Ping</b>\n")
	sb.WriteString(fmt.Sprintf("├ Задержка: %s\n", lat))
	sb.WriteString(fmt.Sprintf("├ TTL: %d\n", ttl))
	sb.WriteString(fmt.Sprintf("└ Хопов: ~%d\n", calculateHops(ttl)))

	// TCP порты
	sb.WriteString("\n<b>🔌 TCP порты</b>\n")
	for i, r := range tcpResults {
		prefix := "├"
		if i == len(tcpResults)-1 {
			prefix = "└"
		}
		statusIcon := "⚪"
		switch r.Status {
		case "ОТКРЫТ":
			statusIcon = "🟢"
		case "ЗАКРЫТ":
			statusIcon = "🔴"
		case "ФИЛЬТР":
			statusIcon = "🟡"
		}
		sb.WriteString(fmt.Sprintf("%s %d: %s %s (%v)\n", prefix, r.Port, statusIcon, r.Status, r.Elapsed.Truncate(time.Millisecond)))
	}

	// HTTP
	sb.WriteString("\n<b>🌐 HTTP (80)</b>\n")
	if httpRes.Available {
		sb.WriteString(fmt.Sprintf("├ Статус: %d\n", httpRes.StatusCode))
		sb.WriteString(fmt.Sprintf("├ Время: %v\n", httpRes.ResponseTime.Truncate(time.Millisecond)))
		if httpRes.TTL > 0 {
			sb.WriteString(fmt.Sprintf("├ TTL: %d (хопов: ~%d)\n", httpRes.TTL, calculateHops(httpRes.TTL)))
		}
		if httpRes.Server != "" {
			sb.WriteString(fmt.Sprintf("├ Сервер: %s\n", httpRes.Server))
		}
		if httpRes.ContentLen > 0 {
			sb.WriteString(fmt.Sprintf("└ Размер: %d байт\n", httpRes.ContentLen))
		} else {
			sb.WriteString("└ Размер: Н/Д\n")
		}
	} else {
		errMsg := "Недоступен"
		if strings.Contains(httpRes.Error, "timeout") {
			errMsg = "Таймаут"
		} else if strings.Contains(httpRes.Error, "refused") {
			errMsg = "Отклонено"
		} else if strings.Contains(httpRes.Error, "reset") {
			errMsg = "Сброс соединения"
		}
		sb.WriteString(fmt.Sprintf("└ ❌ %s\n", errMsg))
	}

	// HTTPS
	sb.WriteString("\n<b>🔒 HTTPS (443)</b>\n")
	if httpsRes.Available {
		sb.WriteString(fmt.Sprintf("├ Статус: %d\n", httpsRes.StatusCode))
		sb.WriteString(fmt.Sprintf("├ Время: %v\n", httpsRes.ResponseTime.Truncate(time.Millisecond)))
		if httpsRes.TTL > 0 {
			sb.WriteString(fmt.Sprintf("├ TTL: %d (хопов: ~%d)\n", httpsRes.TTL, calculateHops(httpsRes.TTL)))
		}
		if httpsRes.TLSVersion != "" {
			sb.WriteString(fmt.Sprintf("├ TLS: %s\n", httpsRes.TLSVersion))
		}
		if httpsRes.Server != "" {
			sb.WriteString(fmt.Sprintf("├ Сервер: %s\n", httpsRes.Server))
		}
		if httpsRes.ContentLen > 0 {
			sb.WriteString(fmt.Sprintf("└ Размер: %d байт\n", httpsRes.ContentLen))
		} else {
			sb.WriteString("└ Размер: Н/Д\n")
		}
	} else {
		errMsg := "Недоступен"
		if strings.Contains(httpsRes.Error, "timeout") {
			errMsg = "Таймаут"
		} else if strings.Contains(httpsRes.Error, "refused") {
			errMsg = "Отклонено"
		} else if strings.Contains(httpsRes.Error, "reset") {
			errMsg = "Сброс соединения"
		} else if strings.Contains(httpsRes.Error, "certificate") {
			errMsg = "Ошибка сертификата"
		}
		sb.WriteString(fmt.Sprintf("└ ❌ %s\n", errMsg))
	}

	// Вердикт
	sb.WriteString("\n<b>📊 Вердикт:</b> ")
	if ttl >= 62 && ttl <= 64 {
		sb.WriteString("⚠️ Высокий TTL — возможно ТСПУ/DPI")
	} else if inSubnet && ttl > 0 {
		sb.WriteString("✅ Доступен, подсеть в базе")
	} else if wl && ttl > 0 {
		sb.WriteString("✅ Доступен, IP в белом списке")
	} else if ttl > 0 {
		sb.WriteString("⚠️ Доступен, но подсеть НЕ в базе")
	} else {
		sb.WriteString("❌ Недоступен")
	}

	sb.WriteString(fmt.Sprintf("\n\n<i>⏱ Время анализа: %v</i>", totalTime.Truncate(time.Millisecond)))

	return sb.String()
}
