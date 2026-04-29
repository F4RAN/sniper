package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/term"
)

type Config struct {
	Port       int
	Ports      string
	Workers    int
	Timeout    time.Duration
	File       string
	Output     string
	Verbose    bool
	Retries    int
	Quiet      bool
	Trace      bool
	TargetIP   string
	TargetFile string
}

type Job struct {
	Domain string
	Port   int
}

type portOutcome struct {
	Allowed bool
	Latency time.Duration
	IP      string
}

type Result struct {
	Domain  string
	IP      string
	Latency time.Duration
	Allowed bool
	Error   string
}

var (
	allowed    atomic.Int64
	failed     atomic.Int64
	doneProbes atomic.Int64
	queuedJobs atomic.Int64
)

func logf(colorize bool, level string, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "%s %s\n", formatLogLevel(level, colorize), fmt.Sprintf(format, args...))
}

func formatLogLevel(level string, colorize bool) string {
	tag := "[" + level + "]"
	if !colorize {
		return tag
	}

	switch level {
	case "INFO":
		return "\033[32m" + tag + "\033[0m"
	case "WARN":
		return "\033[33m" + tag + "\033[0m"
	case "ERR":
		return "\033[31m" + tag + "\033[0m"
	default:
		return tag
	}
}

func formatLatency(latencyMs int64, colorize bool) string {
	latency := fmt.Sprintf("%dms", latencyMs)
	if !colorize {
		return latency
	}

	switch {
	case latencyMs <= 2000:
		return "\033[32m" + latency + "\033[0m"
	case latencyMs <= 6000:
		return "\033[33m" + latency + "\033[0m"
	default:
		return "\033[31m" + latency + "\033[0m"
	}
}

var cdnRanges []struct {
	name string
	net  *net.IPNet
}

func init() {
	specs := []struct{ name, cidr string }{
		// Cloudflare
		{"Cloudflare", "173.245.48.0/20"},
		{"Cloudflare", "103.21.244.0/22"},
		{"Cloudflare", "103.22.200.0/22"},
		{"Cloudflare", "103.31.4.0/22"},
		{"Cloudflare", "104.16.0.0/13"},
		{"Cloudflare", "104.24.0.0/14"},
		{"Cloudflare", "108.162.192.0/18"},
		{"Cloudflare", "131.0.72.0/22"},
		{"Cloudflare", "141.101.64.0/18"},
		{"Cloudflare", "162.158.0.0/15"},
		{"Cloudflare", "172.64.0.0/13"},
		{"Cloudflare", "188.114.96.0/20"},
		{"Cloudflare", "190.93.240.0/20"},
		{"Cloudflare", "197.234.240.0/22"},
		{"Cloudflare", "198.41.128.0/17"},
		// Fastly
		{"Fastly", "23.235.32.0/20"},
		{"Fastly", "43.249.72.0/22"},
		{"Fastly", "103.244.50.0/24"},
		{"Fastly", "103.245.222.0/23"},
		{"Fastly", "103.245.224.0/24"},
		{"Fastly", "104.156.80.0/20"},
		{"Fastly", "140.248.64.0/18"},
		{"Fastly", "140.248.128.0/17"},
		{"Fastly", "146.75.0.0/17"},
		{"Fastly", "151.101.0.0/16"},
		{"Fastly", "157.52.64.0/18"},
		{"Fastly", "167.82.0.0/17"},
		{"Fastly", "167.82.128.0/20"},
		{"Fastly", "167.82.160.0/20"},
		{"Fastly", "167.82.224.0/20"},
		{"Fastly", "172.111.64.0/18"},
		{"Fastly", "185.31.16.0/22"},
		{"Fastly", "199.27.72.0/21"},
		{"Fastly", "199.232.0.0/16"},
		// AWS CloudFront
		{"CloudFront", "13.32.0.0/15"},
		{"CloudFront", "13.35.0.0/16"},
		{"CloudFront", "13.224.0.0/14"},
		{"CloudFront", "52.84.0.0/15"},
		{"CloudFront", "54.182.0.0/16"},
		{"CloudFront", "54.192.0.0/16"},
		{"CloudFront", "54.230.0.0/16"},
		{"CloudFront", "54.239.128.0/18"},
		{"CloudFront", "64.252.64.0/18"},
		{"CloudFront", "70.132.0.0/18"},
		{"CloudFront", "99.84.0.0/16"},
		{"CloudFront", "143.204.0.0/16"},
		{"CloudFront", "204.246.164.0/22"},
		{"CloudFront", "204.246.168.0/22"},
		{"CloudFront", "205.251.192.0/19"},
		{"CloudFront", "216.137.32.0/19"},
		// Akamai
		{"Akamai", "23.32.0.0/11"},
		{"Akamai", "23.64.0.0/14"},
		{"Akamai", "23.192.0.0/11"},
		{"Akamai", "96.6.0.0/15"},
		{"Akamai", "96.16.0.0/15"},
		{"Akamai", "104.64.0.0/10"},
		// Google
		{"Google", "8.8.8.0/24"},
		{"Google", "8.8.4.0/24"},
		{"Google", "66.102.0.0/20"},
		{"Google", "66.249.64.0/19"},
		{"Google", "72.14.192.0/18"},
		{"Google", "74.125.0.0/16"},
		{"Google", "108.177.8.0/21"},
		{"Google", "108.177.96.0/19"},
		{"Google", "130.211.0.0/22"},
		{"Google", "172.217.0.0/16"},
		{"Google", "172.253.0.0/17"},
		{"Google", "173.194.0.0/16"},
		{"Google", "209.85.128.0/17"},
		{"Google", "216.58.192.0/19"},
		{"Google", "216.239.32.0/19"},
		// Incapsula / Imperva
		{"Incapsula", "45.64.64.0/22"},
		{"Incapsula", "149.126.72.0/21"},
		{"Incapsula", "192.230.64.0/18"},
		{"Incapsula", "199.83.128.0/21"},
		{"Incapsula", "198.143.32.0/21"},
	}
	for _, s := range specs {
		_, ipNet, err := net.ParseCIDR(s.cidr)
		if err == nil {
			cdnRanges = append(cdnRanges, struct {
				name string
				net  *net.IPNet
			}{s.name, ipNet})
		}
	}
}

func detectCDN(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "-"
	}
	for _, e := range cdnRanges {
		if e.net.Contains(ip) {
			return e.name
		}
	}
	return "-"
}

func fileIsTerminal(file *os.File) bool {
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func normalizeIP(raw string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return "", fmt.Errorf("invalid IP %q", raw)
	}
	return ip.String(), nil
}

func loadOverrideIPs(targetIP, targetFile string) ([]string, error) {
	if targetIP != "" && targetFile != "" {
		return nil, fmt.Errorf("cannot use -target and -target-file together")
	}
	if targetIP == "" && targetFile == "" {
		return nil, nil
	}

	var ips []string
	seen := make(map[string]struct{})
	addIP := func(raw string) error {
		ip, err := normalizeIP(raw)
		if err != nil {
			return err
		}
		if _, ok := seen[ip]; ok {
			return nil
		}
		seen[ip] = struct{}{}
		ips = append(ips, ip)
		return nil
	}

	if targetIP != "" {
		if err := addIP(targetIP); err != nil {
			return nil, fmt.Errorf("invalid -target: %w", err)
		}
		return ips, nil
	}

	inFile, err := os.Open(targetFile)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", targetFile, err)
	}
	defer inFile.Close()

	scanner := bufio.NewScanner(inFile)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if err := addIP(line); err != nil {
			return nil, fmt.Errorf("invalid IP in %s at line %d: %w", targetFile, lineNo, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", targetFile, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPs found in %s", targetFile)
	}
	return ips, nil
}

func parsePorts(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("no ports specified")
	}
	var ports []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", p)
		}
		if n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port: %d", n)
		}
		ports = append(ports, n)
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports specified")
	}
	return ports, nil
}

// resolvePorts uses -ports when non-empty; otherwise the single -port value (backward compatible).
func resolvePorts(portsFlag string, legacyPort int) ([]int, error) {
	if strings.TrimSpace(portsFlag) != "" {
		return parsePorts(portsFlag)
	}
	if legacyPort < 1 || legacyPort > 65535 {
		return nil, fmt.Errorf("invalid port: %d", legacyPort)
	}
	return []int{legacyPort}, nil
}

func resolveIPs(ctx context.Context, domain string, timeout time.Duration) ([]string, error) {
	resolver := &net.Resolver{}
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addrs, err := resolver.LookupHost(lookupCtx, domain)
	if err != nil {
		return nil, fmt.Errorf("dns failed: %w", err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("dns failed: no addresses returned")
	}
	return addrs, nil
}

func candidateIPs(ctx context.Context, domain string, timeout time.Duration, overrideIPs []string) ([]string, error) {
	if len(overrideIPs) > 0 {
		return overrideIPs, nil
	}
	return resolveIPs(ctx, domain, timeout)
}

func probe(ctx context.Context, domain string, port int, timeout time.Duration, retries int, overrideIPs []string) Result {
	ips, err := candidateIPs(ctx, domain, timeout, overrideIPs)
	if err != nil {
		return Result{Domain: domain, IP: "?", Allowed: false, Error: err.Error()}
	}

	var lastErr error
	lastIP := "?"
	for _, ip := range ips {
		addr := net.JoinHostPort(ip, strconv.Itoa(port))
		lastIP = ip

		for i := 0; i <= retries; i++ {
			if ctx.Err() != nil {
				return Result{Domain: domain, IP: lastIP, Allowed: false, Error: "cancelled"}
			}

			// TCP dial with context timeout
			dialCtx, cancel := context.WithTimeout(ctx, timeout)
			start := time.Now()
			rawConn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
			cancel()

			if err != nil {
				lastErr = err
				if i < retries {
					select {
					case <-ctx.Done():
						return Result{Domain: domain, IP: lastIP, Allowed: false, Error: "cancelled"}
					case <-time.After(150 * time.Millisecond):
					}
				}
				continue
			}

			// TLS handshake with hard deadline
			tlsConn := tls.Client(rawConn, &tls.Config{
				ServerName:         domain,
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			})
			tlsConn.SetDeadline(time.Now().Add(timeout))
			err = tlsConn.Handshake()
			tlsConn.Close()

			if err == nil {
				return Result{Domain: domain, IP: ip, Allowed: true, Latency: time.Since(start)}
			}

			lastErr = err
			if i < retries {
				select {
				case <-ctx.Done():
					return Result{Domain: domain, IP: lastIP, Allowed: false, Error: "cancelled"}
				case <-time.After(150 * time.Millisecond):
				}
			}
		}
	}

	return Result{Domain: domain, IP: lastIP, Allowed: false, Error: lastErr.Error()}
}

func formatMark(ok bool, colorize bool) string {
	const (
		markOK   = "\u2713"
		markFail = "\u2717"
	)
	if !colorize {
		if ok {
			return markOK
		}
		return markFail
	}
	if ok {
		return "\033[32m" + markOK + "\033[0m"
	}
	return "\033[31m" + markFail + "\033[0m"
}

func pickDisplayIP(portOrder []int, perPort map[int]portOutcome) string {
	for _, p := range portOrder {
		if o, ok := perPort[p]; ok && o.IP != "" && o.IP != "?" {
			return o.IP
		}
	}
	return "?"
}

func maxAllowedLatency(perPort map[int]portOutcome, portOrder []int) (time.Duration, bool) {
	var max time.Duration
	var any bool
	for _, p := range portOrder {
		o, ok := perPort[p]
		if !ok || !o.Allowed {
			continue
		}
		any = true
		if o.Latency > max {
			max = o.Latency
		}
	}
	return max, any
}

func formatGroupedLine(domain string, probePorts []int, perPort map[int]portOutcome, colorize bool, verbose bool) string {
	if perPort == nil {
		perPort = map[int]portOutcome{}
	}
	anyAllowed := false
	for _, p := range probePorts {
		if o, ok := perPort[p]; ok && o.Allowed {
			anyAllowed = true
			break
		}
	}
	if !anyAllowed && !verbose {
		return ""
	}

	ip := pickDisplayIP(probePorts, perPort)
	latStr := "-"
	if maxLat, ok := maxAllowedLatency(perPort, probePorts); ok {
		latStr = formatLatency(maxLat.Milliseconds(), colorize)
	}

	cdn := detectCDN(ip)

	var b strings.Builder
	for i, p := range probePorts {
		if i > 0 {
			b.WriteString("  ")
		}
		o, ok := perPort[p]
		allowed := ok && o.Allowed
		fmt.Fprintf(&b, "%d %s", p, formatMark(allowed, colorize))
	}

	return fmt.Sprintf("%-30s %-18s %-12s %s  %s", domain, ip, cdn, latStr, b.String())
}

// formatTraceProbeLine matches formatGroupedLine columns for a single completed probe (stderr stream).
func formatTraceProbeLine(domain string, port int, r Result, colorize bool) string {
	ip := r.IP
	if ip == "" {
		ip = "?"
	}
	latStr := "-"
	if r.Allowed {
		latStr = formatLatency(r.Latency.Milliseconds(), colorize)
	}
	cdn := detectCDN(ip)
	portMark := fmt.Sprintf("%d %s", port, formatMark(r.Allowed, colorize))
	return fmt.Sprintf("%-30s %-18s %-12s %s  %s", domain, ip, cdn, latStr, portMark)
}

func formatProgressBar(done, total int64, width int) string {
	if total <= 0 || width <= 0 {
		return "[]"
	}
	if done > total {
		done = total
	}
	filled := int(float64(width) * float64(done) / float64(total))
	if filled > width {
		filled = width
	}
	var b strings.Builder
	b.Grow(width + 2)
	b.WriteByte('[')
	for i := 0; i < width; i++ {
		if i < filled {
			b.WriteByte('=')
		} else {
			b.WriteByte(' ')
		}
	}
	b.WriteByte(']')
	return b.String()
}

// paintProgressLineInner draws the progress bar. With useStickyRow and a valid terminal size, it is
// painted on the bottom row so trace lines can scroll above. Caller must hold stderrMu.
func paintProgressLineInner(useStickyRow bool) {
	n := doneProbes.Load()
	denom := queuedJobs.Load()
	if denom == 0 {
		denom = 1
	}
	bar := formatProgressBar(n, denom, 20)
	if useStickyRow {
		if _, h, err := term.GetSize(int(os.Stderr.Fd())); err == nil && h > 0 {
			// ESC 7 / ESC 8 (DECSC/DECRC): \033[s / \033[u break on many macOS terminals.
			fmt.Fprint(os.Stderr, "\0337")
			fmt.Fprintf(os.Stderr, "\033[%d;1H\033[K%s %d/%d", h, bar, n, denom)
			fmt.Fprint(os.Stderr, "\0338")
			return
		}
	}
	fmt.Fprintf(os.Stderr, "\r\033[K%s %d/%d", bar, n, denom)
}

// clearProgressLineInner clears the progress bar line (sticky bottom or CR line). Caller must hold stderrMu.
func clearProgressLineInner(useStickyRow bool) {
	if useStickyRow {
		if _, h, err := term.GetSize(int(os.Stderr.Fd())); err == nil && h > 0 {
			fmt.Fprint(os.Stderr, "\0337")
			fmt.Fprintf(os.Stderr, "\033[%d;1H\033[K", h)
			fmt.Fprint(os.Stderr, "\0338")
			return
		}
	}
	fmt.Fprint(os.Stderr, "\r\033[K")
}

func main() {
	cfg := Config{}
	logColorize := fileIsTerminal(os.Stderr)
	flag.StringVar(&cfg.File, "f", "", "Input file with domains (one per line)")
	flag.IntVar(&cfg.Port, "port", 443, "TLS port to probe (used when -ports is not set)")
	flag.StringVar(&cfg.Ports, "ports", "", "Comma-separated TLS ports (e.g. 443,2053); overrides -port when set")
	flag.IntVar(&cfg.Workers, "workers", 200, "Concurrent workers")
	flag.DurationVar(&cfg.Timeout, "timeout", 2*time.Second, "Per DNS/dial/handshake attempt timeout")
	flag.StringVar(&cfg.Output, "output", "", "Save results to file (default: stdout)")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Include domains where every port failed (hidden by default)")
	flag.IntVar(&cfg.Retries, "retries", 0, "Retries on failure")
	flag.BoolVar(&cfg.Quiet, "q", false, "Quiet mode (hide start/end scan logs and progress)")
	flag.BoolVar(&cfg.Trace, "trace", false, "Stream each finished probe to stderr (same columns as results)")
	flag.StringVar(&cfg.TargetIP, "target", "", "Override DNS and probe this IP for every domain")
	flag.StringVar(&cfg.TargetFile, "target-file", "", "Override DNS and probe IPs from this file for every domain")
	flag.Parse()

	if cfg.File == "" {
		logf(logColorize, "ERR", "usage: sniper -f domains.txt [options]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	ports, err := resolvePorts(cfg.Ports, cfg.Port)
	if err != nil {
		logf(logColorize, "ERR", "%v", err)
		os.Exit(1)
	}

	overrideIPs, err := loadOverrideIPs(cfg.TargetIP, cfg.TargetFile)
	if err != nil {
		logf(logColorize, "ERR", "%v", err)
		os.Exit(1)
	}

	inFile, err := os.Open(cfg.File)
	if err != nil {
		logf(logColorize, "ERR", "cannot open %s: %v", cfg.File, err)
		os.Exit(1)
	}
	defer inFile.Close()

	outWriter := bufio.NewWriter(os.Stdout)
	outputFile := os.Stdout
	var outFile *os.File
	if cfg.Output != "" {
		f, err := os.Create(cfg.Output)
		if err != nil {
			logf(logColorize, "ERR", "%v", err)
			os.Exit(1)
		}
		outFile = f
		outputFile = f
		outWriter = bufio.NewWriter(f)
	}
	outputColorize := fileIsTerminal(outputFile)

	cleanupOutput := func() {
		outWriter.Flush()
		if outFile != nil {
			outFile.Close()
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	jobs := make(chan Job, cfg.Workers*2)
	lines := make(chan string, cfg.Workers*4)
	var aggMu sync.Mutex
	aggregated := make(map[string]map[int]portOutcome)
	var wg sync.WaitGroup
	var writeWG sync.WaitGroup

	writeWG.Add(1)
	go func() {
		defer writeWG.Done()

		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case line, ok := <-lines:
				if !ok {
					outWriter.Flush()
					return
				}
				fmt.Fprintln(outWriter, line)
			case <-ticker.C:
				outWriter.Flush()
			}
		}
	}()

	writeLine := func(format string, args ...any) {
		lines <- fmt.Sprintf(format, args...)
	}

	if !cfg.Quiet {
		logf(logColorize, "INFO", "starting workers=%d timeout=%s", cfg.Workers, cfg.Timeout)
	}

	doneProbes.Store(0)
	queuedJobs.Store(0)

	stderrTTY := fileIsTerminal(os.Stderr)
	useStickyFooter := stderrTTY
	var stderrMu sync.Mutex

	// Rows 1..h-1 scroll; row h is reserved for the progress footer so traces never share that line.
	var resetScrollRegion func()
	if useStickyFooter && !cfg.Quiet {
		if _, h, err := term.GetSize(int(os.Stderr.Fd())); err == nil && h > 2 {
			fmt.Fprintf(os.Stderr, "\033[1;%dr", h-1)
			resetScrollRegion = func() { fmt.Fprint(os.Stderr, "\033[r") }
		}
	}

	stopProgress := make(chan struct{})
	if !cfg.Quiet {
		go func() {
			ticker := time.NewTicker(150 * time.Millisecond)
			defer ticker.Stop()
			var lastN, lastD int64 = -1, -1
			for {
				select {
				case <-stopProgress:
					return
				case <-ticker.C:
					n := doneProbes.Load()
					denom := queuedJobs.Load()
					if denom == 0 {
						denom = 1
					}
					if !stderrTTY && n == lastN && denom == lastD {
						continue
					}
					lastN, lastD = n, denom
					stderrMu.Lock()
					paintProgressLineInner(useStickyFooter)
					stderrMu.Unlock()
				}
			}
		}()
	}

	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				r := probe(ctx, job.Domain, job.Port, cfg.Timeout, cfg.Retries, overrideIPs)

				if r.Allowed {
					allowed.Add(1)
				} else {
					failed.Add(1)
				}

				aggMu.Lock()
				m := aggregated[job.Domain]
				if m == nil {
					m = make(map[int]portOutcome)
					aggregated[job.Domain] = m
				}
				m[job.Port] = portOutcome{
					Allowed: r.Allowed,
					Latency: r.Latency,
					IP:      r.IP,
				}
				aggMu.Unlock()

				doneProbes.Add(1)

				if cfg.Trace {
					stderrMu.Lock()
					fmt.Fprintln(os.Stderr, formatTraceProbeLine(job.Domain, job.Port, r, outputColorize))
					stderrMu.Unlock()
				}
			}
		}()
	}

	var domainOrder []string
	seenDomain := make(map[string]struct{})
	var total int64
	scanner := bufio.NewScanner(inFile)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" {
			continue
		}
		if _, ok := seenDomain[domain]; !ok {
			seenDomain[domain] = struct{}{}
			domainOrder = append(domainOrder, domain)
		}
		total += int64(len(ports))
		for _, port := range ports {
			jobs <- Job{Domain: domain, Port: port}
			queuedJobs.Add(1)
		}
	}
	scanErr := scanner.Err()
	close(jobs)

	wg.Wait()
	close(stopProgress)
	if !cfg.Quiet && total > 0 && stderrTTY {
		stderrMu.Lock()
		clearProgressLineInner(useStickyFooter)
		stderrMu.Unlock()
	}
	if resetScrollRegion != nil {
		resetScrollRegion()
		resetScrollRegion = nil
	}

	for _, domain := range domainOrder {
		line := formatGroupedLine(domain, ports, aggregated[domain], outputColorize, cfg.Verbose)
		if line != "" {
			writeLine("%s", line)
		}
	}

	close(lines)
	writeWG.Wait()

	if scanErr != nil {
		cleanupOutput()
		if resetScrollRegion != nil {
			resetScrollRegion()
		}
		logf(logColorize, "ERR", "cannot read %s: %v", cfg.File, scanErr)
		os.Exit(1)
	}

	if !cfg.Quiet {
		level := "INFO"
		if allowed.Load() == 0 {
			level = "WARN"
		}
		logf(logColorize, level, "completed allowed=%d blocked=%d total=%d", allowed.Load(), failed.Load(), total)
	}
	cleanupOutput()
}
