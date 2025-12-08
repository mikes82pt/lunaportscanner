package main

import (
    "bufio"
    "flag"
    "fmt"
    "net"
    "os"
    "strings"
    "sync"
    "syscall"
    "time"
)

const Version = "v4.0 (Go Rewrite)"

// ------------------------------------------------------------
// Port Parsing
// ------------------------------------------------------------

func parsePorts(s string) []int {
    parts := strings.Split(s, ",")
    portSet := make(map[int]bool)

    for _, part := range parts {
        part = strings.TrimSpace(part)
        if part == "" {
            continue
        }

        if strings.Contains(part, "-") {
            r := strings.Split(part, "-")
            if len(r) != 2 {
                continue
            }
            var start, end int
            _, err1 := fmt.Sscanf(r[0], "%d", &start)
            _, err2 := fmt.Sscanf(r[1], "%d", &end)
            if err1 != nil || err2 != nil || start > end {
                continue
            }
            for p := start; p <= end; p++ {
                if p > 0 && p <= 65535 {
                    portSet[p] = true
                }
            }
        } else {
            var p int
            if _, err := fmt.Sscanf(part, "%d", &p); err == nil {
                if p > 0 && p <= 65535 {
                    portSet[p] = true
                }
            }
        }
    }

    ports := make([]int, 0, len(portSet))
    for p := range portSet {
        ports = append(ports, p)
    }

    for i := range ports {
        for j := i + 1; j < len(ports); j++ {
            if ports[j] < ports[i] {
                ports[j], ports[i] = ports[i], ports[j]
            }
        }
    }
    return ports
}

// ------------------------------------------------------------
// Protocol Parsing
// ------------------------------------------------------------

func parseProtocols(s string) []string {
    s = strings.ToUpper(strings.TrimSpace(s))
    switch s {
    case "TCP":
        return []string{"TCP"}
    case "UDP":
        return []string{"UDP"}
    case "BOTH":
        return []string{"TCP", "UDP"}
    default:
        return []string{"TCP"}
    }
}

func resolveTarget(target string) []string {
    ips, _ := net.LookupHost(target)
    return ips
}

// ------------------------------------------------------------
// TCP Scan
// ------------------------------------------------------------

func scanTCP(ip string, port int, timeout time.Duration, wg *sync.WaitGroup, sem chan struct{}, results chan<- string) {
    defer wg.Done()
    sem <- struct{}{}
    defer func() { <-sem }()

    addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
    conn, err := net.DialTimeout("tcp", addr, timeout)
    if err == nil {
        results <- fmt.Sprintf("TCP %d Open", port)
        conn.Close()
    }
}

// ------------------------------------------------------------
// UDP Scan
// ------------------------------------------------------------

func scanUDP(ip string, port int, timeout time.Duration, wg *sync.WaitGroup, sem chan struct{}, results chan<- string) {
    defer wg.Done()
    sem <- struct{}{}
    defer func() { <-sem }()

    addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
    conn, err := net.DialTimeout("udp", addr, timeout)
    if err != nil {
        results <- fmt.Sprintf("UDP %d Closed", port)
        return
    }
    defer conn.Close()

    _, _ = conn.Write([]byte{0})

    buf := make([]byte, 2048)
    _ = conn.SetReadDeadline(time.Now().Add(timeout))
    _, err = conn.Read(buf)

    if err == nil {
        results <- fmt.Sprintf("UDP %d Open", port)
        return
    }

    if opErr, ok := err.(*net.OpError); ok {
        if sysErr, ok := opErr.Err.(*os.SyscallError); ok && sysErr.Err == syscall.ECONNREFUSED {
            results <- fmt.Sprintf("UDP %d Closed", port)
            return
        }
    }

    results <- fmt.Sprintf("UDP %d Open|Filtered", port)
}

// ------------------------------------------------------------
// Scan Target
// ------------------------------------------------------------

func scanTarget(ip string, ports []int, protocols []string, timeout time.Duration, concurrency int) []string {
    results := []string{}
    resultChan := make(chan string, len(ports)*2)

    var wg sync.WaitGroup
    sem := make(chan struct{}, concurrency)

    for _, port := range ports {
        for _, proto := range protocols {
            wg.Add(1)
            if proto == "TCP" {
                go scanTCP(ip, port, timeout, &wg, sem, resultChan)
            } else {
                go scanUDP(ip, port, timeout, &wg, sem, resultChan)
            }
        }
    }

    go func() {
        wg.Wait()
        close(resultChan)
    }()

    for r := range resultChan {
        results = append(results, r)
    }

    for i := range results {
        for j := i + 1; j < len(results); j++ {
            if results[j] < results[i] {
                results[j], results[i] = results[i], results[j]
            }
        }
    }

    return results
}

// ------------------------------------------------------------
// Interactive Mode
// ------------------------------------------------------------

func runInteractive(timeout time.Duration, concurrency int) {
    fmt.Println("Luna Port Scanner", Version)

    reader := bufio.NewReader(os.Stdin)

    for {
        fmt.Print("Enter domain or IP: ")
        target, _ := reader.ReadString('\n')
        target = strings.TrimSpace(target)
        if target == "" {
            continue
        }

        fmt.Print("Enter port(s): ")
        portStr, _ := reader.ReadString('\n')
        ports := parsePorts(strings.TrimSpace(portStr))
        if len(ports) == 0 {
            fmt.Println("[!] Invalid ports")
            continue
        }

        fmt.Print("Enter protocol (TCP/UDP/BOTH) [default TCP]: ")
        protoStr, _ := reader.ReadString('\n')
        protoStr = strings.TrimSpace(protoStr)

        var protocols []string
        if protoStr == "" {
            protocols = []string{"TCP"}
        } else {
            protocols = parseProtocols(protoStr)
        }

        ips := resolveTarget(target)
        for _, ip := range ips {
            fmt.Println("\n--- Scanning", ip, "---")
            results := scanTarget(ip, ports, protocols, timeout, concurrency)

            if len(results) == 0 {
                fmt.Println("   No open ports found")
            } else {
                for _, r := range results {
                    fmt.Println("   " + r)
                }
            }
        }

        fmt.Print("\nScan another target? (y/n): ")
        ans, _ := reader.ReadString('\n')
        if strings.ToLower(strings.TrimSpace(ans)) != "y" {
            return
        }
    }
}

// ------------------------------------------------------------
// Non-Interactive Mode (silent, logs only)
// ------------------------------------------------------------

func runNonInteractive(target string, ports []int, protocols []string, timeout time.Duration, concurrency int, show bool) {

    ips := resolveTarget(target)

    var f *os.File
    var err error

    // If not show, create log file
    if !show {
        logFile := fmt.Sprintf("scan-%s.log", target)
        f, err = os.Create(logFile)
        if err != nil {
            return
        }
        defer f.Close()
    }

    for _, ip := range ips {
        header := fmt.Sprintf("\n--- Scanning %s ---\n", ip)

        if show {
            fmt.Print(header)
        } else {
            fmt.Fprint(f, header)
        }

        results := scanTarget(ip, ports, protocols, timeout, concurrency)

        if len(results) == 0 {
            if show {
                fmt.Println("   No open ports found")
            } else {
                fmt.Fprintln(f, "   No open ports found")
            }
        } else {
            for _, r := range results {
                if show {
                    fmt.Println("   " + r)
                } else {
                    fmt.Fprintln(f, "   "+r)
                }
            }
        }
    }
}



// ------------------------------------------------------------
// Main
// ------------------------------------------------------------

func main() {
	target := flag.String("target", "", "Target host")
	portStr := flag.String("port", "", "Ports: 80,443 or 20-25")
	protocol := flag.String("protocol", "TCP", "TCP | UDP | BOTH")
	timeout := flag.Float64("timeout", 1.0, "Timeout seconds")
	concurrency := flag.Int("concurrency", 200, "Concurrency level")
	version := flag.Bool("version", false, "Show version")
	show := flag.Bool("show", false, "Show results on screen instead of saving to a log file")


    flag.Usage = func() {
    fmt.Fprintf(os.Stderr, "Luna Port Scanner %s\n\n", Version)
    fmt.Fprintf(os.Stderr, "Usage:\n")
    fmt.Fprintf(os.Stderr, "  lunaportscanner [options]\n\n")
    fmt.Fprintf(os.Stderr, "Options:\n")
    fmt.Fprintf(os.Stderr, "  --target string\n        Target host\n")
    fmt.Fprintf(os.Stderr, "  --port string\n        Ports: 80,443 or 20-25\n")
    fmt.Fprintf(os.Stderr, "  --protocol string\n        TCP | UDP | BOTH (default \"TCP\")\n")
    fmt.Fprintf(os.Stderr, "  --timeout float\n        Timeout seconds (default 1)\n")
    fmt.Fprintf(os.Stderr, "  --concurrency int\n        Concurrency level (default 200)\n")
    fmt.Fprintf(os.Stderr, "  --version\n        Show version\n")
    fmt.Fprintf(os.Stderr, "  --show\n        Show results on screen instead of saving to a log file\n")
    fmt.Fprintf(os.Stderr, "  --help\n        Show this help\n\n")
}

    
    flag.Parse()

    if *version {
        fmt.Println("Luna Port Scanner", Version)
        return
    }

    tout := time.Duration(*timeout * float64(time.Second))
    if *concurrency < 1 {
        *concurrency = 1
    }

    protocols := parseProtocols(*protocol)

    if *target != "" {
        if *portStr == "" {
            return
        }

        ports := parsePorts(*portStr)
        if len(ports) == 0 {
            return
        }

        runNonInteractive(*target, ports, protocols, tout, *concurrency, *show)

        return
    }

    runInteractive(tout, *concurrency)
}


