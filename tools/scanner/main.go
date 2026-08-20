// Command scanner performs a concurrent TCP connect-scan over a port range
// and prints the result as JSON. Usage: scanner <host> <start_port> <end_port>
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"
)

var hostnameRegex = regexp.MustCompile(`^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$`)

type ScanRequest struct {
	Host      string
	StartPort int
	EndPort   int
}

type ScanResponse struct {
	Target          string    `json:"target"`
	StartPort       int       `json:"start_port"`
	EndPort         int       `json:"end_port"`
	OpenPorts       []int     `json:"open_ports"`
	ClosedPorts     int       `json:"closed_ports"`
	TotalPorts      int       `json:"total_ports"`
	DurationSeconds float64   `json:"duration_seconds"`
	Timestamp       time.Time `json:"timestamp"`
}

// ValidateScanRequest rejects malformed hosts and out-of-range port bounds.
func ValidateScanRequest(req ScanRequest) error {
	if req.Host == "" {
		return errors.New("host required")
	}
	if net.ParseIP(req.Host) == nil {
		if !hostnameRegex.MatchString(req.Host) {
			return errors.New("invalid hostname or IP address")
		}
		if _, err := net.LookupHost(req.Host); err != nil {
			return fmt.Errorf("failed to resolve hostname: %v", err)
		}
	}
	if req.StartPort < 1 || req.EndPort > 65535 || req.StartPort > req.EndPort {
		return errors.New("ports must satisfy 1 <= start <= end <= 65535")
	}
	return nil
}

// scanPort reports the port on the results channel if a TCP connection succeeds.
func scanPort(host string, port int, wg *sync.WaitGroup, results chan<- int, timeout time.Duration) {
	defer wg.Done()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err == nil {
		results <- port
		_ = conn.Close()
	}
}

func run(req ScanRequest) ScanResponse {
	start := time.Now()
	total := req.EndPort - req.StartPort + 1
	results := make(chan int, total)
	var wg sync.WaitGroup

	for port := req.StartPort; port <= req.EndPort; port++ {
		wg.Add(1)
		go scanPort(req.Host, port, &wg, results, time.Second)
	}
	go func() { wg.Wait(); close(results) }()

	open := make([]int, 0)
	for port := range results {
		open = append(open, port)
	}

	return ScanResponse{
		Target:          req.Host,
		StartPort:       req.StartPort,
		EndPort:         req.EndPort,
		OpenPorts:       open,
		ClosedPorts:     total - len(open),
		TotalPorts:      total,
		DurationSeconds: time.Since(start).Seconds(),
		Timestamp:       time.Now(),
	}
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: scanner <host> <start_port> <end_port>")
		os.Exit(1)
	}
	start, err1 := strconv.Atoi(os.Args[2])
	end, err2 := strconv.Atoi(os.Args[3])
	if err1 != nil || err2 != nil {
		fmt.Fprintln(os.Stderr, "start and end ports must be integers")
		os.Exit(1)
	}

	req := ScanRequest{Host: os.Args[1], StartPort: start, EndPort: end}
	if err := ValidateScanRequest(req); err != nil {
		fmt.Fprintf(os.Stderr, "validation error: %v\n", err)
		os.Exit(1)
	}

	out, _ := json.MarshalIndent(run(req), "", "  ")
	fmt.Println(string(out))
}
