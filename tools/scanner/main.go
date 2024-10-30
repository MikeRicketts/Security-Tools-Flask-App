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

// ScanRequest represents the expected JSON payload for scanning
type ScanRequest struct {
    Host      string `json:"host"`
    StartPort int    `json:"start_port"`
    EndPort   int    `json:"end_port"`
}

// ScanResponse represents the JSON response after scanning
type ScanResponse struct {
    Target          string    `json:"target"`
    StartPort       int       `json:"start_port"`
    EndPort         int       `json:"end_port"`
    OpenPorts       []int     `json:"open_ports"`
    ClosedPorts     int       `json:"closed_ports"`
    TotalPorts      int       `json:"total_ports"`
    DurationSeconds float64   `json:"duration_seconds"`
    Timestamp       time.Time `json:"timestamp"`
    Error           string    `json:"error,omitempty"`
}

// ValidateScanRequest validates the ScanRequest fields
func ValidateScanRequest(req ScanRequest) error {
    // Validate Host
    if req.Host == "" {
        return errors.New("host is required")
    }
    // Check if it's a valid IP address
    if net.ParseIP(req.Host) == nil {
        // Validate hostname using regex
        hostnameRegex := `^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$`
        matched, err := regexp.MatchString(hostnameRegex, req.Host)
        if err != nil || !matched {
            return errors.New("invalid hostname or IP address")
        }
        // Attempt to resolve the hostname
        _, err = net.LookupHost(req.Host)
        if err != nil {
            return fmt.Errorf("unable to resolve host: %v", err)
        }
    }

    // Validate StartPort and EndPort
    if req.StartPort < 1 || req.StartPort > 65535 {
        return errors.New("start_port must be between 1 and 65535")
    }
    if req.EndPort < 1 || req.EndPort > 65535 {
        return errors.New("end_port must be between 1 and 65535")
    }
    if req.StartPort > req.EndPort {
        return errors.New("start_port cannot be greater than end_port")
    }

    return nil
}

// ScanPort scans a specific TCP port on a given hostname
func ScanPort(hostname string, port int, wg *sync.WaitGroup, results chan<- int, timeout time.Duration) {
    defer wg.Done()

    address := net.JoinHostPort(hostname, strconv.Itoa(port))
    conn, err := net.DialTimeout("tcp", address, timeout)
    if err == nil {
        results <- port
        _ = conn.Close()
    }
}

func main() {
    if len(os.Args) != 4 {
        fmt.Println("Usage: go run main.go <host> <start_port> <end_port>")
        os.Exit(1)
    }

    host := os.Args[1]
    startPort, err := strconv.Atoi(os.Args[2])
    if err != nil {
        fmt.Printf("Invalid start port: %v\n", err)
        os.Exit(1)
    }
    endPort, err := strconv.Atoi(os.Args[3])
    if err != nil {
        fmt.Printf("Invalid end port: %v\n", err)
        os.Exit(1)
    }

    req := ScanRequest{
        Host:      host,
        StartPort: startPort,
        EndPort:   endPort,
    }

    if err := ValidateScanRequest(req); err != nil {
        fmt.Printf("Validation error: %v\n", err)
        os.Exit(1)
    }

    totalPorts := req.EndPort - req.StartPort + 1
    openPorts := make([]int, 0)
    results := make(chan int, totalPorts)
    var wg sync.WaitGroup

    for port := req.StartPort; port <= req.EndPort; port++ {
        wg.Add(1)
        go ScanPort(req.Host, port, &wg, results, 1*time.Second)
    }

    go func() {
        wg.Wait()
        close(results)
    }()

    for port := range results {
        openPorts = append(openPorts, port)
    }

    closedPorts := totalPorts - len(openPorts)
    response := ScanResponse{
        Target:          req.Host,
        StartPort:       req.StartPort,
        EndPort:         req.EndPort,
        OpenPorts:       openPorts,
        ClosedPorts:     closedPorts,
        TotalPorts:      totalPorts,
        DurationSeconds: 0, // Placeholder for scan duration if needed
        Timestamp:       time.Now(),
    }

    jsonResponse, _ := json.MarshalIndent(response, "", "  ")
    fmt.Println(string(jsonResponse))
}