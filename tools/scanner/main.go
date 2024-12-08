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

// JSON request for scanning
type ScanRequest struct {
    Host      string `json:"host"`
    StartPort int    `json:"start_port"`
    EndPort   int    `json:"end_port"`
}

// JSON response after scanning
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

// Validates the ScanRequest payload
func ValidateScanRequest(req ScanRequest) error {
    if req.Host == "" {
        return errors.New("host required")
    }
    if net.ParseIP(req.Host) == nil {
        // Checks if valid hostname with regex
        hostnameRegex := `^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$`
        matched, err := regexp.MatchString(hostnameRegex, req.Host)
        if err != nil || !matched {
            return errors.New("invalid hostname or IP address")
        }
        // Resolves hostname to IP address
        _, err = net.LookupHost(req.Host)
        if err != nil {
            return fmt.Errorf("failed to resolve hostname: %v", err)
        }
    }

    // Validates StartPort and EndPort
    if req.StartPort < 1 || req.StartPort > 65535 {
        return errors.New("start port must be between 1 and 65535")
    }
    if req.EndPort < 1 || req.EndPort > 65535 {
        return errors.New("end port must be between 1 and 65535")
    }
    if req.StartPort > req.EndPort {
        return errors.New("start port cannot be greater than end port")
    }

    return nil
}

// Scans a single port on a host
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

    // Scans ports concurrently and collects open ports
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

    // Generates the response in JSON
    closedPorts := totalPorts - len(openPorts)
    response := ScanResponse{
        Target:          req.Host,
        StartPort:       req.StartPort,
        EndPort:         req.EndPort,
        OpenPorts:       openPorts,
        ClosedPorts:     closedPorts,
        TotalPorts:      totalPorts,
        DurationSeconds: 0, // Placeholder for scan duration
        Timestamp:       time.Now(),
    }

    jsonResponse, _ := json.MarshalIndent(response, "", "  ")
    fmt.Println(string(jsonResponse))
}