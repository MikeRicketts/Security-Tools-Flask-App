package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"sync"
	"syscall"
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

// ScanHandler handles HTTP requests for port scanning
func ScanHandler(workerPoolSize int, portTimeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Invalid request method. Use POST.", http.StatusMethodNotAllowed)
			return
		}

		var req ScanRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, "Invalid request payload.", http.StatusBadRequest)
			return
		}

		// Validate the request
		if err := ValidateScanRequest(req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Calculate total ports to scan
		totalPorts := req.EndPort - req.StartPort + 1

		// Limit the maximum number of ports to scan in a single request
		const MaxPortRange = 10000
		if totalPorts > MaxPortRange {
			http.Error(w, fmt.Sprintf("Port range too large. Maximum allowed is %d ports.", MaxPortRange), http.StatusBadRequest)
			return
		}

		// Prepare for scanning
		openPorts := make([]int, 0)
		results := make(chan int, totalPorts)
		var wg sync.WaitGroup

		// Create a buffered channel to limit concurrency
		portsChan := make(chan int, workerPoolSize)

		// Start worker goroutines
		for i := 0; i < workerPoolSize; i++ {
			go func() {
				for port := range portsChan {
					wg.Add(1)
					ScanPort(req.Host, port, &wg, results, portTimeout)
				}
			}()
		}

		// Send ports to the portsChan
		go func() {
			for port := req.StartPort; port <= req.EndPort; port++ {
				portsChan <- port
			}
			close(portsChan)
		}()

		// Wait for all scans to complete in a separate goroutine
		go func() {
			wg.Wait()
			close(results)
		}()

		// Collect open ports
		for port := range results {
			openPorts = append(openPorts, port)
		}

		// Calculate closed ports
		closedPorts := totalPorts - len(openPorts)

		// Prepare the response
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

		// Respond with JSON
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func main() {
	// Configuration
	const (
		WorkerPoolSize = 100             // Number of concurrent workers
		PortTimeout    = 1 * time.Second // Timeout for each port scan
		ServerAddr     = ":8080"         // Server address
	)

	// Handle graceful shutdown
	server := &http.Server{
		Addr:    ServerAddr,
		Handler: nil, // We'll register handlers below
	}

	// Register the scan handler
	http.HandleFunc("/scan", ScanHandler(WorkerPoolSize, PortTimeout))

	// Channel to listen for interrupt or terminate signals
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	// Start the server in a goroutine
	go func() {
		fmt.Printf("Starting server on %s...\n", ServerAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Failed to start server: %v\n", err)
			os.Exit(1)
		}
	}()

	// Block until a signal is received
	<-stopChan
	fmt.Println("\nShutting down server...")

	// Create a deadline to wait for current operations to complete
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		fmt.Printf("Server Shut Down Failed:%+v\n", err)
	}

	fmt.Println("Server Shut Down.")
}
