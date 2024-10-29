package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// ScanPort scans a specific TCP port on a given hostname
func ScanPort(hostname string, port int, wg *sync.WaitGroup, results chan int) {
	defer wg.Done()

	address := fmt.Sprintf("%s:%d", hostname, port)
	conn, err := net.DialTimeout("tcp", address, 1*time.Second)
	if err == nil {
		results <- port
		_ = conn.Close()
	}
}

// ScanHandler handles HTTP requests for port scanning
func ScanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	type ScanRequest struct {
		Host      string `json:"host"`
		StartPort int    `json:"start_port"`
		EndPort   int    `json:"end_port"`
	}

	var req ScanRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	var wg sync.WaitGroup
	results := make(chan int, req.EndPort-req.StartPort+1)

	// Start scanning the ports
	for port := req.StartPort; port <= req.EndPort; port++ {
		wg.Add(1)
		go ScanPort(req.Host, port, &wg, results)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	openPorts := []int{}
	for port := range results {
		openPorts = append(openPorts, port)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"open_ports": openPorts,
	})
}

func main() {
	http.HandleFunc("/scan", ScanHandler)
	fmt.Println("Starting server on :8080...")
	http.ListenAndServe(":8080", nil)
}
