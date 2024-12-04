package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

// Device represents a discovered device
type Device struct {
	IP        string `json:"ip"`
	OpenPorts []int  `json:"open_ports"`
}

// Ping sends an ICMP echo request to the specified IP
func Ping(ip string, timeout time.Duration) bool {
	message := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("PING"),
		},
	}

	msgBytes, err := message.Marshal(nil)
	if err != nil {
		fmt.Printf("Error marshalling ICMP message: %v\n", err)
		return false
	}

	addr, err := net.ResolveIPAddr("ip4", ip)
	if err != nil {
		fmt.Printf("Error resolving address %s: %v\n", ip, err)
		return false
	}

	conn, err := net.DialIP("ip4:icmp", nil, addr)
	if err != nil {
		fmt.Printf("Error dialing %s: %v\n", ip, err)
		return false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	_, err = conn.Write(msgBytes)
	if err != nil {
		fmt.Printf("Error sending ICMP message to %s: %v\n", ip, err)
		return false
	}

	reply := make([]byte, 1500)
	n, err := conn.Read(reply)
	if err != nil {
		fmt.Printf("Error receiving reply from %s: %v\n", ip, err)
		return false
	}

	parsedMsg, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		fmt.Printf("Error parsing ICMP message from %s: %v\n", ip, err)
		return false
	}

	switch parsedMsg.Type {
	case ipv4.ICMPTypeEchoReply:
		return true
	default:
		return false
	}
}

// ScanPort checks if a specific port is open on the given IP
func ScanPort(ip string, port int, timeout time.Duration) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// DiscoverDevices scans the given IP range and returns a list of active devices
func DiscoverDevices(startIP, endIP string, ports []int, timeout time.Duration, wg *sync.WaitGroup, devicesChan chan<- Device) {
	defer wg.Done()

	start := ipToInt(net.ParseIP(startIP))
	end := ipToInt(net.ParseIP(endIP))

	var localWg sync.WaitGroup
	semaphore := make(chan struct{}, 100)

	for ipInt := start; ipInt <= end; ipInt++ {
		ip := intToIP(ipInt).String()

		semaphore <- struct{}{}
		localWg.Add(1)

		go func(ip string) {
			defer localWg.Done()
			defer func() { <-semaphore }()

			if Ping(ip, timeout) {
				device := Device{IP: ip}
				if len(ports) > 0 {
					var portWg sync.WaitGroup
					portSemaphore := make(chan struct{}, 100)
					for _, port := range ports {
						portSemaphore <- struct{}{}
						portWg.Add(1)
						go func(p int) {
							defer portWg.Done()
							defer func() { <-portSemaphore }()
							if ScanPort(ip, p, timeout) {
								device.OpenPorts = append(device.OpenPorts, p)
							}
						}(port)
					}
					portWg.Wait()
				}
				devicesChan <- device
			}
		}(ip)
	}

	localWg.Wait()
}

// ipToInt converts a net.IP to an integer
func ipToInt(ip net.IP) uint32 {
	ipv4 := ip.To4()
	return uint32(ipv4[0])<<24 + uint32(ipv4[1])<<16 + uint32(ipv4[2])<<8 + uint32(ipv4[3])
}

// intToIP converts an integer to net.IP
func intToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16&0xFF), byte(n>>8&0xFF), byte(n&0xFF))
}

func main() {
	startIP := flag.String("start", "192.168.1.1", "Start IP address")
	endIP := flag.String("end", "192.168.1.254", "End IP address")
	ports := flag.String("ports", "22,80,443", "Comma-separated list of ports to scan")
	timeout := flag.Int("timeout", 1000, "Timeout in milliseconds")
	flag.Parse()

	var portList []int
	if *ports != "" {
		for _, p := range splitAndTrim(*ports, ",") {
			port, err := strconv.Atoi(p)
			if err == nil {
				portList = append(portList, port)
			}
		}
	}

	devicesChan := make(chan Device, 100)
	var wg sync.WaitGroup

	wg.Add(1)
	go DiscoverDevices(*startIP, *endIP, portList, time.Duration(*timeout)*time.Millisecond, &wg, devicesChan)

	go func() {
		wg.Wait()
		close(devicesChan)
	}()

	var devices []Device
	for device := range devicesChan {
		devices = append(devices, device)
	}

	// Ensure output is always JSON format
	if len(devices) == 0 {
		fmt.Println("[]")
	} else {
		jsonOutput, err := json.Marshal(devices)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshalling devices to JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(jsonOutput))
	}
}

// splitAndTrim splits a string by sep and trims spaces
func splitAndTrim(s, sep string) []string {
	var res []string
	parts := []byte(s)
	current := ""
	for _, b := range parts {
		if string(b) == sep {
			if current != "" {
				res = append(res, current)
				current = ""
			}
		} else {
			current += string(b)
		}
	}
	if current != "" {
		res = append(res, current)
	}
	return res
}
