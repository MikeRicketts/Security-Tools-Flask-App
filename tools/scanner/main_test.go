package main

import "testing"

func TestValidateScanRequest(t *testing.T) {
	cases := []struct {
		name    string
		req     ScanRequest
		wantErr bool
	}{
		{"valid ip", ScanRequest{"127.0.0.1", 1, 1024}, false},
		{"empty host", ScanRequest{"", 1, 1024}, true},
		{"start below range", ScanRequest{"127.0.0.1", 0, 1024}, true},
		{"end above range", ScanRequest{"127.0.0.1", 1, 70000}, true},
		{"start after end", ScanRequest{"127.0.0.1", 500, 100}, true},
		{"garbage host", ScanRequest{"not a host!!", 1, 10}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := ValidateScanRequest(c.req); (err != nil) != c.wantErr {
				t.Fatalf("ValidateScanRequest(%v) error = %v, wantErr = %v", c.req, err, c.wantErr)
			}
		})
	}
}

func TestRunLocalhost(t *testing.T) {
	resp := run(ScanRequest{Host: "127.0.0.1", StartPort: 1, EndPort: 2})
	if resp.TotalPorts != 2 {
		t.Fatalf("TotalPorts = %d, want 2", resp.TotalPorts)
	}
	if resp.DurationSeconds <= 0 {
		t.Fatalf("DurationSeconds = %f, want > 0", resp.DurationSeconds)
	}
}
