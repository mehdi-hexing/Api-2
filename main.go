package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// CheckResult defines the structure of the JSON response.
type CheckResult struct {
	Success    bool              `json:"success"`
	TestedIP   string            `json:"tested_ip"`
	UsedHost   string            `json:"used_host"`
	Message    string            `json:"message"`
	Error      string            `json:"error,omitempty"`
	ReportedIP string            `json:"reported_ip,omitempty"`
	RawTrace   map[string]string `json:"raw_trace,omitempty"`
}

func main() {
	http.HandleFunc("/check", checkHandler)
	fmt.Println("Server is listening on port 8080...")

	// For cloud platforms, the port is often set via the PORT environment variable.
	port := "8080"
	if p := getEnv("PORT", ""); p != "" {
		port = p
	}
	http.ListenAndServe(":"+port, nil)
}

func checkHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS for all origins.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	// Get parameters from the URL query.
	queryParams := r.URL.Query()
	ipToTest := queryParams.Get("ip")
	host := queryParams.Get("host")
	port := queryParams.Get("port")

	if ipToTest == "" || host == "" {
		json.NewEncoder(w).Encode(CheckResult{
			Success: false,
			Error:   "Missing 'ip' or 'host' query parameters.",
		})
		return
	}

	if port == "" {
		port = "443" // Default port.
	}

	// --- Core Logic ---
	// 1. Establish a TCP connection to the input IP and port.
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(ipToTest, port))
	if err != nil {
		json.NewEncoder(w).Encode(CheckResult{
			Success:  false,
			TestedIP: ipToTest,
			UsedHost: host,
			Message:  "TCP connection failed.",
			Error:    err.Error(),
		})
		return
	}
	defer conn.Close()

	// 2. Initiate a TLS handshake over the connection with the specified SNI.
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host, // This is the most crucial part (SNI).
		InsecureSkipVerify: true, // We don't care about the certificate's validity, only the connection.
	})

	// 3. Send an HTTP GET request for /cdn-cgi/trace over the TLS connection.
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "https://"+host+"/cdn-cgi/trace", nil)
	req.Host = host
	req.Header.Set("User-Agent", "Go-Proxy-Checker/1.0")

	err = req.Write(tlsConn)
	if err != nil {
		json.NewEncoder(w).Encode(CheckResult{
			Success:  false,
			TestedIP: ipToTest,
			UsedHost: host,
			Message:  "Failed to write HTTP request over TLS.",
			Error:    err.Error(),
		})
		return
	}

	// 4. Read and parse the response.
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		json.NewEncoder(w).Encode(CheckResult{
			Success:  false,
			TestedIP: ipToTest,
			UsedHost: host,
			Message:  "Failed to read HTTP response.",
			Error:    err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	traceData := parseTrace(string(body))

	// 5. Compare the IPs and return the final result.
	reportedIP := traceData["ip"]
	isVerified := reportedIP == ipToTest

	json.NewEncoder(w).Encode(CheckResult{
		Success:    isVerified,
		TestedIP:   ipToTest,
		UsedHost:   host,
		Message:    "Check complete.",
		ReportedIP: reportedIP,
		RawTrace:   traceData,
	})
}

// Helper function to parse the trace output.
func parseTrace(trace string) map[string]string {
	data := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(trace), "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			data[parts[0]] = parts[1]
		}
	}
	return data
}

// Helper function to read environment variables.
func getEnv(key, fallback string) string {
    if value, ok := os.LookupEnv(key); ok {
        return value
    }
    return fallback
}
