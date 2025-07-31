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

// CheckResult defines the structure of the JSON response for clear and predictable output.
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
	// Register the handler for the /check endpoint.
	http.HandleFunc("/check", checkHandler)

	// Determine the port to listen on, defaulting to 8080.
	// Cloud platforms often set the PORT environment variable.
	port := getEnv("PORT", "8080")
	fmt.Printf("Server starting on port %s...\n", port)
	
	// Start the HTTP server.
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Printf("Error starting server: %s\n", err)
		os.Exit(1)
	}
}

func checkHandler(w http.ResponseWriter, r *http.Request) {
	// Set headers for CORS and JSON content type.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	// Extract and validate required query parameters.
	queryParams := r.URL.Query()
	ipToTest := queryParams.Get("ip")
	host := queryParams.Get("host")
	port := getEnv(queryParams.Get("port"), "443")

	if ipToTest == "" || host == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(CheckResult{
			Success: false,
			Error:   "Bad Request: 'ip' and 'host' query parameters are required.",
		})
		return
	}

	// --- Core Logic: The definitive method for proxy verification ---

	// 1. Establish a TCP connection with a strict timeout.
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(ipToTest, port))
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
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

	// 2. Initiate a TLS handshake over the established connection, providing the crucial SNI.
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host, // This ensures the correct SNI is sent.
		InsecureSkipVerify: true, // We don't validate the cert, we just need to establish a TLS session.
	})

	// 3. Send a well-formed HTTP GET request for /cdn-cgi/trace.
	req, _ := http.NewRequestWithContext(r.Context(), "GET", "https://"+host+"/cdn-cgi/trace", nil)
	req.Host = host
	req.Header.Set("User-Agent", "Go-Proxy-Checker/2.0")

	if err := req.Write(tlsConn); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(CheckResult{
			Success:  false,
			TestedIP: ipToTest,
			UsedHost: host,
			Message:  "Failed to write HTTP request over TLS.",
			Error:    err.Error(),
		})
		return
	}

	// 4. Read the server's response.
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(CheckResult{
			Success:  false,
			TestedIP: ipToTest,
			UsedHost: host,
			Message:  "Failed to read HTTP response from the target server.",
			Error:    err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	// 5. Parse the trace data and perform the final, strict validation.
	body, _ := io.ReadAll(resp.Body)
	traceData := parseTrace(string(body))
	reportedIP := traceData["ip"]
	isVerified := reportedIP == ipToTest

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(CheckResult{
		Success:    isVerified,
		TestedIP:   ipToTest,
		UsedHost:   host,
		Message:    "Check complete.",
		ReportedIP: reportedIP,
		RawTrace:   traceData,
	})
}

// parseTrace is a robust helper function to parse the key-value trace output.
func parseTrace(trace string) map[string]string {
	data := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(trace))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			data[parts[0]] = parts[1]
		}
	}
	return data
}

// getEnv is a helper function to read an environment variable or return a fallback value.
func getEnv(key, fallback string) string {
    if value, ok := os.LookupEnv(key); ok {
        return value
    }
    return fallback
}
