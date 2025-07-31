package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// CheckResult defines the structure of the JSON response for clear, predictable output.
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

	port := getEnv("PORT", "8080")
	fmt.Printf("Server starting on port %s...\n", port)
	
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Printf("Error starting server: %s\n", err)
		os.Exit(1)
	}
}

func checkHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	queryParams := r.URL.Query()
	ipToTest := queryParams.Get("ip")
	host := queryParams.Get("host")
	port := queryParams.Get("port")

	if ipToTest == "" || host == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(CheckResult{
			Success: false,
			Error:   "Bad Request: 'ip' and 'host' query parameters are required.",
		})
		return
	}

	if port == "" {
		port = "443" // Default HTTPS port.
	}

	// --- The Definitive and Robust Go Logic ---

	// Create a custom dialer that connects to our target IP and port.
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	// Create a custom HTTP transport.
	// This is the standard Go way to control connection behavior.
	transport := &http.Transport{
		// Force the transport to use our custom dialer.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Ignore the address provided by the transport (which would be the resolved 'host').
			// Instead, use the IP and port we want to test.
			return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ipToTest, port))
		},
		// The TLSClientConfig will automatically use the request's Host for the SNI.
		// This is exactly what we need.
		TLSClientConfig: &http.TLSClientConfig{
			ServerName:         host,
			InsecureSkipVerify: true, // We don't need to verify the certificate chain.
		},
	}

	// Create an HTTP client that uses our custom transport.
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second, // Overall timeout for the request.
	}

	// Create the request to the /cdn-cgi/trace endpoint.
	// The URL must use HTTPS and the correct host to set the SNI.
	requestUrl := "https://" + host + "/cdn-cgi/trace"
	req, err := http.NewRequestWithContext(r.Context(), "GET", requestUrl, nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(CheckResult{Success: false, Error: "Failed to create request."})
		return
	}
	req.Header.Set("User-Agent", "Go-Proxy-Checker/3.0")

	// Execute the request using our custom client.
	resp, err := client.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(CheckResult{
			Success:  false,
			TestedIP: ipToTest,
			UsedHost: host,
			Message:  "Request failed. The IP may not be a valid proxy for this host.",
			Error:    err.Error(),
		})
		return
	}
	defer resp.Body.Close()

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

// Helper function to parse the key-value trace output.
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

// Helper function to read an environment variable or return a fallback value.
func getEnv(key, fallback string) string {
    if value, ok := os.LookupEnv(key); ok {
        return value
    }
    return fallback
}
