package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// normalizeAddr converts various address formats into a value acceptable by http.ListenAndServe.
// Examples:
//  - "http://127.0.0.1:8080" -> "127.0.0.1:8080"
//  - "http://127.0.0.1" -> "127.0.0.1:80"
//  - "127.0.0.1:8080" -> "127.0.0.1:8080"
//  - "127.0.0.1" -> "127.0.0.1:80"
//  - ":8080" -> ":8080"
func normalizeAddr(arg string) (string, error) {
	s := strings.TrimSpace(arg)
	if s == "" {
		return "", fmt.Errorf("empty address")
	}
	// If it looks like a URL with scheme
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", err
		}
		if u.Scheme != "http" && u.Scheme != "" {
			return "", fmt.Errorf("unsupported scheme: %s", u.Scheme)
		}
		host := u.Host
		if host == "" {
			// Some inputs might be like http://:8080 where Host is empty and Path holds the value
			host = strings.TrimPrefix(u.Path, "/")
		}
		if host == "" {
			return "", fmt.Errorf("missing host")
		}
		if _, _, err := net.SplitHostPort(host); err != nil {
			// No port: default to 80 for http
			// Handle possible IPv6 without brackets by joining properly
			// net.JoinHostPort expects a bare host without brackets
			if strings.HasPrefix(host, "[") && strings.Contains(host, "]") {
				host = strings.Trim(host, "[]")
			}
			host = net.JoinHostPort(host, "80")
		}
		return host, nil
	}
	// Bare address cases
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s, nil
	}
	// If it's only :port or host without port
	if strings.HasPrefix(s, ":") {
		return s, nil
	}
	return net.JoinHostPort(s, "80"), nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s [address or URL]\nExample: %s http://127.0.0.1:8080\n", os.Args[0], os.Args[0])
		os.Exit(2)
	}
	addr, err := normalizeAddr(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Invalid address:", err)
		os.Exit(2)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("hello world!"))
	})
	log.Printf("Listening on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}
