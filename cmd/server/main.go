package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"time"

	"banner-fingerprint/fingerprint"
)

func main() {
	health := flag.Bool("health", false, "check local server health")
	flag.Parse()
	if *health {
		client := http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get("http://127.0.0.1:8080/health")
		if err != nil {
			log.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Fatal(resp.Status)
		}
		return
	}
	path := os.Getenv("RULES_FILE")
	if path == "" {
		path = "rules.json"
	}
	m, err := fingerprint.Load(path)
	if err != nil {
		log.Fatal(err)
	}
	server := http.Server{Addr: ":8080", Handler: handler(m), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	log.Print("listening on :8080")
	log.Fatal(server.ListenAndServe())
}

func handler(m *fingerprint.Matcher) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("POST /fingerprint", func(w http.ResponseWriter, r *http.Request) {
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
		var input []fingerprint.Input
		if err := dec.Decode(&input); err != nil || input == nil {
			http.Error(w, "expected a JSON array", http.StatusBadRequest)
			return
		}
		var trailing any
		if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
			http.Error(w, "trailing JSON data", http.StatusBadRequest)
			return
		}
		out := make([]fingerprint.Result, 0, len(input))
		for _, item := range input {
			if net.ParseIP(item.IP) == nil || item.Port < 1 || item.Port > 65535 {
				http.Error(w, "invalid ip or port", http.StatusBadRequest)
				return
			}
			out = append(out, m.Match(item))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	})
	return mux
}
