package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"banner-fingerprint/fingerprint"
)

func main() {
	file := flag.String("file", "sample.json", "input JSON array")
	url := flag.String("url", "http://localhost:8080/fingerprint", "server endpoint")
	flag.Parse()
	data, err := os.ReadFile(*file)
	if err != nil {
		log.Fatal(err)
	}
	var input []fingerprint.Input
	if err := json.Unmarshal(data, &input); err != nil || input == nil {
		log.Fatal("input must be a JSON array: ", err)
	}
	client := http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(*url, "application/json", bytes.NewReader(data))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		log.Fatalf("server: %s: %s", resp.Status, body)
	}
	var output any
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		log.Fatal(err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(output); err != nil {
		log.Fatal(err)
	}
}
