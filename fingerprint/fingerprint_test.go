package fingerprint

import (
	"encoding/json"
	"os"
	"testing"
)

func TestSample(t *testing.T) {
	m, err := Load("../rules.json")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../sample.json")
	if err != nil {
		t.Fatal(err)
	}
	var inputs []Input
	if err := json.Unmarshal(data, &inputs); err != nil {
		t.Fatal(err)
	}
	want := []struct{ protocol, product, version, os string }{
		{"SSH", "OpenSSH", "8.9p1", "Ubuntu"}, {"HTTP", "nginx", "1.24.0", ""},
		{"HTTP", "Apache", "2.4.57", ""}, {"MySQL", "MySQL", "8.0.32", ""},
		{"Redis", "Redis", "", ""}, {"FTP", "ProFTPD", "1.3.7", ""},
		{"HTTP", "Jetty", "9.4.51", ""}, {"SSH", "OpenSSH", "9.3", "Debian"},
		{"HTTP", "nginx", "1.18.0", "Ubuntu"}, {"HTTP", "Apache", "2.4.41", "Ubuntu"},
		{"MySQL", "MySQL", "5.7.42", ""}, {"Redis", "Redis", "", ""},
		{"FTP", "vsFTPd", "3.0.5", ""}, {"HTTP", "nginx", "1.25.3", ""},
		{"SSH", "OpenSSH", "4.3", ""}, {"unknown", "", "", ""},
		{"HTTP", "Microsoft-IIS", "10.0", ""}, {"Redis", "Redis", "", ""},
		{"FTP", "Pure-FTPd", "", ""}, {"unknown", "", "", ""},
	}
	if len(inputs) != len(want) {
		t.Fatalf("got %d samples, want %d", len(inputs), len(want))
	}
	for i, in := range inputs {
		got := m.Match(in)
		w := want[i]
		if got.IP != in.IP || got.Port != in.Port || got.Protocol != w.protocol || got.Product != w.product || got.Version != w.version || got.OSHint != w.os || got.Confidence < 0 || got.Confidence > 1 {
			t.Errorf("sample %d: got %+v, want %+v", i, got, w)
		}
	}
}
