package fingerprint

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type Input struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

type rule struct {
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Pattern    string  `json:"pattern"`
	Confidence float64 `json:"confidence"`
	re         *regexp.Regexp
}

type Matcher struct{ rules []rule }

func Load(path string) (*Matcher, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("empty rules")
	}
	for i := range rules {
		r := &rules[i]
		if r.Protocol == "" || r.Pattern == "" || r.Confidence <= 0 || r.Confidence > 1 {
			return nil, fmt.Errorf("invalid rule %d", i)
		}
		r.re, err = regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
	}
	return &Matcher{rules: rules}, nil
}

func (m *Matcher) Match(in Input) Result {
	out := Result{IP: in.IP, Port: in.Port, Protocol: "unknown"}
	// MySQL greeting is a packet header, protocol byte 0x0a, then a NUL-terminated server version.
	b := []byte(in.Banner)
	if len(b) > 6 && b[4] == 10 && int(b[0])|int(b[1])<<8|int(b[2])<<16 >= len(b)-4 {
		if end := strings.IndexByte(in.Banner[5:], 0); end > 0 {
			version := in.Banner[5 : 5+end]
			if mysqlVersion.MatchString(version) {
				out.Protocol, out.Product, out.Version, out.Confidence = "MySQL", "MySQL", version, 0.9
				return out
			}
		}
	}
	for _, r := range m.rules {
		matches := r.re.FindStringSubmatch(in.Banner)
		if matches == nil {
			continue
		}
		out.Protocol, out.Product, out.Confidence = r.Protocol, r.Product, r.Confidence
		for i, name := range r.re.SubexpNames() {
			switch name {
			case "version":
				out.Version = matches[i]
			case "os":
				out.OSHint = matches[i]
			}
		}
		return out
	}
	return out
}

var mysqlVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-\w.]*)$`)
