package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"banner-fingerprint/fingerprint"
)

func TestContentTypeAndUnknown(t *testing.T) {
	m, err := fingerprint.Load("../../rules.json")
	if err != nil {
		t.Fatal(err)
	}
	h := handler(m)
	for _, tc := range []struct {
		body, contentType string
		status            int
		contains          string
	}{
		{`[{"ip":"1.2.3.4","port":22,"banner":"unrecognized"}]`, "application/json; charset=utf-8", 200, `"protocol":"unknown"`},
		{`[]`, "application/json", 200, `[]`},
		{`{}`, "application/json", 400, ""},
		{`null`, "application/json", 400, ""},
		{`[] []`, "application/json", 400, ""},
		{`[]`, "text/plain", 415, ""},
	} {
		req := httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(tc.body))
		req.Header.Set("Content-Type", tc.contentType)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.contains) {
			t.Errorf("%q %q: status=%d body=%q", tc.body, tc.contentType, w.Code, w.Body.String())
		}
	}
}
