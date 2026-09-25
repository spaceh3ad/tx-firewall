package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	tests := []struct {
		format, level string
		wantErr       bool
	}{
		{"pretty", "info", false},
		{"text", "DEBUG", false},
		{"json", "warn", false},
		{"json", "error", false},
		{"xml", "info", true},
		{"json", "verbose", true},
		{"json", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.format+"/"+tt.level, func(t *testing.T) {
			l, err := New(&bytes.Buffer{}, tt.format, tt.level)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && l == nil {
				t.Fatal("nil logger without error")
			}
		})
	}
}

func TestJSONOutputAndLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(&buf, "json", "warn")
	if err != nil {
		t.Fatal(err)
	}
	l.Info("dropped")
	l.With("component", "proxy").Warn("kept", "method", "eth_sendRawTransaction")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("want 1 line, got %d: %q", len(lines), buf.String())
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["msg"] != "kept" || rec["component"] != "proxy" || rec["level"] != "WARN" {
		t.Fatalf("unexpected record: %v", rec)
	}
}

// Any input must either yield a usable logger or an error, never panic.
func FuzzNew(f *testing.F) {
	for _, s := range [][2]string{{"json", "info"}, {"text", "debug+2"}, {"pretty", "ERROR"}, {"", ""}} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, format, level string) {
		var buf bytes.Buffer
		l, err := New(&buf, format, level)
		if err != nil {
			return
		}
		l.Error("probe")
		if buf.Len() == 0 {
			t.Fatalf("valid config (%q, %q) produced no output for Error", format, level)
		}
	})
}
