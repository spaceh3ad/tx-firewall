// Package logging builds the application's slog logger from configuration.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/lmittmann/tint"
)

// New returns a logger writing to w.
// format: "pretty" (colored, for local dev), "text" or "json".
// level:  "debug", "info", "warn" or "error" (case-insensitive).
func New(w io.Writer, format, level string) (*slog.Logger, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("invalid log level %q: %w", level, err)
	}

	var h slog.Handler
	switch format {
	case "pretty":
		h = tint.NewHandler(w, &tint.Options{Level: lvl, TimeFormat: time.TimeOnly})
	case "text":
		h = slog.NewTextHandler(w, &slog.HandlerOptions{Level: lvl})
	case "json":
		h = slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lvl})
	default:
		return nil, fmt.Errorf("invalid log format %q (want pretty, text or json)", format)
	}
	return slog.New(h), nil
}
