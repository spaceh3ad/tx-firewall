// Package sanctions answers whether a single address is sanctioned.
// Deciding which addresses of a transaction to check is up to the rules.
package sanctions

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// Checker reports whether an address is sanctioned.
type Checker interface {
	IsSanctioned(ctx context.Context, addr common.Address) (bool, error)
}

// ListChecker checks addresses against a fixed in-memory list.
type ListChecker struct {
	set map[common.Address]struct{}
}

var _ Checker = (*ListChecker)(nil)

// NewListChecker builds a checker from the given addresses.
func NewListChecker(addrs []common.Address) *ListChecker {
	set := make(map[common.Address]struct{}, len(addrs))
	for _, a := range addrs {
		set[a] = struct{}{}
	}
	return &ListChecker{set: set}
}

// LoadListChecker reads a list file with one address per line.
// Blank lines and everything after a '#' are ignored.
func LoadListChecker(path string) (*ListChecker, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open sanctions list: %w", err)
	}
	defer f.Close()

	addrs, err := parseList(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return NewListChecker(addrs), nil
}

func parseList(r io.Reader) ([]common.Address, error) {
	var addrs []common.Address
	scanner := bufio.NewScanner(r)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// HexToAddress never fails and silently mangles bad input, so validate first.
		if !common.IsHexAddress(line) {
			return nil, fmt.Errorf("line %d: invalid address %q", lineNo, line)
		}
		addrs = append(addrs, common.HexToAddress(line))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read sanctions list: %w", err)
	}
	return addrs, nil
}

// IsSanctioned is a single map lookup. The error is always nil here,
// but checkers that query the chain need it for failed RPC calls.
func (c *ListChecker) IsSanctioned(_ context.Context, addr common.Address) (bool, error) {
	_, ok := c.set[addr]
	return ok, nil
}

// Len returns the number of distinct addresses on the list.
func (c *ListChecker) Len() int {
	return len(c.set)
}
