package sanctions

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

var (
	alice = common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	bob   = common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	carol = common.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
)

func writeList(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sanctions.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func isSanctioned(t *testing.T, c Checker, addr common.Address) bool {
	t.Helper()
	ok, err := c.IsSanctioned(t.Context(), addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return ok
}

func TestListChecker(t *testing.T) {
	c := NewListChecker([]common.Address{alice, bob, alice})

	if !isSanctioned(t, c, alice) || !isSanctioned(t, c, bob) {
		t.Error("listed address not reported as sanctioned")
	}
	if isSanctioned(t, c, carol) {
		t.Error("unlisted address reported as sanctioned")
	}
	if c.Len() != 2 {
		t.Errorf("Len = %d, want 2 (duplicates collapse)", c.Len())
	}
}

func TestLoadListChecker(t *testing.T) {
	path := writeList(t, strings.Join([]string{
		"# OFAC list",
		"",
		strings.ToLower(alice.Hex()),                         // all lowercase
		"  " + strings.ToUpper(bob.Hex()[2:]) + "  # inline", // uppercase, no 0x, padded
		carol.Hex() + "\r",                                   // Windows line ending
	}, "\n"))

	c, err := LoadListChecker(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, addr := range []common.Address{alice, bob, carol} {
		if !isSanctioned(t, c, addr) {
			t.Errorf("%s not loaded", addr)
		}
	}
	if c.Len() != 3 {
		t.Errorf("Len = %d, want 3", c.Len())
	}
}

func TestLoadListCheckerEmptyFile(t *testing.T) {
	c, err := LoadListChecker(writeList(t, "# nothing here\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Len() != 0 {
		t.Errorf("Len = %d, want 0", c.Len())
	}
}

func TestLoadListCheckerRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"too short":     "0x1234\n",
		"not hex":       "0xzz39Fd6e51aad88F6F4ce6aB8827279cffFb92266\n",
		"two per line":  alice.Hex() + " " + bob.Hex() + "\n",
		"bad after ok":  alice.Hex() + "\nnot-an-address\n",
		"too long":      alice.Hex() + "00\n",
		"comma list":    alice.Hex() + ",\n",
		"empty 0x only": "0x\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadListChecker(writeList(t, content)); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestLoadListCheckerMissingFile(t *testing.T) {
	if _, err := LoadListChecker(filepath.Join(t.TempDir(), "missing.txt")); err == nil {
		t.Error("expected an error")
	}
}

// Whatever the file contains, parsing must not panic, and every address it
// accepts must be found by the checker built from it.
func FuzzParseList(f *testing.F) {
	f.Add(alice.Hex() + "\n" + bob.Hex())
	f.Add("# comment\n\n" + strings.ToLower(carol.Hex()) + " # inline\n")
	f.Add("0x1234")
	f.Add("")

	f.Fuzz(func(t *testing.T, content string) {
		addrs, err := parseList(strings.NewReader(content))
		if err != nil {
			return
		}
		c := NewListChecker(addrs)
		for _, a := range addrs {
			if !isSanctioned(t, c, a) {
				t.Fatalf("parsed address %s not found", a)
			}
		}
	})
}

// However an address is written (case, 0x prefix, padding), it loads as the same address.
func FuzzParseListAddressSpelling(f *testing.F) {
	f.Add(alice.Bytes(), uint8(0))
	f.Add(bob.Bytes(), uint8(7))

	f.Fuzz(func(t *testing.T, raw []byte, style uint8) {
		want := common.BytesToAddress(raw)

		s := want.Hex()
		if style&1 != 0 {
			s = strings.ToLower(s)
		}
		if style&2 != 0 {
			s = strings.ToUpper(s[2:])
		}
		if style&4 != 0 {
			s = " \t" + s + " # note"
		}

		addrs, err := parseList(strings.NewReader(s))
		if err != nil {
			t.Fatalf("valid spelling %q rejected: %v", s, err)
		}
		if len(addrs) != 1 || addrs[0] != want {
			t.Fatalf("parsed %v from %q, want [%s]", addrs, s, want)
		}
	})
}
