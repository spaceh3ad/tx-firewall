package rules

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spaceh3ad/tx-firewall/internal/analysis"
	"github.com/spaceh3ad/tx-firewall/internal/events"
)

var (
	vault = common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3")
	fresh = common.HexToAddress("0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512")
	role  = common.HexToHash("0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6")
)

func withPrivileged(created []common.Address, pcs ...events.PrivilegeChange) *analysis.Analysis {
	a := txFrom(alice, &vault)
	a.Created = created
	a.Privileged = pcs
	return a
}

func TestPrivilegeChange(t *testing.T) {
	cases := map[string]struct {
		a           *analysis.Analysis
		wantReasons []string // empty: no finding
	}{
		"no events": {withPrivileged(nil), nil},
		"ownership transfer": {
			withPrivileged(nil, events.PrivilegeChange{Kind: events.OwnershipTransferred, Contract: vault, Previous: alice, Subject: carol}),
			[]string{"ownership of " + vault.Hex() + " transferred to " + carol.Hex()},
		},
		"proxy upgrade": {
			withPrivileged(nil, events.PrivilegeChange{Kind: events.Upgraded, Contract: vault, Subject: fresh}),
			[]string{vault.Hex() + " upgraded to implementation " + fresh.Hex()},
		},
		"admin change": {
			withPrivileged(nil, events.PrivilegeChange{Kind: events.AdminChanged, Contract: vault, Subject: carol}),
			[]string{"admin of " + vault.Hex() + " changed to " + carol.Hex()},
		},
		"role grant": {
			withPrivileged(nil, events.PrivilegeChange{Kind: events.RoleGranted, Contract: vault, Role: role, Subject: carol}),
			[]string{"role " + role.Hex(), "granted to " + carol.Hex()},
		},
		"constructor of a contract deployed in this tx": {
			withPrivileged([]common.Address{fresh}, events.PrivilegeChange{Kind: events.OwnershipTransferred, Contract: fresh, Subject: alice}),
			nil,
		},
		"existing contract changed by a freshly deployed one": {
			withPrivileged([]common.Address{fresh}, events.PrivilegeChange{Kind: events.OwnershipTransferred, Contract: vault, Subject: fresh}),
			[]string{"ownership of " + vault.Hex() + " transferred to " + fresh.Hex()},
		},
		"several changes, one finding": {
			withPrivileged(nil,
				events.PrivilegeChange{Kind: events.Upgraded, Contract: vault, Subject: fresh},
				events.PrivilegeChange{Kind: events.AdminChanged, Contract: vault, Subject: carol},
			),
			[]string{"upgraded to implementation", "admin of"},
		},
	}
	rule := NewPrivilegeChange()
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			findings, err := rule.Evaluate(t.Context(), tc.a)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(tc.wantReasons) == 0 {
				if len(findings) != 0 {
					t.Errorf("unexpected findings: %+v", findings)
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
			}
			f := findings[0]
			if f.Weight != WeightHigh || f.HardBlock || f.Rule != rule.Name() {
				t.Errorf("finding = %+v, want a high-weight %s finding", f, rule.Name())
			}
			for _, want := range tc.wantReasons {
				if !strings.Contains(f.Reason, want) {
					t.Errorf("reason %q does not contain %q", f.Reason, want)
				}
			}
		})
	}
}

// For any set of privilege changes: the rule fires exactly when at least one
// comes from a contract not deployed in this transaction, and then only once.
func FuzzPrivilegeChange(f *testing.F) {
	f.Add([]byte{0x00}, uint8(0))
	f.Add([]byte{0x05, 0x12}, uint8(1))
	f.Add([]byte{0x03, 0x03}, uint8(0xff))

	contracts := []common.Address{vault, fresh, carol, bob}
	kinds := []events.PrivilegeKind{events.OwnershipTransferred, events.Upgraded, events.AdminChanged, events.RoleGranted}

	f.Fuzz(func(t *testing.T, raw []byte, createdMask uint8) {
		var created []common.Address
		for i, c := range contracts {
			if createdMask&(1<<i) != 0 {
				created = append(created, c)
			}
		}
		var pcs []events.PrivilegeChange
		wantFire := false
		for _, b := range raw {
			pc := events.PrivilegeChange{Kind: kinds[b&0x03], Contract: contracts[(b>>2)&0x03], Subject: alice}
			pcs = append(pcs, pc)
			if createdMask&(1<<((b>>2)&0x03)) == 0 {
				wantFire = true
			}
		}

		findings, err := NewPrivilegeChange().Evaluate(t.Context(), withPrivileged(created, pcs...))
		if err != nil {
			t.Fatal(err)
		}
		if got := len(findings) == 1; got != wantFire || len(findings) > 1 {
			t.Fatalf("got %d findings, want fire=%v", len(findings), wantFire)
		}
	})
}
