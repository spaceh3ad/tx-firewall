package rules

import (
	"context"
	"fmt"
	"strings"

	"github.com/spaceh3ad/tx-firewall/internal/analysis"
	"github.com/spaceh3ad/tx-firewall/internal/events"
)

// PrivilegeChange flags transactions that change who controls a contract:
// ownership transfers, proxy upgrades, proxy admin changes and role grants.
// Events from contracts deployed in the same transaction are ignored, because
// constructors emit them while setting up the initial owner or implementation.
type PrivilegeChange struct{}

var _ Rule = PrivilegeChange{}

func NewPrivilegeChange() PrivilegeChange { return PrivilegeChange{} }

func (PrivilegeChange) Name() string { return "privilege-change" }

func (r PrivilegeChange) Evaluate(_ context.Context, a *analysis.Analysis) ([]Finding, error) {
	var changes []string
	for _, pc := range a.Privileged {
		if a.CreatedInTx(pc.Contract) {
			continue
		}
		changes = append(changes, describePrivilegeChange(pc))
	}
	if len(changes) == 0 {
		return nil, nil
	}
	return []Finding{{
		Rule:   r.Name(),
		Weight: WeightHigh,
		Reason: "privilege change: " + strings.Join(changes, ", "),
	}}, nil
}

func describePrivilegeChange(pc events.PrivilegeChange) string {
	contract := pc.Contract.Hex()
	switch pc.Kind {
	case events.OwnershipTransferred:
		return fmt.Sprintf("ownership of %s transferred to %s", contract, pc.Subject.Hex())
	case events.Upgraded:
		return fmt.Sprintf("%s upgraded to implementation %s", contract, pc.Subject.Hex())
	case events.AdminChanged:
		return fmt.Sprintf("admin of %s changed to %s", contract, pc.Subject.Hex())
	case events.RoleGranted:
		return fmt.Sprintf("role %s on %s granted to %s", pc.Role.Hex(), contract, pc.Subject.Hex())
	default:
		return fmt.Sprintf("%s on %s", pc.Kind, contract)
	}
}
