package sanctions

import (
	"context"

	"github.com/ethereum/go-ethereum/common"
)

// AnyChecker reports an address as sanctioned if any of its checkers does.
// Checkers run in order and stop at the first hit, so put cheap ones first.
// Any error fails the whole check: an address we couldn't fully check is not clean.
type AnyChecker []Checker

var _ Checker = AnyChecker(nil)

func (c AnyChecker) IsSanctioned(ctx context.Context, addr common.Address) (bool, error) {
	for _, checker := range c {
		hit, err := checker.IsSanctioned(ctx, addr)
		if err != nil {
			return false, err
		}
		if hit {
			return true, nil
		}
	}
	return false, nil
}
