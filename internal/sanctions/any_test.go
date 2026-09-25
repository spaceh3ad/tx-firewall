package sanctions

import (
	"context"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// stubChecker returns a fixed answer and counts how often it was asked.
type stubChecker struct {
	hit   bool
	err   error
	calls int
}

func (s *stubChecker) IsSanctioned(context.Context, common.Address) (bool, error) {
	s.calls++
	return s.hit, s.err
}

var errBackend = errors.New("backend unavailable")

func TestAnyChecker(t *testing.T) {
	cases := map[string]struct {
		checkers []*stubChecker
		wantHit  bool
		wantErr  bool
	}{
		"no checkers":      {nil, false, false},
		"all clean":        {[]*stubChecker{{}, {}}, false, false},
		"second hits":      {[]*stubChecker{{}, {hit: true}}, true, false},
		"error":            {[]*stubChecker{{}, {err: errBackend}}, false, true},
		"hit before error": {[]*stubChecker{{hit: true}, {err: errBackend}}, true, false},
		"error before hit": {[]*stubChecker{{err: errBackend}, {hit: true}}, false, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var c AnyChecker
			for _, s := range tc.checkers {
				c = append(c, s)
			}
			hit, err := c.IsSanctioned(t.Context(), alice)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if hit != tc.wantHit {
				t.Errorf("hit = %v, want %v", hit, tc.wantHit)
			}
		})
	}
}

func TestAnyCheckerStopsAtFirstHit(t *testing.T) {
	list, oracle := &stubChecker{hit: true}, &stubChecker{}
	if _, err := (AnyChecker{list, oracle}).IsSanctioned(t.Context(), alice); err != nil {
		t.Fatal(err)
	}
	if oracle.calls != 0 {
		t.Errorf("slower checker was called %d times after the first hit", oracle.calls)
	}
}

// Each byte picks a checker's answer: 0 clean, 1 hit, anything else an error.
// The result must match the first non-clean answer, and later checkers must not run.
func FuzzAnyChecker(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0})
	f.Add([]byte{0, 1, 2})
	f.Add([]byte{2, 1})

	f.Fuzz(func(t *testing.T, answers []byte) {
		stubs := make([]*stubChecker, len(answers))
		c := make(AnyChecker, len(answers))
		for i, a := range answers {
			stubs[i] = &stubChecker{hit: a == 1}
			if a > 1 {
				stubs[i].err = errBackend
			}
			c[i] = stubs[i]
		}

		hit, err := c.IsSanctioned(t.Context(), alice)

		wantHit, wantErr, decidedAt := false, false, len(answers)
		for i, a := range answers {
			if a != 0 {
				wantHit, wantErr, decidedAt = a == 1, a > 1, i
				break
			}
		}
		if hit != wantHit || (err != nil) != wantErr {
			t.Fatalf("got hit=%v err=%v, want hit=%v err=%v", hit, err, wantHit, wantErr)
		}
		if err != nil && hit {
			t.Fatal("an error must never report a hit")
		}
		for i, s := range stubs {
			wantCalls := 0
			if i <= decidedAt {
				wantCalls = 1
			}
			if s.calls != wantCalls {
				t.Fatalf("checker %d called %d times, want %d", i, s.calls, wantCalls)
			}
		}
	})
}
