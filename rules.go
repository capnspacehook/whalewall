package whalewall

import (
	"bytes"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"go.uber.org/zap"
)

// findRule returns true if rule is contained within rules. If rule is
// found, its Position and Handle will be set to match its counterpart
// in rules.
func findRule(logger *zap.Logger, rule *nftables.Rule, rules []*nftables.Rule) bool {
	for i := range rules {
		if rulesEqual(logger, rule, rules[i]) {
			rule.Position = rules[i].Position
			rule.Handle = rules[i].Handle
			return true
		}
	}

	return false
}

// rulesEqual returns true if r1 and r2 are semantically equal to one
// another.
func rulesEqual(logger *zap.Logger, r1, r2 *nftables.Rule) bool {
	if len(r1.Exprs) != len(r2.Exprs) {
		return false
	}

	for i := range r1.Exprs {
		_, e1Ctr := r1.Exprs[i].(*expr.Counter)
		_, e2Ctr := r2.Exprs[i].(*expr.Counter)
		// expressions are not of same type, rules are different
		if e1Ctr != e2Ctr {
			return false
		}
		// skip comparing counters, they will probably have different
		// number of packets/bytes counted
		if e1Ctr && e2Ctr {
			continue
		}

		exprb1, err := expr.Marshal(byte(r1.Table.Family), r1.Exprs[i])
		if err != nil {
			logger.Error("error marshaling rule", zap.Error(err))
			continue
		}
		exprb2, err := expr.Marshal(byte(r2.Table.Family), r2.Exprs[i])
		if err != nil {
			logger.Error("error marshaling rule", zap.Error(err))
			continue
		}
		if !bytes.Equal(exprb1, exprb2) {
			return false
		}
	}

	return true
}
