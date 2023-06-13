package whalewall

import (
	"bytes"
	"strconv"
	"strings"

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

		e1Lookup, e1LookupOk := r1.Exprs[i].(*expr.Lookup)
		e2Lookup, e2LookupOk := r2.Exprs[i].(*expr.Lookup)
		// expressions are not of same type, rules are different
		if e1LookupOk != e2LookupOk {
			return false
		}
		if e1LookupOk && e2LookupOk {
			if e1Lookup.SourceRegister != e2Lookup.SourceRegister {
				return false
			}
			if e1Lookup.DestRegister != e2Lookup.DestRegister {
				return false
			}
			if e1Lookup.IsDestRegSet != e2Lookup.IsDestRegSet {
				return false
			}
			if e1Lookup.Invert != e2Lookup.Invert {
				return false
			}

			// Anonymous set names are set to "__set%d" initially and nftables
			// will change the set name when the rule is created, so the same
			// lookup expression before and after getting created can be slightly
			// different. We can't know before the rule is created what the set
			// name will be changed to, so if that's the only difference treat
			// these expressions as the same.
			if e1Lookup.SetName != e2Lookup.SetName {
				if e1Lookup.SetName == "__set%d" {
					if strings.HasPrefix(e2Lookup.SetName, "__set") {
						if _, err := strconv.ParseUint(e2Lookup.SetName[5:], 10, 64); err == nil {
							continue
						}
					}
				}
				if e2Lookup.SetName == "__set%d" {
					if strings.HasPrefix(e1Lookup.SetName, "__set") {
						if _, err := strconv.ParseUint(e1Lookup.SetName[5:], 10, 64); err == nil {
							continue
						}
					}
				}

				return false
			}
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
