package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

const (
	filterTableName     = "filter"
	dockerUserChainName = "DOCKER-USER"
	chainName           = "whalewall"
	ipv4DropSetName     = "whalewall-ipv4-drop"
)

func (r *ruleManager) createBaseRules() error {
	ipv4Table := &nftables.Table{
		Name:   filterTableName,
		Family: nftables.TableFamilyIPv4,
	}

	// create set
	r.dropSet = &nftables.Set{
		Name:    ipv4DropSetName,
		Table:   ipv4Table,
		KeyType: nftables.TypeIPAddr,
	}
	if err := r.createSet(r.dropSet); err != nil {
		return err
	}

	if err := r.nfc.Flush(); err != nil {
		return fmt.Errorf("error creating sets: %v", err)
	}

	// get or create whalewall chain
	chains, err := r.nfc.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("error listing IPv4 chains: %v", err)
	}
	var dockerChain *nftables.Chain
	for _, c := range chains {
		if c.Name == dockerUserChainName {
			dockerChain = c
		} else if c.Name == chainName {
			r.chain = c
		}
	}
	if dockerChain == nil {
		return errors.New("couldn't find required Docker chain, is Docker running?")
	}

	var ourRules []*nftables.Rule
	var addDropRules bool
	if r.chain == nil {
		r.chain = r.nfc.AddChain(&nftables.Chain{
			Name:   chainName,
			Table:  ipv4Table,
			Type:   nftables.ChainTypeFilter,
			Legacy: true,
		})
		addDropRules = true
	} else {
		ourRules, err = r.nfc.GetRules(ipv4Table, r.chain)
		if err != nil {
			return fmt.Errorf("error listing rules of %q chain: %v", chainName, err)
		}
		if len(ourRules) == 0 {
			addDropRules = true
		}
	}

	// add rule to jump to whalewall chain from DOCKER-USER
	dockerRules, err := r.nfc.GetRules(ipv4Table, dockerChain)
	if err != nil {
		return fmt.Errorf("error listing rules of %q chain: %v", dockerUserChainName, err)
	}

	jumpRule := &nftables.Rule{
		Table: ipv4Table,
		Chain: dockerChain,
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: chainName,
			},
		},
	}
	if !findRule(jumpRule, dockerRules) {
		r.nfc.InsertRule(jumpRule)
	}

	// ip saddr @whalewall-ipv4-drop drop
	dropSrcRule := &nftables.Rule{
		Table: ipv4Table,
		Chain: r.chain,
		Exprs: []expr.Any{
			// [ payload load 4b @ network header + 12 => reg 1 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           4,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        12,
				DestRegister:  1,
			},
			// [ lookup reg 1 set whalewall-ipv4-drop 0x0 ]
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        ipv4DropSetName,
				DestRegister:   0,
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	}
	if addDropRules || !findRule(dropSrcRule, ourRules) {
		r.nfc.AddRule(dropSrcRule)
	}

	// ip daddr @whalewall-ipv4-drop drop
	dropDstRule := &nftables.Rule{
		Table: ipv4Table,
		Chain: r.chain,
		Exprs: []expr.Any{
			// [ payload load 4b @ network header + 16 => reg 1 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           4,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        16,
				DestRegister:  1,
			},
			// [ lookup reg 1 set whalewall-ipv4-drop 0x0 ]
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        ipv4DropSetName,
				DestRegister:   0,
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	}
	if addDropRules || !findRule(dropDstRule, ourRules) {
		r.nfc.AddRule(dropDstRule)
	}

	if err := r.nfc.Flush(); err != nil {
		return fmt.Errorf("error flushing commands: %v", err)
	}

	return nil
}

func (r *ruleManager) createSet(set *nftables.Set) error {
	if err := r.nfc.AddSet(set, nil); err != nil {
		return fmt.Errorf("error creating set %s: %v", set.Name, err)
	}
	return nil
}

func findRule(rule *nftables.Rule, rules []*nftables.Rule) bool {
	for i := range rules {
		if rulesEqual(rule, rules[i]) {
			rule.Position = rules[i].Position
			rule.Handle = rules[i].Handle
			return true
		}
	}

	return false
}

func rulesEqual(r1, r2 *nftables.Rule) bool {
	if len(r1.Exprs) != len(r2.Exprs) {
		return false
	}

	for i := range r1.Exprs {
		// skip comparing counters, they will probably have different
		// number of packets/bytes counted
		if _, ok := r1.Exprs[i].(*expr.Counter); ok {
			continue
		}
		if _, ok := r2.Exprs[i].(*expr.Counter); ok {
			continue
		}

		exprb1, err := expr.Marshal(byte(r1.Table.Family), r1.Exprs[i])
		if err != nil {
			log.Printf("error marshalling rule: %v", err)
			continue
		}
		exprb2, err := expr.Marshal(byte(r2.Table.Family), r2.Exprs[i])
		if err != nil {
			log.Printf("error marshalling rule: %v", err)
			continue
		}
		if !bytes.Equal(exprb1, exprb2) {
			return false
		}
	}

	return true
}
