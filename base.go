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
	filterTableName = "filter"
	dockerChainName = "DOCKER-USER"
	inputChainName  = "INPUT"
	outputChainName = "OUTPUT"
	chainName       = "whalewall"
	dropSetName     = "whalewall-ipv4-drop"
)

func (r *ruleManager) createBaseRules() error {
	filterTable := &nftables.Table{
		Name:   filterTableName,
		Family: nftables.TableFamilyIPv4,
	}

	chains, err := r.nfc.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("error listing IPv4 chains: %v", err)
	}
	var (
		dockerChain *nftables.Chain
		inputChain  *nftables.Chain
		outputChain *nftables.Chain
	)
	for _, c := range chains {
		if c.Table.Name != filterTableName {
			continue
		}

		switch c.Name {
		case dockerChainName:
			dockerChain = c
		case chainName:
			r.chain = c
		case inputChainName:
			inputChain = c
		case outputChainName:
			outputChain = c
		}
	}
	if dockerChain == nil {
		return errors.New("couldn't find required Docker chain, is Docker running?")
	}

	// get or create whalewall chain
	var ourRules []*nftables.Rule
	var addDropRules bool
	if r.chain == nil {
		r.chain = r.nfc.AddChain(&nftables.Chain{
			Name:  chainName,
			Table: filterTable,
			Type:  nftables.ChainTypeFilter,
		})
		addDropRules = true
	} else {
		ourRules, err = r.nfc.GetRules(filterTable, r.chain)
		if err != nil {
			return fmt.Errorf("error listing rules of %q chain: %v", chainName, err)
		}
		if len(ourRules) == 0 {
			addDropRules = true
		}
	}

	// add rule to jump from DOCKER-USER chain to whalewall chain
	dockerRules, err := r.nfc.GetRules(filterTable, dockerChain)
	if err != nil {
		return fmt.Errorf("error listing rules of %q chain: %v", dockerChainName, err)
	}
	jumpRule := &nftables.Rule{
		Table: filterTable,
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

	// add rule to jump from INPUT/OUTPUT chains to whalewall chain
	handleMainChain := func(name string, hook *nftables.ChainHook, mainChain *nftables.Chain) error {
		if mainChain == nil {
			log.Printf("creating %s chain", name)
			// INPUT and OUTPUT sometimes don't exist in nftables
			mainChain = &nftables.Chain{
				Name:     name,
				Table:    filterTable,
				Hooknum:  hook,
				Priority: nftables.ChainPriorityFilter,
				Type:     nftables.ChainTypeFilter,
				Policy:   ref(nftables.ChainPolicyAccept),
			}
			r.nfc.AddChain(mainChain)
		}

		rules, err := r.nfc.GetRules(filterTable, mainChain)
		if err != nil {
			return fmt.Errorf("error listing rules of %q chain: %v", name, err)
		}
		jumpRule.Chain = mainChain
		if !findRule(jumpRule, rules) {
			r.nfc.InsertRule(jumpRule)
		}

		return nil
	}
	if err := handleMainChain(inputChainName, nftables.ChainHookInput, inputChain); err != nil {
		return err
	}
	if err := handleMainChain(outputChainName, nftables.ChainHookOutput, outputChain); err != nil {
		return err
	}

	r.dropSet = &nftables.Set{
		Name:    dropSetName,
		Table:   filterTable,
		KeyType: nftables.TypeIPAddr,
	}
	// create set that will hold all IPs of currently running containers
	// that have whalewall enabled
	if err := r.createSet(r.dropSet); err != nil {
		return err
	}

	// create rules that will drop any traffic to or from whalewall
	// enabled containers, these will be the last rules in the chain
	// ip saddr @whalewall-ipv4-drop drop
	dropSrcRule := &nftables.Rule{
		Table: filterTable,
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
				SetName:        dropSetName,
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
		Table: filterTable,
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
				SetName:        dropSetName,
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
		return fmt.Errorf("error flushing nftables commands: %v", err)
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
