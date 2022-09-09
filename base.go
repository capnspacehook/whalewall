package main

import (
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
	mainChainName   = "whalewall"
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
		case mainChainName:
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
	if r.chain == nil {
		r.chain = r.nfc.AddChain(&nftables.Chain{
			Name:  mainChainName,
			Table: filterTable,
			Type:  nftables.ChainTypeFilter,
		})
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
				Chain: mainChainName,
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

	if err := r.nfc.Flush(); err != nil {
		return fmt.Errorf("error flushing nftables commands: %v", err)
	}

	return nil
}
