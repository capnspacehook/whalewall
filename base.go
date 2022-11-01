package main

import (
	"errors"
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"go.uber.org/zap"
)

const (
	filterTableName      = "filter"
	dockerChainName      = "DOCKER-USER"
	inputChainName       = "INPUT"
	outputChainName      = "OUTPUT"
	whalewallChainName   = "whalewall"
	containerAddrSetName = "whalewall-container-addrs"
)

var (
	filterTable = &nftables.Table{
		Name:   filterTableName,
		Family: nftables.TableFamilyIPv4,
	}
	whalewallChain = &nftables.Chain{
		Name:  whalewallChainName,
		Table: filterTable,
		Type:  nftables.ChainTypeFilter,
	}
	containerAddrSet = &nftables.Set{
		Table:    filterTable,
		Name:     containerAddrSetName,
		IsMap:    true,
		KeyType:  nftables.TypeIPAddr,
		DataType: nftables.TypeVerdict,
	}

	srcJumpRule = &nftables.Rule{
		Table: filterTable,
		Chain: whalewallChain,
		Exprs: []expr.Any{
			// [ payload load 4b @ network header + 12 => reg 1 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           4,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        12,
				DestRegister:  1,
			},
			// [ lookup reg 1 set ... dreg 0 0x0 ]
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        containerAddrSetName,
				DestRegister:   0,
				IsDestRegSet:   true,
			},
		},
	}
	dstJumpRule = &nftables.Rule{
		Table: filterTable,
		Chain: whalewallChain,
		Exprs: []expr.Any{
			// [ payload load 4b @ network header + 16 => reg 1 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           4,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        16,
				DestRegister:  1,
			},
			// [ lookup reg 1 set ... dreg 0 0x0 ]
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        containerAddrSetName,
				DestRegister:   0,
				IsDestRegSet:   true,
			},
		},
	}
)

func (r *ruleManager) createBaseRules() error {
	nfc, err := nftables.New()
	if err != nil {
		return fmt.Errorf("error creating netlink connection: %w", err)
	}

	chains, err := nfc.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("error listing IPv4 chains: %w", err)
	}
	var (
		whalewallChainFound bool
		dockerChain         *nftables.Chain
		inputChain          *nftables.Chain
		outputChain         *nftables.Chain
	)
	for _, c := range chains {
		if c.Table.Name != filterTableName {
			continue
		}

		switch c.Name {
		case dockerChainName:
			dockerChain = c
		case whalewallChainName:
			whalewallChainFound = true
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
	var mainChainRules []*nftables.Rule
	var addContainerJumpRules bool
	if !whalewallChainFound {
		nfc.AddChain(whalewallChain)
		addContainerJumpRules = true
	} else {
		mainChainRules, err = nfc.GetRules(filterTable, whalewallChain)
		if err != nil {
			return fmt.Errorf("error listing rules of %q chain: %w", whalewallChainName, err)
		}
		if len(mainChainRules) == 0 {
			addContainerJumpRules = true
		}
	}

	// add rule to jump from DOCKER-USER chain to whalewall chain
	dockerRules, err := nfc.GetRules(filterTable, dockerChain)
	if err != nil {
		return fmt.Errorf("error listing rules of %q chain: %w", dockerChainName, err)
	}
	dockerUserJumpRule := createJumpRule(dockerChain, whalewallChainName)
	if !findRule(r.logger, dockerUserJumpRule, dockerRules) {
		nfc.InsertRule(dockerUserJumpRule)
	}

	// add rule to jump from INPUT/OUTPUT chains to whalewall chain
	handleMainChain := func(name string, hook *nftables.ChainHook, mainChain *nftables.Chain) error {
		if mainChain == nil {
			r.logger.Debug("creating chain", zap.String("chain.name", name))
			// INPUT and OUTPUT sometimes don't exist in nftables
			mainChain = &nftables.Chain{
				Name:     name,
				Table:    filterTable,
				Hooknum:  hook,
				Priority: nftables.ChainPriorityFilter,
				Type:     nftables.ChainTypeFilter,
				Policy:   ref(nftables.ChainPolicyAccept),
			}
			nfc.AddChain(mainChain)
		}

		rules, err := nfc.GetRules(filterTable, mainChain)
		if err != nil {
			return fmt.Errorf("error listing rules of %q chain: %w", name, err)
		}
		jumpRule := createJumpRule(mainChain, whalewallChainName)
		if !findRule(r.logger, jumpRule, rules) {
			nfc.InsertRule(jumpRule)
		}

		return nil
	}
	if err := handleMainChain(inputChainName, nftables.ChainHookInput, inputChain); err != nil {
		return err
	}
	if err := handleMainChain(outputChainName, nftables.ChainHookOutput, outputChain); err != nil {
		return err
	}

	// create a map that maps container IPs to their respective chain
	if err := nfc.AddSet(containerAddrSet, nil); err != nil {
		return fmt.Errorf("error adding set %q: %w", containerAddrSetName, err)
	}

	// create rules to jump to container chain if packet is from/to a container
	if addContainerJumpRules || !findRule(r.logger, srcJumpRule, mainChainRules) {
		nfc.AddRule(srcJumpRule)
	}

	if addContainerJumpRules || !findRule(r.logger, dstJumpRule, mainChainRules) {
		nfc.AddRule(dstJumpRule)
	}

	if err := nfc.Flush(); err != nil {
		return fmt.Errorf("error flushing nftables commands: %w", err)
	}

	return nil
}

func createJumpRule(srcChain *nftables.Chain, dstChainName string) *nftables.Rule {
	return &nftables.Rule{
		Table: filterTable,
		Chain: srcChain,
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: dstChainName,
			},
		},
	}
}
