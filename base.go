package main

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	filterTableName   = "filter"
	chainName         = "whalewall"
	ipv4InputMapName  = "whalewall-ipv4-input-allow"
	ipv4OutputMapName = "whalewall-ipv4-output-allow"
	ipv4DropSetName   = "whalewall-ipv4-drop"
)

func (r *ruleManager) createBaseRules() error {
	// get ipv4 filter table
	tables, err := r.nfc.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("error listing IPv4 tables: %v", err)
	}
	var ipv4Table *nftables.Table
	for _, t := range tables {
		if t.Name == filterTableName {
			ipv4Table = t
			break
		}
	}

	// create sets/maps

	// type ipv4_addr . inet_proto . inet_service . ct_state : verdict
	setType, err := nftables.ConcatSetType(
		nftables.TypeIPAddr,
		nftables.TypeInetProto,
		nftables.TypeInetService,
		nftables.TypeCTState,
	)
	if err != nil {
		return fmt.Errorf("error building set type: %v", err)
	}

	r.inputAllowSet = &nftables.Set{
		Table:         ipv4Table,
		Name:          ipv4InputMapName,
		IsMap:         true,
		Concatenation: true,
		KeyType:       setType,
		DataType:      nftables.TypeVerdict,
	}
	if err := r.createSet(r.inputAllowSet); err != nil {
		return err
	}
	r.outputAllowSet = &nftables.Set{
		Table:         ipv4Table,
		Name:          ipv4OutputMapName,
		IsMap:         true,
		Concatenation: true,
		KeyType:       setType,
		DataType:      nftables.TypeVerdict,
	}
	if err := r.createSet(r.outputAllowSet); err != nil {
		return err
	}

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
	var chain *nftables.Chain
	for _, c := range chains {
		if c.Name == chainName {
			chain = c
			break
		}
	}
	// TODO: check if all rules are added if chain exists
	if chain == nil {
		chain = r.nfc.AddChain(&nftables.Chain{
			Name:     chainName,
			Table:    ipv4Table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookInput,
			Priority: nftables.ChainPriorityFilter,
		})
	}

	// ip daddr . ip protocol . tcp sport . ct state vmap @whalewall-ipv4-input-allow
	r.nfc.AddRule(&nftables.Rule{
		Table: ipv4Table,
		Chain: chain,
		Exprs: []expr.Any{
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{
				Key:      expr.MetaKeyL4PROTO,
				Register: 1,
			},
			// [ cmp eq reg 1 0x00000006 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
			// [ payload load 4b @ network header + 16 => reg 1 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           4,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        16,
				DestRegister:  1,
			},
			// [ payload load 1b @ network header + 9 => reg 9 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           1,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        9,
				DestRegister:  9,
			},
			// [ payload load 2b @ transport header + 0 => reg 10 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           2,
				Base:          expr.PayloadBaseTransportHeader,
				Offset:        0,
				DestRegister:  10,
			},
			// [ ct load state => reg 11 ]
			&expr.Ct{
				Key:      expr.CtKeySTATE,
				Register: 11,
			},
			// [ lookup reg 1 set whalewall-ipv4-input-allow dreg 0 0x0 ]
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        ipv4InputMapName,
				DestRegister:   0,
				IsDestRegSet:   true,
			},
		},
	})

	// ip daddr . ip protocol . udp sport . ct state vmap @whalewall-ipv4-input-allow
	r.nfc.AddRule(&nftables.Rule{
		Table: ipv4Table,
		Chain: chain,
		Exprs: []expr.Any{
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{
				Key:      expr.MetaKeyL4PROTO,
				Register: 1,
			},
			// [ cmp eq reg 1 0x00000011 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_UDP},
			},
			// [ payload load 4b @ network header + 16 => reg 1 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           4,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        16,
				DestRegister:  1,
			},
			// [ payload load 1b @ network header + 9 => reg 9 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           1,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        9,
				DestRegister:  9,
			},
			// [ payload load 2b @ transport header + 0 => reg 10 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           2,
				Base:          expr.PayloadBaseTransportHeader,
				Offset:        0,
				DestRegister:  10,
			},
			// [ ct load state => reg 11 ]
			&expr.Ct{
				Key:      expr.CtKeySTATE,
				Register: 11,
			},
			// [ lookup reg 1 set whalewall-ipv4-input-allow dreg 0 0x0 ]
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        "whalewall-ipv4-input-allow",
				DestRegister:   0,
				IsDestRegSet:   true,
			},
		},
	})

	// ip saddr . ip protocol . tcp dport . ct state vmap @whalewall-ipv4-output-allow
	r.nfc.AddRule(&nftables.Rule{
		Table: ipv4Table,
		Chain: chain,
		Exprs: []expr.Any{
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{
				Key:      expr.MetaKeyL4PROTO,
				Register: 1,
			},
			// [ cmp eq reg 1 0x00000006 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
			// [ payload load 4b @ network header + 12 => reg 1 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           4,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        12,
				DestRegister:  1,
			},
			// [ payload load 1b @ network header + 9 => reg 9 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           1,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        9,
				DestRegister:  9,
			},
			// [ payload load 2b @ transport header + 2 => reg 10 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           2,
				Base:          expr.PayloadBaseTransportHeader,
				Offset:        2,
				DestRegister:  10,
			},
			// [ ct load state => reg 11 ]
			&expr.Ct{
				Key:      expr.CtKeySTATE,
				Register: 11,
			},
			// [ lookup reg 1 set whalewall-ipv4-output-allow dreg 0 0x0 ]
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        "whalewall-ipv4-output-allow",
				DestRegister:   0,
				IsDestRegSet:   true,
			},
		},
	})

	// ip saddr . ip protocol . udp dport . ct state vmap @whalewall-ipv4-output-allow
	r.nfc.AddRule(&nftables.Rule{
		Table: ipv4Table,
		Chain: chain,
		Exprs: []expr.Any{
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{
				Key:      expr.MetaKeyL4PROTO,
				Register: 1,
			},
			// [ cmp eq reg 1 0x00000011 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_UDP},
			},
			// [ payload load 4b @ network header + 12 => reg 1 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           4,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        12,
				DestRegister:  1,
			},
			// [ payload load 1b @ network header + 9 => reg 9 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           1,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        9,
				DestRegister:  9,
			},
			// [ payload load 2b @ transport header + 2 => reg 10 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           2,
				Base:          expr.PayloadBaseTransportHeader,
				Offset:        2,
				DestRegister:  10,
			},
			// [ ct load state => reg 11 ]
			&expr.Ct{
				Key:      expr.CtKeySTATE,
				Register: 11,
			},
			// [ lookup reg 1 set whalewall-ipv4-output-allow dreg 0 0x0 ]
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        "whalewall-ipv4-output-allow",
				DestRegister:   0,
				IsDestRegSet:   true,
			},
		},
	})

	// ip saddr @whalewall-ipv4-drop drop
	r.nfc.AddRule(&nftables.Rule{
		Table: ipv4Table,
		Chain: chain,
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
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	})

	// ip daddr @whalewall-ipv4-drop drop
	r.nfc.AddRule(&nftables.Rule{
		Table: ipv4Table,
		Chain: chain,
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
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	})

	if err := r.nfc.Flush(); err != nil {
		return fmt.Errorf("error creating rules: %v", err)
	}

	return nil
}

func (r *ruleManager) createSet(set *nftables.Set) error {
	if err := r.nfc.AddSet(set, nil); err != nil {
		return fmt.Errorf("error creating set %s: %v", set.Name, err)
	}
	return nil
}
