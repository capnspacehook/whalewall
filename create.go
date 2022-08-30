package main

import (
	"encoding/binary"
	"log"
	"net/netip"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

const (
	srcAddrOffset = 12
	dstAddrOffset = 16
	srcPortOffset = 0
	dstPortOffset = 2
)

func (r *ruleManager) createRules(ch <-chan *types.ContainerJSON) {
	for container := range ch {
		containerName := strings.Replace(container.Name, "/", "", 1) // container name appears with prefix "/"
		log.Printf("adding rules for %q", containerName)

		cfg := container.Config.Labels[rulesLabel]
		var rulesCfg containerRules
		if err := yaml.Unmarshal([]byte(cfg), &rulesCfg); err != nil {
			log.Printf("error parsing rules: %v", err)
			continue
		}

		addrs := make(map[string][]byte, len(container.NetworkSettings.Networks))
		for netName, netSettings := range container.NetworkSettings.Networks {
			addr, err := netip.ParseAddr(netSettings.IPAddress)
			if err != nil {
				log.Printf("error parsing container IP: %v", err)
				continue
			}
			log.Printf("%s: %s", netName, addr)
			addrs[netName] = ref(addr.As4())[:]
		}

		// TODO: handle IPv6
		var nftRules []*nftables.Rule

		// handle outbound rules
		for _, ruleCfg := range rulesCfg.Output {
			if ruleCfg.Network != "" {
				nftRules = append(nftRules, r.createNFTRules(false, addrs[ruleCfg.Network], ruleCfg)...)
			} else {
				for _, addr := range addrs {
					nftRules = append(nftRules, r.createNFTRules(false, addr, ruleCfg)...)
				}
			}
		}

		// handle inbound rules
		for _, ruleCfg := range rulesCfg.Input {
			if ruleCfg.Network != "" {
				nftRules = append(nftRules, r.createNFTRules(true, addrs[ruleCfg.Network], ruleCfg)...)
			} else {
				for _, addr := range addrs {
					nftRules = append(nftRules, r.createNFTRules(true, addr, ruleCfg)...)
				}
			}
		}

		// handle deny all out
		elements := make([]nftables.SetElement, 0, len(addrs))
		for _, addr := range addrs {
			elements = append(elements, nftables.SetElement{
				Key: addr,
			})
		}

		err := r.nfc.SetAddElements(r.dropSet, elements)
		if err != nil {
			log.Printf("error adding set elements: %v", err)
			continue
		}

		// insert rules in reverse order that they were created in to maintain order
		for i := len(nftRules) - 1; i >= 0; i-- {
			r.nfc.InsertRule(nftRules[i])
		}

		if err := r.nfc.Flush(); err != nil {
			log.Printf("error flushing commands: %v", err)
			continue
		}

		c := &containerInfo{
			Name:  containerName,
			Addrs: addrs,
			Cfg:   rulesCfg,
			Rules: nftRules,
		}
		r.addContainer(container.ID, c)
	}
}

func (r *ruleManager) createNFTRules(inbound bool, addr []byte, cfg containerRule) []*nftables.Rule {
	return []*nftables.Rule{
		r.createNFTRule(inbound, true, addr, cfg),
		r.createNFTRule(!inbound, false, addr, cfg),
	}
}

func (r *ruleManager) createNFTRule(inbound, new bool, addr []byte, cfg containerRule) *nftables.Rule {
	addrOffset := srcAddrOffset
	portOffset := dstPortOffset
	if inbound {
		addrOffset = dstAddrOffset
		portOffset = srcPortOffset
	}
	proto := unix.IPPROTO_TCP
	if cfg.Proto == "udp" {
		proto = unix.IPPROTO_UDP
	}
	connState := expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED
	if new {
		connState |= expr.CtStateBitNEW
	}

	return &nftables.Rule{
		Table: r.chain.Table,
		Chain: r.chain,
		Exprs: []expr.Any{
			// [ payload load 4b @ network header + ... => reg 1 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           4,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        uint32(addrOffset),
				DestRegister:  1,
			},
			// [ cmp eq reg 1 ... ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     addr[:],
			},
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{
				Key:      expr.MetaKeyL4PROTO,
				Register: 1,
			},
			// [ cmp eq reg 1 ... ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{byte(proto)},
			},
			// [ payload load 2b @ transport header + 2 => reg 1 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           2,
				Base:          expr.PayloadBaseTransportHeader,
				Offset:        uint32(portOffset),
				DestRegister:  1,
			},
			// [ cmp eq reg 1 ... ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binary.BigEndian.AppendUint16(nil, cfg.Port),
			},
			// [ ct load state => reg 1 ]
			&expr.Ct{
				Key:      expr.CtKeySTATE,
				Register: 1,
			},
			// [ bitwise reg 1 = ( reg 1 & ... ) ^ 0x00000000 ]
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binary.LittleEndian.AppendUint32(nil, connState),
				Xor:            []byte{0, 0, 0, 0},
			},
			// [ cmp neq reg 1 0x00000000 ]
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0, 0, 0, 0},
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}
}

func ref[T any](v T) *T {
	return &v
}
