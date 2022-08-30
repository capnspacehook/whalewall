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

func (r *ruleManager) createUFWRules(ch <-chan *types.ContainerJSON) {
	for container := range ch {
		log.Printf("adding set elements for %q", container.Name)

		ruleCfg := container.Config.Labels[rulesLabel]
		var rules containerRules
		if err := yaml.Unmarshal([]byte(ruleCfg), &rules); err != nil {
			log.Printf("error parsing rules: %v", err)
			continue
		}

		containerName := strings.Replace(container.Name, "/", "", 1) // container name appears with prefix "/"
		containerIP := container.NetworkSettings.IPAddress
		containerID := container.ID[:12]
		// If docker-compose, container IP is defined here
		if containerIP == "" {
			networkMode := container.HostConfig.NetworkMode.NetworkName()
			if ip, ok := container.NetworkSettings.Networks[networkMode]; ok {
				containerIP = ip.IPAddress
			} else {
				log.Println("couldn't detect the container IP address")
				continue
			}
		}
		ip, err := netip.ParseAddr(containerIP)
		if err != nil {
			log.Printf("error parsing container IP: %v", err)
			continue
		}

		// TODO: handle IPv6
		var nftRules []*nftables.Rule
		addr := ip.As4()

		// handle inbound rules

		// handle outbound rules
		for _, rule := range rules.Output {
			// ip saddr SADDR PROTO dport PORT ct state new counter accept
			nftRule := &nftables.Rule{
				Table: r.chain.Table,
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
						Data:     []byte{unix.IPPROTO_TCP}, // TODO: make dynamic
					},
					// [ payload load 2b @ transport header + 2 => reg 1 ]
					&expr.Payload{
						OperationType: expr.PayloadLoad,
						Len:           2,
						Base:          expr.PayloadBaseTransportHeader,
						Offset:        2,
						DestRegister:  1,
					},
					// [ cmp eq reg 1 ... ]
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     binary.BigEndian.AppendUint16(nil, rule.Port),
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
						Mask:           binary.BigEndian.AppendUint32(nil, expr.CtStateBitNEW),
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

			r.nfc.AddRule(nftRule)
			nftRules = append(nftRules, nftRule)
		}

		// handle deny all out
		var element nftables.SetElement
		element.Key = addr[:]

		if err := r.nfc.SetAddElements(r.dropSet, []nftables.SetElement{element}); err != nil {
			log.Printf("error adding set elements: %v", err)
			continue
		}

		if err := r.nfc.Flush(); err != nil {
			log.Printf("error flushing set elements: %v", err)
			continue
		}

		c := &containerInfo{
			Name:   containerName,
			IP:     ip,
			Labels: container.Config.Labels,
			Rules:  rules,
		}
		r.addContainer(containerID, c)
	}
}
