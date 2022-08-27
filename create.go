package main

import (
	"bytes"
	"fmt"
	"log"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/google/nftables"
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

	inputSet := &nftables.Set{
		Table:         ipv4Table,
		Name:          ipv4InputMapName,
		IsMap:         true,
		Concatenation: true,
		KeyType:       setType,
		DataType:      nftables.TypeVerdict,
	}
	if err := r.createSet(inputSet); err != nil {
		return err
	}
	outputSet := &nftables.Set{
		Table:         ipv4Table,
		Name:          ipv4OutputMapName,
		IsMap:         true,
		Concatenation: true,
		KeyType:       setType,
		DataType:      nftables.TypeVerdict,
	}
	if err := r.createSet(outputSet); err != nil {
		return err
	}

	dropSet := &nftables.Set{
		Name:    ipv4DropSetName,
		Table:   ipv4Table,
		KeyType: nftables.TypeIPAddr,
	}
	if err := r.createSet(dropSet); err != nil {
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

	// // ip daddr . ip protocol . tcp sport . ct state vmap @whalewall-ipv4-input-allow
	// r.nfc.AddRule(&nftables.Rule{
	// 	Table: ipv4Table,
	// 	Chain: chain,
	// 	Exprs: []expr.Any{
	// 		// [ meta load l4proto => reg 1 ]
	// 		&expr.Meta{
	// 			Key:      expr.MetaKeyL4PROTO,
	// 			Register: 1,
	// 		},
	// 		// [ cmp eq reg 1 0x00000006 ]
	// 		&expr.Cmp{
	// 			Op:       expr.CmpOpEq,
	// 			Register: 1,
	// 			Data:     []byte{0x6},
	// 		},
	// 		// [ payload load 4b @ network header + 16 => reg 1 ]
	// 		&expr.Payload{
	// 			OperationType: expr.PayloadLoad,
	// 			Len:           4,
	// 			Base:          expr.PayloadBaseNetworkHeader,
	// 			Offset:        16,
	// 			DestRegister:  1,
	// 		},
	// 		// [ payload load 1b @ network header + 9 => reg 9 ]
	// 		&expr.Payload{
	// 			OperationType: expr.PayloadLoad,
	// 			Len:           1,
	// 			Base:          expr.PayloadBaseNetworkHeader,
	// 			Offset:        9,
	// 			DestRegister:  9,
	// 		},
	// 		// [ payload load 2b @ transport header + 0 => reg 10 ]
	// 		&expr.Payload{
	// 			OperationType: expr.PayloadLoad,
	// 			Len:           2,
	// 			Base:          expr.PayloadBaseTransportHeader,
	// 			Offset:        0,
	// 			DestRegister:  10,
	// 		},
	// 		// [ ct load state => reg 11 ]
	// 		&expr.Ct{
	// 			Key:      expr.CtKeySTATE,
	// 			Register: 11,
	// 		},
	// 		// [ lookup reg 1 set whalewall-ipv4-input-allow dreg 0 0x0 ]
	// 		&expr.Lookup{
	// 			SourceRegister: 1,
	// 			SetName:        ipv4InputMapName,
	// 			DestRegister:   0,
	// 		},
	// 	},
	// })

	// // ip daddr . ip protocol . udp sport . ct state vmap @whalewall-ipv4-input-allow
	// r.nfc.AddRule(&nftables.Rule{
	// 	Table: ipv4Table,
	// 	Chain: chain,
	// 	Exprs: []expr.Any{
	// 		// [ meta load l4proto => reg 1 ]
	// 		&expr.Meta{
	// 			Key:      expr.MetaKeyL4PROTO,
	// 			Register: 1,
	// 		},
	// 		// [ cmp eq reg 1 0x00000011 ]
	// 		&expr.Cmp{
	// 			Op:       expr.CmpOpEq,
	// 			Register: 1,
	// 			Data:     []byte{0x11},
	// 		},
	// 		// [ payload load 4b @ network header + 16 => reg 1 ]
	// 		&expr.Payload{
	// 			OperationType: expr.PayloadLoad,
	// 			Len:           4,
	// 			Base:          expr.PayloadBaseNetworkHeader,
	// 			Offset:        10,
	// 			DestRegister:  1,
	// 		},
	// 		// [ payload load 1b @ network header + 9 => reg 9 ]
	// 		&expr.Payload{
	// 			OperationType: expr.PayloadLoad,
	// 			Len:           1,
	// 			Base:          expr.PayloadBaseNetworkHeader,
	// 			Offset:        9,
	// 			DestRegister:  9,
	// 		},
	// 		// [ payload load 2b @ transport header + 0 => reg 10 ]
	// 		&expr.Payload{
	// 			OperationType: expr.PayloadLoad,
	// 			Len:           2,
	// 			Base:          expr.PayloadBaseTransportHeader,
	// 			Offset:        0,
	// 			DestRegister:  10,
	// 		},
	// 		// [ ct load state => reg 11 ]
	// 		&expr.Ct{
	// 			Key:      expr.CtKeySTATE,
	// 			Register: 11,
	// 		},
	// 		// [ lookup reg 1 set whalewall-ipv4-input-allow dreg 0 0x0 ]
	// 		&expr.Lookup{
	// 			SourceRegister: 1,
	// 			SetName:        "whalewall-ipv4-input-allow",
	// 			DestRegister:   0,
	// 		},
	// 	},
	// })

	// // ip saddr . ip protocol . tcp dport . ct state vmap @whalewall-ipv4-output-allow
	// r.nfc.AddRule(&nftables.Rule{
	// 	Table: ipv4Table,
	// 	Chain: chain,
	// 	Exprs: []expr.Any{
	// 		// [ meta load l4proto => reg 1 ]
	// 		&expr.Meta{
	// 			Key:      expr.MetaKeyL4PROTO,
	// 			Register: 1,
	// 		},
	// 		// [ cmp eq reg 1 0x00000006 ]
	// 		&expr.Cmp{
	// 			Op:       expr.CmpOpEq,
	// 			Register: 1,
	// 			Data:     []byte{0x6},
	// 		},
	// 		// [ payload load 4b @ network header + 12 => reg 1 ]
	// 		&expr.Payload{
	// 			OperationType: expr.PayloadLoad,
	// 			Len:           4,
	// 			Base:          expr.PayloadBaseNetworkHeader,
	// 			Offset:        12,
	// 			DestRegister:  1,
	// 		},
	// 		// [ payload load 1b @ network header + 9 => reg 9 ]
	// 		&expr.Payload{
	// 			OperationType: expr.PayloadLoad,
	// 			Len:           1,
	// 			Base:          expr.PayloadBaseNetworkHeader,
	// 			Offset:        9,
	// 			DestRegister:  9,
	// 		},
	// 		// [ payload load 2b @ transport header + 2 => reg 10 ]
	// 		&expr.Payload{
	// 			OperationType: expr.PayloadLoad,
	// 			Len:           2,
	// 			Base:          expr.PayloadBaseTransportHeader,
	// 			Offset:        2,
	// 			DestRegister:  10,
	// 		},
	// 		// [ ct load state => reg 11 ]
	// 		&expr.Ct{
	// 			Key:      expr.CtKeySTATE,
	// 			Register: 11,
	// 		},
	// 		// [ lookup reg 1 set whalewall-ipv4-output-allow dreg 0 0x0 ]
	// 		&expr.Lookup{
	// 			SourceRegister: 1,
	// 			SetName:        "whalewall-ipv4-output-allow",
	// 			DestRegister:   0,
	// 		},
	// 	},
	// })

	// // ip saddr . ip protocol . udp dport . ct state vmap @whalewall-ipv4-output-allow
	// r.nfc.AddRule(&nftables.Rule{
	// 	Table: ipv4Table,
	// 	Chain: chain,
	// 	Exprs: []expr.Any{
	// 		// [ meta load l4proto => reg 1 ]
	// 		&expr.Meta{
	// 			Key:      expr.MetaKeyL4PROTO,
	// 			Register: 1,
	// 		},
	// 		// [ cmp eq reg 1 0x00000011 ]
	// 		&expr.Cmp{
	// 			Op:       expr.CmpOpEq,
	// 			Register: 1,
	// 			Data:     []byte{0x11},
	// 		},
	// 		// [ payload load 4b @ network header + 12 => reg 1 ]
	// 		&expr.Payload{
	// 			OperationType: expr.PayloadLoad,
	// 			Len:           4,
	// 			Base:          expr.PayloadBaseNetworkHeader,
	// 			Offset:        12,
	// 			DestRegister:  1,
	// 		},
	// 		// [ payload load 1b @ network header + 9 => reg 9 ]
	// 		&expr.Payload{
	// 			OperationType: expr.PayloadLoad,
	// 			Len:           1,
	// 			Base:          expr.PayloadBaseNetworkHeader,
	// 			Offset:        9,
	// 			DestRegister:  9,
	// 		},
	// 		// [ payload load 2b @ transport header + 2 => reg 10 ]
	// 		&expr.Payload{
	// 			OperationType: expr.PayloadLoad,
	// 			Len:           2,
	// 			Base:          expr.PayloadBaseTransportHeader,
	// 			Offset:        2,
	// 			DestRegister:  10,
	// 		},
	// 		// [ ct load state => reg 11 ]
	// 		&expr.Ct{
	// 			Key:      expr.CtKeySTATE,
	// 			Register: 11,
	// 		},
	// 		// [ lookup reg 1 set whalewall-ipv4-output-allow dreg 0 0x0 ]
	// 		&expr.Lookup{
	// 			SourceRegister: 1,
	// 			SetName:        "whalewall-ipv4-output-allow",
	// 			DestRegister:   0,
	// 		},
	// 	},
	// })

	// // ip saddr @whalewall-ipv4-drop drop
	// r.nfc.AddRule(&nftables.Rule{
	// 	Table: ipv4Table,
	// 	Chain: chain,
	// 	Exprs: []expr.Any{
	// 		&expr.Counter{},
	// 		// [ payload load 4b @ network header + 12 => reg 1 ]
	// 		&expr.Payload{
	// 			OperationType: expr.PayloadLoad,
	// 			Len:           4,
	// 			Base:          expr.PayloadBaseNetworkHeader,
	// 			Offset:        12,
	// 			DestRegister:  1,
	// 		},
	// 		// [ lookup reg 1 set whalewall-ipv4-drop 0x0 ]
	// 		&expr.Lookup{
	// 			SourceRegister: 1,
	// 			SetName:        ipv4DropSetName,
	// 			DestRegister:   0,
	// 		},
	// 		&expr.Verdict{
	// 			Kind: expr.VerdictDrop,
	// 		},
	// 	},
	// })

	// // ip daddr @whalewall-ipv4-drop drop
	// r.nfc.AddRule(&nftables.Rule{
	// 	Table: ipv4Table,
	// 	Chain: chain,
	// 	Exprs: []expr.Any{
	// 		&expr.Counter{},
	// 		// [ payload load 4b @ network header + 16 => reg 1 ]
	// 		&expr.Payload{
	// 			OperationType: expr.PayloadLoad,
	// 			Len:           4,
	// 			Base:          expr.PayloadBaseNetworkHeader,
	// 			Offset:        16,
	// 			DestRegister:  1,
	// 		},
	// 		// [ lookup reg 1 set whalewall-ipv4-drop 0x0 ]
	// 		&expr.Lookup{
	// 			SourceRegister: 1,
	// 			SetName:        ipv4DropSetName,
	// 			DestRegister:   0,
	// 		},
	// 		&expr.Verdict{
	// 			Kind: expr.VerdictDrop,
	// 		},
	// 	},
	// })

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

func (r *ruleManager) createUFWRules(ch <-chan *types.ContainerJSON) {
	for container := range ch {
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

		c := &containerRules{
			Name:      containerName,
			IPAddress: containerIP,
			Labels:    container.Config.Labels,
		}
		r.addContainer(containerID, c)

		// Handle inbound rules
		for port, portMaps := range container.HostConfig.PortBindings {
			// List is non empty if port is published
			if len(portMaps) > 0 {
				ufwRules := []ufwRule{}
				if container.Config.Labels["UFW_ALLOW_FROM"] != "" {
					ufwAllowFromLabelParsed := strings.Split(container.Config.Labels["UFW_ALLOW_FROM"], ";")

					for _, allowFrom := range ufwAllowFromLabelParsed {
						ip := strings.Split(allowFrom, "-")
						// First element should be always valid IP Address or CIDR
						if strings.Contains(ip[0], "/") {
							if _, err := netip.ParsePrefix(ip[0]); err != nil {
								log.Printf("error parsing IP: %s: %v", ip[0], err)
								continue
							}
						} else {
							if _, err := netip.ParseAddr(ip[0]); err != nil {
								log.Printf("error parsing IP: %s: %v", ip[0], err)
								continue
							}
						}

						// Example: 172.10.5.0-LAN or 172.10.5.0-80
						if len(ip) == 2 {
							if _, err := strconv.Atoi(ip[1]); err == nil {
								// case: 172.10.5.0-80
								ufwRules = append(ufwRules, ufwRule{CIDR: ip[0], Port: ip[1], Proto: port.Proto()})
							} else {
								// case: 172.10.5.0-LAN
								ufwRules = append(ufwRules, ufwRule{CIDR: ip[0], Port: port.Port(), Proto: port.Proto(), Comment: fmt.Sprintf(" %s", ip[1])})
							}
							// Example: 172.10.5.0-80-LAN
						} else if len(ip) == 3 {
							ufwRules = append(ufwRules, ufwRule{CIDR: ip[0], Port: ip[1], Proto: port.Proto(), Comment: fmt.Sprintf(" %s", ip[2])})
						} else {
							// Example: 172.10.5.0
							ufwRules = append(ufwRules, ufwRule{CIDR: ip[0], Port: port.Port(), Proto: port.Proto()})
						}
					}
				} else {
					ufwRules = append(ufwRules, ufwRule{CIDR: "any", Port: port.Port(), Proto: port.Proto()})
				}

				for _, rule := range ufwRules {
					cmd := exec.Command("ufw", "route", "allow", "proto", rule.Proto, "from", rule.CIDR, "to", containerIP, "port", rule.Port, "comment", containerName+":"+containerID+rule.Comment)
					log.Printf("adding ufw rule: %s", cmd)

					var stdout, stderr bytes.Buffer
					cmd.Stdout = &stdout
					cmd.Stderr = &stderr
					err := cmd.Run()
					if err != nil {
						log.Printf("error creating ufw rule: %s: %v", &stderr, err)
					}
				}

				c.UfwInboundRules = append(c.UfwInboundRules, ufwRules...)
				// ufw route allow proto tcp from any to 172.17.0.2 port 80 comment "Comment"
				// ufw route allow proto <tcp|udp> <source> to <container_ip> port <port> comment <comment>
				// ufw route delete allow proto tcp from any to 172.17.0.2 port 80 comment "Comment"
				// ufw route delete allow proto <tcp|udp> <source> to <container_ip> port <port> comment <comment>
			}
		}

		// Handle outbound rules
		if container.Config.Labels["UFW_DENY_OUT"] == "TRUE" {
			if container.Config.Labels["UFW_ALLOW_TO"] != "" {
				ufwRules := []ufwRule{}
				ufwAllowToLabelParsed := strings.Split(container.Config.Labels["UFW_ALLOW_TO"], ";")

				for _, allowTo := range ufwAllowToLabelParsed {
					ip := strings.Split(allowTo, "-")
					// First element should be always valid IP Address or CIDR
					if strings.Contains(ip[0], "/") {
						if _, err := netip.ParsePrefix(ip[0]); err != nil {
							log.Printf("error parsing IP: %s: %v", ip[0], err)
							continue
						}
					} else {
						if _, err := netip.ParseAddr(ip[0]); err != nil {
							log.Printf("error parsing IP: %s: %v", ip[0], err)
							continue
						}
					}

					// Example: 172.10.5.0-LAN or 172.10.5.0-80
					if len(ip) == 2 {
						if _, err := strconv.Atoi(ip[1]); err == nil {
							// case: 172.10.5.0-80
							ufwRules = append(ufwRules, ufwRule{CIDR: ip[0], Port: ip[1]})
						} else {
							// case: 172.10.5.0-LAN
							ufwRules = append(ufwRules, ufwRule{CIDR: ip[0], Comment: fmt.Sprintf(" %s", ip[1])})
						}
						// Example: 172.10.5.0-80-LAN
					} else if len(ip) == 3 {
						ufwRules = append(ufwRules, ufwRule{CIDR: ip[0], Port: ip[1], Comment: fmt.Sprintf(" %s", ip[2])})
					} else {
						// Example: 172.10.5.0
						ufwRules = append(ufwRules, ufwRule{CIDR: ip[0]})
					}
				}

				for _, rule := range ufwRules {
					var cmd *exec.Cmd

					if rule.Port == "" {
						cmd = exec.Command("ufw", "route", "allow", "from", containerIP, "to", rule.CIDR, "comment", containerName+":"+containerID+rule.Comment)
					} else {
						cmd = exec.Command("ufw", "route", "allow", "from", containerIP, "to", rule.CIDR, "port", rule.Port, "comment", containerName+":"+containerID+rule.Comment)
					}
					log.Printf("adding ufw rule: %s", cmd)

					var stdout, stderr bytes.Buffer
					cmd.Stdout = &stdout
					cmd.Stderr = &stderr
					err := cmd.Run()
					if err != nil {
						log.Printf("error creating ufw rule: %s: %v", &stderr, err)
					}
				}

				c.UfwOutboundRules = append(c.UfwOutboundRules, ufwRules...)
			}

			// Handle deny all out
			cmd := exec.Command("ufw", "route", "deny", "from", containerIP, "to", "any", "comment", containerName+":"+containerID)
			log.Printf("adding ufw rule: %s", cmd)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err := cmd.Run()
			if err != nil {
				log.Printf("error creating ufw rule: %s: %v", &stderr, err)
			}
		}
	}
}
