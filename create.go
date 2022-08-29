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

		c := &containerInfo{
			Name:   containerName,
			IP:     ip,
			Labels: container.Config.Labels,
			Rules:  rules,
		}
		r.addContainer(containerID, c)

		// TODO: handle IPv6
		addr := ip.As4()

		// handle inbound rules

		// handle outbound rules
		for _, rule := range rules.Output {
			elements := make([]nftables.SetElement, 3)

			var key []byte
			key = append(key, addr[:]...)
			proto := strings.ToLower(rule.Proto)
			if proto == "tcp" {
				key = append(key, unix.IPPROTO_TCP)
			} else {
				key = append(key, unix.IPPROTO_UDP)
			}
			key = binary.BigEndian.AppendUint16(key, rule.Port)

			elements[0].Key = binary.BigEndian.AppendUint32(key, expr.CtStateBitNEW)
			elements[1].Key = binary.BigEndian.AppendUint32(key, expr.CtStateBitESTABLISHED)
			elements[2].Key = binary.BigEndian.AppendUint32(key, expr.CtStateBitRELATED)

			// TODO: allow specifying "jump" or "queue"
			for i := range elements {
				elements[i].VerdictData = &expr.Verdict{
					Kind: expr.VerdictAccept,
				}
			}

			if err := r.nfc.SetAddElements(r.outputAllowSet, elements); err != nil {
				log.Printf("error adding set elements: %v", err)
				continue
			}
			if err := r.nfc.SetAddElements(r.inputAllowSet, elements[1:]); err != nil {
				log.Printf("error adding set elements: %v", err)
				continue
			}
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
		}
	}
}
