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
)

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
