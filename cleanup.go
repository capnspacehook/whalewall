package main

import (
	"bufio"
	"bytes"
	"context"
	"log"
	"os/exec"
	"strings"

	"github.com/docker/docker/client"
)

func cleanupRules(ctx context.Context, client *client.Client) {
	cmd := exec.Command("ufw", "show", "added")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		log.Printf("error getting ufw rules: %s: %v", &stderr, err)
		return
	}

	ufwRuleMap := make(map[string][]string)
	scanner := bufio.NewScanner(strings.NewReader(stdout.String()))
	scanner.Scan() // Skipping first line that says: "Added user rules (see 'ufw status' for running firewall):"
	for scanner.Scan() {
		ufwRule := scanner.Text()
		if ufwRule != "(None)" { // if ufw is empty it returns "(None)"
			comment := ufwRule[strings.LastIndex(ufwRule, ":")+1:]      // comment after ":", Example: "a6cc06a1ebdb LAN"
			containerIDWithQuotes := strings.Split(comment, " ")[0]     // Example: "a6cc06a1ebdb GoogleDNS'" or "a6cc06a1ebdb'"
			containerID := strings.Split(containerIDWithQuotes, "'")[0] // First element is guaranteed to be container ID

			if c, ok := ufwRuleMap[containerID]; ok {
				ufwRuleMap[containerID] = append(c, ufwRule)
			} else {
				ufwRuleMap[containerID] = []string{ufwRule}
			}
		}
	}

	for containerID, rules := range ufwRuleMap {
		c, err := client.ContainerInspect(ctx, containerID)
		if err != nil {
			log.Printf("error inspecting container: %v", err)
			continue
		}
		if !c.State.Running {
			log.Printf("cleaning up ufw rules of stopped container %s", containerID)
			clean(rules)
		}
	}
}

func clean(rules []string) {
	for _, rule := range rules {
		cmd := exec.Command("ufw", "route", "delete", rule[10:]) // trimming first couple of words "ufw route " to fit delete command
		log.Printf("deleting rule: %s", rule)

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			log.Printf("error deleting ufw rule: %s: %v", &stderr, err)
		}
	}
}

// Example output:
// ❯ sudo ufw show added
// Added user rules (see 'ufw status' for running firewall):
// ufw route allow to 172.17.0.2 port 88 proto tcp comment 'dreamy_goldberg:b44309293890 Internet'
// ufw route allow from 192.168.3.0/24 to 172.17.0.2 port 89 proto tcp comment 'dreamy_goldberg:b44309293890 LAN'
// ufw route allow from 10.10.0.50 to 172.17.0.2 port 90 proto tcp comment 'dreamy_goldberg:b44309293890'
// ufw route allow from 172.10.5.0 to 172.17.0.3 port 90 proto tcp comment 'gracious_darwin:fd6b1483b319'
// ufw route allow from 192.168.3.0/24 to 172.17.0.3 port 90 proto tcp comment 'gracious_darwin:fd6b1483b319 LAN'
// ufw route allow from 10.10.0.50 to 172.17.0.3 port 90 proto tcp comment 'gracious_darwin:fd6b1483b319 DNS'
// ufw route allow from 172.10.5.0 to 172.17.0.3 port 91 proto tcp comment 'gracious_darwin:fd6b1483b319'
// ufw route allow from 192.168.3.0/24 to 172.17.0.3 port 91 proto tcp comment 'gracious_darwin:fd6b1483b319 LAN'
// ufw route allow from 10.10.0.50 to 172.17.0.3 port 91 proto tcp comment 'gracious_darwin:fd6b1483b319 DNS'
// ufw route allow from 172.17.0.3 to 8.8.8.8 port 53 comment 'gracious_darwin:fd6b1483b319 GoogleDNS'
// ufw route allow from 172.17.0.3 to 1.1.1.0/24 port 53 comment 'gracious_darwin:fd6b1483b319 CloudflareDNS'
// ufw route allow from 172.17.0.3 to 192.168.10.0/24 comment 'gracious_darwin:fd6b1483b319 LAN'
// ufw route deny from 172.17.0.3 comment 'gracious_darwin:fd6b1483b319'
// ufw route allow from 172.10.5.0 to 172.17.0.4 port 89 proto tcp comment 'goofy_moore:0b5d1f92dbf4'
// ufw route allow from 192.168.3.0/24 to 172.17.0.4 port 89 proto tcp comment 'goofy_moore:0b5d1f92dbf4 LAN'
// ufw route allow from 10.10.0.50 to 172.17.0.4 port 89 proto tcp comment 'goofy_moore:0b5d1f92dbf4 DNS'
// ufw route allow from 172.10.5.0 to 172.17.0.4 port 88 proto tcp comment 'goofy_moore:0b5d1f92dbf4'
// ufw route allow from 192.168.3.0/24 to 172.17.0.4 port 88 proto tcp comment 'goofy_moore:0b5d1f92dbf4 LAN'
// ufw route allow from 10.10.0.50 to 172.17.0.4 port 88 proto tcp comment 'goofy_moore:0b5d1f92dbf4 DNS'
// ufw route allow from 192.168.3.0/24 to 172.17.0.5 port 86 proto tcp comment 'elegant_keller:039417fcdb8d'
// ufw route allow from 10.10.0.50 to 172.17.0.5 port 86 proto tcp comment 'elegant_keller:039417fcdb8d'
// ufw route allow from 192.168.3.0/24 to 172.17.0.5 port 87 proto tcp comment 'elegant_keller:039417fcdb8d'
// ufw route allow from 10.10.0.50 to 172.17.0.5 port 87 proto tcp comment 'elegant_keller:039417fcdb8d'
// ufw route allow from 192.168.3.0 to 172.17.0.6 port 85 proto tcp comment 'nice_varahamihira:f8dbb2d7d488'
// ufw route allow from 192.168.3.0 to 172.17.0.6 port 84 proto tcp comment 'nice_varahamihira:f8dbb2d7d488'
// ufw route allow to 172.17.0.7 port 82 proto tcp comment 'thirsty_chebyshev:f7c1699fc536'
// ufw route allow to 172.17.0.7 port 83 proto tcp comment 'thirsty_chebyshev:f7c1699fc536'
// ufw route deny from 172.17.0.7 comment 'thirsty_chebyshev:f7c1699fc536'
// ufw route allow to 172.17.0.8 port 80 proto tcp comment 'zen_knuth:b26723a7404e'
// ufw route allow to 172.17.0.8 port 81 proto tcp comment 'zen_knuth:b26723a7404e'
