package main

func (r *ruleManager) deleteUFWRules(containerID <-chan string) {
	// for id := range containerID {
	// 	c, ok := r.getContainer(id)
	// 	if !ok {
	// 		log.Printf("information for container %s not found", id)
	// 		continue
	// 	}

	// 	// Handle inbound rules
	// 	for _, rule := range c.UfwInboundRules {
	// 		cmd := exec.Command("ufw", "route", "delete", "allow", "proto", rule.Proto, "from", rule.CIDR, "to", c.IPAddress, "port", rule.Port, "comment", c.Name+":"+id+rule.Comment)
	// 		log.Printf("deleting ufw rule: %s", cmd)

	// 		var stdout, stderr bytes.Buffer
	// 		cmd.Stdout = &stdout
	// 		cmd.Stderr = &stderr
	// 		err := cmd.Run()
	// 		if err != nil {
	// 			log.Printf("error deleting ufw rule: %s: %v", &stderr, err)
	// 		}
	// 	}

	// 	// Handle outbound rules
	// 	for _, rule := range c.UfwOutboundRules {
	// 		var cmd *exec.Cmd
	// 		if rule.Port == "" {
	// 			cmd = exec.Command("ufw", "route", "delete", "allow", "from", c.IPAddress, "to", rule.CIDR, "comment", c.Name+":"+id+rule.Comment)
	// 		} else {
	// 			cmd = exec.Command("ufw", "route", "delete", "allow", "from", c.IPAddress, "to", rule.CIDR, "port", rule.Port, "comment", c.Name+":"+id+rule.Comment)
	// 		}
	// 		log.Printf("deleting ufw rule: %s", cmd)

	// 		var stdout, stderr bytes.Buffer
	// 		cmd.Stdout = &stdout
	// 		cmd.Stderr = &stderr
	// 		err := cmd.Run()
	// 		if err != nil {
	// 			log.Printf("error deleting ufw rule: %s: %v", &stderr, err)
	// 		}
	// 	}

	// 	// Handle deny all out
	// 	cmd := exec.Command("ufw", "route", "delete", "deny", "from", c.IPAddress, "to", "any", "comment", c.Name+":"+id)
	// 	log.Printf("deleting ufw rule: %s", cmd)

	// 	var stdout, stderr bytes.Buffer
	// 	cmd.Stdout = &stdout
	// 	cmd.Stderr = &stderr
	// 	err := cmd.Run()
	// 	if err != nil {
	// 		log.Printf("error deleting ufw rule: %s: %v", &stderr, err)
	// 	}
	// }
}
