package main

import (
	"errors"
	"fmt"
	"net/netip"
)

type config struct {
	Input  []ruleConfig
	Output []ruleConfig
}

type ruleConfig struct {
	Network   string
	IP        netip.Addr
	Container string
	Proto     string
	Port      uint16
}

func validateConfig(c config) error {
	for i, r := range c.Input {
		err := validateRule(r)
		if err != nil {
			return fmt.Errorf("input rule #%d: %w", i, err)
		}
	}
	for i, r := range c.Output {
		err := validateRule(r)
		if err != nil {
			return fmt.Errorf("output rule #%d: %w", i, err)
		}
	}

	return nil
}

func validateRule(r ruleConfig) error {
	if !r.IP.IsValid() && r.Container == "" && r.Proto == "" && r.Port == 0 {
		return errors.New("rule is empty")
	}
	if r.IP.IsValid() && r.Container != "" {
		return errors.New(`"IP" and "Container" are mutually exclusive`)
	}
	if r.Port != 0 && r.Proto == "" {
		return errors.New(`"Proto" must be set when "Port" is set`)
	}
	if r.Proto != "" && r.Proto != "tcp" && r.Proto != "udp" {
		return fmt.Errorf("unknown protocol %q", r.Proto)
	}

	return nil
}
