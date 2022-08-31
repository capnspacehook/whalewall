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
	Network        string
	IP             netip.Addr
	Container      string
	Proto          string
	Port           uint16
	Chain          string
	Queue          uint16
	InputEstQueue  uint16 `yaml:"input_est_queue"`
	OutputEstQueue uint16 `yaml:"output_est_queue"`
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
		return errors.New(`"ip" and "container" are mutually exclusive`)
	}
	if r.Network == "" && r.Container != "" {
		return errors.New(`"network" must be set when "container" is set`)
	}
	if r.Port != 0 && r.Proto == "" {
		return errors.New(`"proto" must be set when "port" is set`)
	}
	if r.Proto != "" && r.Proto != "tcp" && r.Proto != "udp" {
		return fmt.Errorf("unknown protocol %q", r.Proto)
	}
	if r.Chain != "" && r.Queue != 0 {
		return errors.New(`"chain" and "queue" are mutually exclusive`)
	}
	if r.Queue == 0 && r.InputEstQueue != 0 {
		return errors.New(`"queue" must be set when "input_est_queue" is set`)
	}
	if r.Queue == 0 && r.OutputEstQueue != 0 {
		return errors.New(`"queue" must be set when "output_est_queue" is set`)
	}
	if r.InputEstQueue == 0 && r.OutputEstQueue != 0 {
		return errors.New(`"input_est_queue" must be set when "output_est_queue" is set`)
	}
	if r.OutputEstQueue == 0 && r.InputEstQueue != 0 {
		return errors.New(`"output_est_queue" must be set when "input_est_queue" is set`)
	}

	return nil
}
