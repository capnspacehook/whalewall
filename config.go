package whalewall

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go4.org/netipx"
)

type config struct {
	MappedPorts mappedPorts `yaml:"mapped_ports"`
	Output      []ruleConfig
}

type mappedPorts struct {
	Localhost localRules
	External  externalRules
}

// TODO: allow users to specify addrOrRange that is within 127.0.0.1/8?
type localRules struct {
	Allow     bool
	LogPrefix string `yaml:"log_prefix"`
	Verdict   verdict
}

type externalRules struct {
	Allow     bool
	LogPrefix string `yaml:"log_prefix"`
	IP        addrOrRange
	Verdict   verdict
}

type ruleConfig struct {
	LogPrefix string `yaml:"log_prefix"`
	Network   string
	IP        addrOrRange
	Container string
	Proto     string
	Port      uint16
	Verdict   verdict
}

func (r ruleConfig) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if r.LogPrefix != "" {
		enc.AddString("log_prefix", r.LogPrefix)
	}
	if r.Network != "" {
		enc.AddString("network", r.Network)
	}
	if r.IP.IsValid() {
		zap.Inline(r.IP).AddTo(enc)
	}
	if r.Container != "" {
		enc.AddString("container", r.Container)
	}
	enc.AddString("proto", r.Proto)
	enc.AddUint16("port", r.Port)
	enc.AddObject("verdict", r.Verdict)

	return nil
}

type verdict struct {
	Chain          string
	Queue          uint16
	InputEstQueue  uint16 `yaml:"input_est_queue"`
	OutputEstQueue uint16 `yaml:"output_est_queue"`

	drop bool
}

func (v verdict) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if v.Chain != "" {
		enc.AddString("chain", v.Chain)
	}
	if v.Queue != 0 {
		enc.AddUint16("queue", v.Queue)
	}
	if v.InputEstQueue != 0 {
		enc.AddUint16("input_est_queue", v.InputEstQueue)
	}
	if v.OutputEstQueue != 0 {
		enc.AddUint16("output_est_queue", v.OutputEstQueue)
	}
	enc.AddBool("drop", v.drop)

	return nil
}

type addrOrRange struct {
	addr      netip.Addr
	addrRange netipx.IPRange
}

func (a addrOrRange) MarshalText() ([]byte, error) {
	if a.addr.IsValid() {
		return a.addr.MarshalText()
	}
	return a.addrRange.MarshalText()
}

func (a *addrOrRange) UnmarshalText(text []byte) error {
	if bytes.ContainsRune(text, '/') {
		prefix := new(netip.Prefix)
		err := prefix.UnmarshalText(text)
		if err != nil {
			return err
		}
		a.addrRange = netipx.RangeOfPrefix(*prefix)
		return nil
	} else if bytes.ContainsRune(text, '-') {
		return a.addrRange.UnmarshalText(text)
	}
	return a.addr.UnmarshalText(text)
}

func (a addrOrRange) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if a.addr.IsValid() {
		enc.AddString("addr", a.addr.String())
	} else {
		enc.AddString("addrs", a.addrRange.String())
	}
	return nil
}

func (a *addrOrRange) IsValid() bool {
	return a.addr.IsValid() || a.addrRange.IsValid()
}

func (a *addrOrRange) Addr() (netip.Addr, bool) {
	return a.addr, a.addr.IsValid()
}

func (a *addrOrRange) Range() (netip.Addr, netip.Addr, bool) {
	return a.addrRange.From(), a.addrRange.To(), a.addrRange.IsValid()
}

func validateConfig(c config) error {
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
	if r.Proto == "" && r.Port != 0 {
		return errors.New(`"port" must be set when "proto" is set`)
	}
	if r.Proto != "" && r.Proto != "tcp" && r.Proto != "udp" {
		return fmt.Errorf("unknown protocol %q", r.Proto)
	}

	return validateVerdict(r.Verdict)
}

func validateVerdict(v verdict) error {
	if v.Chain != "" && v.Queue != 0 {
		return errors.New(`"chain" and "queue" are mutually exclusive`)
	}
	if v.Queue == 0 && v.InputEstQueue != 0 {
		return errors.New(`"queue" must be set when "input_est_queue" is set`)
	}
	if v.Queue == 0 && v.OutputEstQueue != 0 {
		return errors.New(`"queue" must be set when "output_est_queue" is set`)
	}
	if v.InputEstQueue == 0 && v.OutputEstQueue != 0 {
		return errors.New(`"input_est_queue" must be set when "output_est_queue" is set`)
	}
	if v.OutputEstQueue == 0 && v.InputEstQueue != 0 {
		return errors.New(`"output_est_queue" must be set when "input_est_queue" is set`)
	}

	return nil
}
