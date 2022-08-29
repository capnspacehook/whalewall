package main

import (
	"net/netip"
)

type containerRules struct {
	Input  []containerRule
	Output []containerRule
}

type containerRule struct {
	IP        netip.Addr
	Container string
	Proto     string
	Port      uint16
}
