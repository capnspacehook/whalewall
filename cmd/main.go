package main

import (
	"github.com/google/nftables"
	"github.com/kr/pretty"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	c, err := nftables.New()
	check(err)

	rules, err := c.GetRules(
		&nftables.Table{
			Family: nftables.TableFamilyIPv4,
			Name:   "filter",
		},
		&nftables.Chain{
			Name: "DOCKER-USER",
		},
	)
	check(err)

	for _, rule := range rules {
		pretty.Println(rule)
	}
}
