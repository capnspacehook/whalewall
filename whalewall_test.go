package main

import (
	"context"
	"net/netip"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/go-connections/nat"
	"github.com/google/go-cmp/cmp"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/matryer/is"
	"go.uber.org/zap"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
)

func TestRuleCreation(t *testing.T) {
	cont1ID := "container_one_ID"
	cont1Name := "container1"
	gatewayAddr := netip.MustParseAddr("172.0.1.1")
	cont1Addr := netip.MustParseAddr("172.0.1.2")
	dstAddr := netip.MustParseAddr("1.1.1.1")
	dstRange := netipx.RangeOfPrefix(netip.MustParsePrefix("192.168.1.0/24"))
	lowDstAddr := dstRange.From()
	highDstAddr := dstRange.To()

	tests := []struct {
		name          string
		container     types.ContainerJSON
		expectedRules map[*nftables.Chain][]*nftables.Rule
	}{
		{
			name: "allow HTTPS outbound",
			container: types.ContainerJSON{
				ContainerJSONBase: &types.ContainerJSONBase{
					ID:   cont1ID,
					Name: "/" + cont1Name,
				},
				Config: &container.Config{
					Labels: map[string]string{
						enabledLabel: "true",
						rulesLabel: `
output:
  - proto: tcp
    port: 443
`,
					},
				},
				NetworkSettings: &types.NetworkSettings{
					Networks: map[string]*network.EndpointSettings{
						"default": {
							Gateway:   gatewayAddr.String(),
							IPAddress: cont1Addr.String(),
						},
					},
				},
			},
			expectedRules: map[*nftables.Chain][]*nftables.Rule{
				{
					Name:  buildChainName(cont1Name, cont1ID),
					Table: filterTable,
				}: {
					{
						Exprs: slicesJoin(
							matchIPExprs(ref(cont1Addr.As4())[:], srcAddrOffset),
							matchProtoExprs(unix.IPPROTO_TCP),
							matchPortExprs(443, dstPortOffset),
							matchConnStateExprs(stateNewEst),
							[]expr.Any{
								&expr.Counter{},
								acceptVerdict,
							},
						),
						UserData: []byte(cont1ID),
					},
					{
						Exprs: slicesJoin(
							matchIPExprs(ref(cont1Addr.As4())[:], dstAddrOffset),
							matchProtoExprs(unix.IPPROTO_TCP),
							matchPortExprs(443, srcPortOffset),
							matchConnStateExprs(stateEst),
							[]expr.Any{
								&expr.Counter{},
								acceptVerdict,
							},
						),
						UserData: []byte(cont1ID),
					},
					createDropRule(
						&nftables.Chain{
							Name:  buildChainName(cont1Name, cont1ID),
							Table: filterTable,
						},
						cont1ID,
					),
				},
			},
		},
		{
			name: "allow HTTPS outbound to 1.1.1.1",
			container: types.ContainerJSON{
				ContainerJSONBase: &types.ContainerJSONBase{
					ID:   cont1ID,
					Name: "/" + cont1Name,
				},
				Config: &container.Config{
					Labels: map[string]string{
						enabledLabel: "true",
						rulesLabel: `
output:
  - ip: 1.1.1.1
    proto: tcp
    port: 443
`,
					},
				},
				NetworkSettings: &types.NetworkSettings{
					Networks: map[string]*network.EndpointSettings{
						"default": {
							Gateway:   gatewayAddr.String(),
							IPAddress: cont1Addr.String(),
						},
					},
				},
			},
			expectedRules: map[*nftables.Chain][]*nftables.Rule{
				{
					Name:  buildChainName(cont1Name, cont1ID),
					Table: filterTable,
				}: {
					{
						Exprs: slicesJoin(
							matchIPExprs(ref(cont1Addr.As4())[:], srcAddrOffset),
							matchIPExprs(ref(dstAddr.As4())[:], dstAddrOffset),
							matchProtoExprs(unix.IPPROTO_TCP),
							matchPortExprs(443, dstPortOffset),
							matchConnStateExprs(stateNewEst),
							[]expr.Any{
								&expr.Counter{},
								acceptVerdict,
							},
						),
						UserData: []byte(cont1ID),
					},
					{
						Exprs: slicesJoin(
							matchIPExprs(ref(dstAddr.As4())[:], srcAddrOffset),
							matchIPExprs(ref(cont1Addr.As4())[:], dstAddrOffset),
							matchProtoExprs(unix.IPPROTO_TCP),
							matchPortExprs(443, srcPortOffset),
							matchConnStateExprs(stateEst),
							[]expr.Any{
								&expr.Counter{},
								acceptVerdict,
							},
						),
						UserData: []byte(cont1ID),
					},
					createDropRule(
						&nftables.Chain{
							Name:  buildChainName(cont1Name, cont1ID),
							Table: filterTable,
						},
						cont1ID,
					),
				},
			},
		},
		{
			name: "allow DNS outbound to 192.168.1.0/24",
			container: types.ContainerJSON{
				ContainerJSONBase: &types.ContainerJSONBase{
					ID:   cont1ID,
					Name: "/" + cont1Name,
				},
				Config: &container.Config{
					Labels: map[string]string{
						enabledLabel: "true",
						rulesLabel: `
output:
  - ip: 192.168.1.0/24
    proto: udp
    port: 53
`,
					},
				},
				NetworkSettings: &types.NetworkSettings{
					Networks: map[string]*network.EndpointSettings{
						"default": {
							Gateway:   gatewayAddr.String(),
							IPAddress: cont1Addr.String(),
						},
					},
				},
			},
			expectedRules: map[*nftables.Chain][]*nftables.Rule{
				{
					Name:  buildChainName(cont1Name, cont1ID),
					Table: filterTable,
				}: {
					{
						Exprs: slicesJoin(
							matchIPExprs(ref(cont1Addr.As4())[:], srcAddrOffset),
							matchIPRangeExprs(lowDstAddr, highDstAddr, dstAddrOffset),
							matchProtoExprs(unix.IPPROTO_UDP),
							matchPortExprs(53, dstPortOffset),
							matchConnStateExprs(stateNewEst),
							[]expr.Any{
								&expr.Counter{},
								acceptVerdict,
							},
						),
						UserData: []byte(cont1ID),
					},
					{
						Exprs: slicesJoin(
							matchIPRangeExprs(lowDstAddr, highDstAddr, srcAddrOffset),
							matchIPExprs(ref(cont1Addr.As4())[:], dstAddrOffset),
							matchProtoExprs(unix.IPPROTO_UDP),
							matchPortExprs(53, srcPortOffset),
							matchConnStateExprs(stateEst),
							[]expr.Any{
								&expr.Counter{},
								acceptVerdict,
							},
						),
						UserData: []byte(cont1ID),
					},
					createDropRule(
						&nftables.Chain{
							Name:  buildChainName(cont1Name, cont1ID),
							Table: filterTable,
						},
						cont1ID,
					),
				},
			},
		},
		{
			name: "allow external access to mapped ports",
			container: types.ContainerJSON{
				ContainerJSONBase: &types.ContainerJSONBase{
					ID:   cont1ID,
					Name: "/" + cont1Name,
				},
				Config: &container.Config{
					Labels: map[string]string{
						enabledLabel: "true",
						rulesLabel: `
mapped_ports:
  external:
    allow: true
    ip: 192.168.1.0/24
`,
					},
				},
				NetworkSettings: &types.NetworkSettings{
					NetworkSettingsBase: types.NetworkSettingsBase{
						Ports: nat.PortMap{
							"80/tcp": []nat.PortBinding{
								{
									HostIP:   "0.0.0.0",
									HostPort: "8080",
								},
								{
									HostIP:   "::",
									HostPort: "8080",
								},
							},
							"53/udp": []nat.PortBinding{
								{
									HostIP:   "0.0.0.0",
									HostPort: "5533",
								},
								{
									HostIP:   "::",
									HostPort: "5533",
								},
							},
						},
					},
					Networks: map[string]*network.EndpointSettings{
						"default": {
							Gateway:   gatewayAddr.String(),
							IPAddress: cont1Addr.String(),
						},
					},
				},
			},
			expectedRules: map[*nftables.Chain][]*nftables.Rule{
				{
					Name:  buildChainName(cont1Name, cont1ID),
					Table: filterTable,
				}: {
					{
						Exprs: slicesJoin(
							matchIPRangeExprs(lowDstAddr, highDstAddr, srcAddrOffset),
							matchIPExprs(ref(cont1Addr.As4())[:], dstAddrOffset),
							matchProtoExprs(unix.IPPROTO_UDP),
							matchPortExprs(53, dstPortOffset),
							matchConnStateExprs(stateNewEst),
							[]expr.Any{
								&expr.Counter{},
								acceptVerdict,
							},
						),
						UserData: []byte(cont1ID),
					},
					{
						Exprs: slicesJoin(
							matchIPExprs(ref(cont1Addr.As4())[:], srcAddrOffset),
							matchIPRangeExprs(lowDstAddr, highDstAddr, dstAddrOffset),
							matchProtoExprs(unix.IPPROTO_UDP),
							matchPortExprs(53, srcPortOffset),
							matchConnStateExprs(stateEst),
							[]expr.Any{
								&expr.Counter{},
								acceptVerdict,
							},
						),
						UserData: []byte(cont1ID),
					},
					{
						Exprs: slicesJoin(
							matchIPRangeExprs(lowDstAddr, highDstAddr, srcAddrOffset),
							matchIPExprs(ref(cont1Addr.As4())[:], dstAddrOffset),
							matchProtoExprs(unix.IPPROTO_TCP),
							matchPortExprs(80, dstPortOffset),
							matchConnStateExprs(stateNewEst),
							[]expr.Any{
								&expr.Counter{},
								acceptVerdict,
							},
						),
						UserData: []byte(cont1ID),
					},
					{
						Exprs: slicesJoin(
							matchIPExprs(ref(cont1Addr.As4())[:], srcAddrOffset),
							matchIPRangeExprs(lowDstAddr, highDstAddr, dstAddrOffset),
							matchProtoExprs(unix.IPPROTO_TCP),
							matchPortExprs(80, srcPortOffset),
							matchConnStateExprs(stateEst),
							[]expr.Any{
								&expr.Counter{},
								acceptVerdict,
							},
						),
						UserData: []byte(cont1ID),
					},
					createDropRule(
						&nftables.Chain{
							Name:  buildChainName(cont1Name, cont1ID),
							Table: filterTable,
						},
						cont1ID,
					),
				},
			},
		},

		{
			name: "allow localhost access to mapped ports",
			container: types.ContainerJSON{
				ContainerJSONBase: &types.ContainerJSONBase{
					ID:   cont1ID,
					Name: "/" + cont1Name,
				},
				Config: &container.Config{
					Labels: map[string]string{
						enabledLabel: "true",
						rulesLabel: `
mapped_ports:
  localhost:
    allow: true
`,
					},
				},
				NetworkSettings: &types.NetworkSettings{
					NetworkSettingsBase: types.NetworkSettingsBase{
						Ports: nat.PortMap{
							"443/udp": []nat.PortBinding{
								{
									HostIP:   "0.0.0.0",
									HostPort: "8443",
								},
							},
						},
					},
					Networks: map[string]*network.EndpointSettings{
						"default": {
							Gateway:   gatewayAddr.String(),
							IPAddress: cont1Addr.String(),
						},
					},
				},
			},
			expectedRules: map[*nftables.Chain][]*nftables.Rule{
				{
					Name:  buildChainName(cont1Name, cont1ID),
					Table: filterTable,
				}: {
					{
						Exprs: slicesJoin(
							matchIPExprs(ref(gatewayAddr.As4())[:], srcAddrOffset),
							matchIPExprs(ref(cont1Addr.As4())[:], dstAddrOffset),
							matchProtoExprs(unix.IPPROTO_UDP),
							matchPortExprs(443, dstPortOffset),
							matchConnStateExprs(stateNewEst),
							[]expr.Any{
								&expr.Counter{},
								acceptVerdict,
							},
						),
						UserData: []byte(cont1ID),
					},
					{
						Exprs: slicesJoin(
							matchIPExprs(ref(cont1Addr.As4())[:], srcAddrOffset),
							matchIPExprs(ref(gatewayAddr.As4())[:], dstAddrOffset),
							matchProtoExprs(unix.IPPROTO_UDP),
							matchPortExprs(443, srcPortOffset),
							matchConnStateExprs(stateEst),
							[]expr.Any{
								&expr.Counter{},
								acceptVerdict,
							},
						),
						UserData: []byte(cont1ID),
					},
					createDropRule(
						&nftables.Chain{
							Name:  buildChainName(cont1Name, cont1ID),
							Table: filterTable,
						},
						cont1ID,
					),
				},
			},
		},
	}

	is := is.New(t)
	logger, err := zap.NewDevelopment()
	is.NoErr(err)

	comparer := func(r1, r2 *nftables.Rule) bool {
		return rulesEqual(logger, r1, r2)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)

			// create new database and base rules
			r := newRuleManager(zap.NewNop())
			err = r.init(context.Background(), t.TempDir())
			is.NoErr(err)
			err = r.createBaseRules()
			is.NoErr(err)
			t.Cleanup(func() {
				err := r.clearRules(context.Background())
				is.NoErr(err)
			})

			// create rules
			err := r.createRule(context.Background(), tt.container)
			is.NoErr(err)

			// TODO: create rules in network namespace
			nfc, err := nftables.New()
			is.NoErr(err)

			// check that created rules are what is expected
			for chain, expectedRules := range tt.expectedRules {
				rules, err := nfc.GetRules(chain.Table, chain)
				is.NoErr(err)

				is.Equal(len(expectedRules), len(rules))
				for i := range expectedRules {
					// set rule's table here so we don't have to in test
					// cases above
					expectedRules[i].Table = chain.Table

					diff := cmp.Diff(expectedRules[i], rules[i], cmp.Comparer(comparer))
					if diff != "" {
						t.Errorf("rules not equal: %s", diff)
					}
				}
			}
		})
	}
}

func slicesJoin[T any](s ...[]T) (ret []T) {
	for _, ss := range s {
		ret = append(ret, ss...)
	}

	return ret
}
