package whalewall

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/capnspacehook/whalewall/database"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/google/go-cmp/cmp"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/matryer/is"
	"go.uber.org/zap"
	"go4.org/netipx"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"
)

const defaultTimeout = 3 * time.Second

var (
	binaryTests     = flag.Bool("binary-tests", false, "use compiled binary to test with landlock and seccomp enabled")
	containerTests  = flag.Bool("container-tests", false, "use Docker image to test with landlock and seccomp enabled")
	whalewallBinary = flag.String("whalewall-binary", "./whalewall", "path to compiled whalewall binary")
	whalewallImage  = flag.String("whalewall-image", "whalewall:test", "Docker image to test with")
)

func TestIntegration(t *testing.T) {
	is := is.New(t)

	checkFirewallRules := func() {
		is.True(runCmd(t, "client", "nslookup google.com") == 0)                             // udp port 53 is allowed
		is.True(runCmd(t, "client", "curl --connect-timeout 1 http://1.1.1.1") == 0)         // tcp port 80 to 1.1.1.1 is allowed
		is.True(runCmd(t, "client", "curl --connect-timeout 1 http://1.0.0.1") != 0)         // tcp port 80 to 1.0.0.1 is not allowed
		is.True(runCmd(t, "client", "curl --connect-timeout 1 https://www.google.com") == 0) // DNS and HTTPS is allowed externally
		is.True(portOpen(t, "client", "server", 756, false))                                 // tcp port 756 is allowed client -> server
		is.True(!portOpen(t, "client", "server", 756, true))                                 // udp port 756 is not allowed client -> server
		is.True(!portOpen(t, "client", "server", 80, false))                                 // tcp port 80 is not allowed client -> server
		is.True(!portOpen(t, "client", "server", 80, true))                                  // udp port 80 is not allowed client -> server
		is.True(portOpen(t, "tester", "localhost", 8080, false))                             // tcp mapped port 8080:80 of client is allowed from localhost
		is.True(!portOpen(t, "tester", "localhost", 8080, true))                             // udp mapped port 8080:80 of client is not allowed from localhost
		is.True(!portOpen(t, "tester", "localhost", 8081, false))                            // tcp mapped port 8081:80 of server is not allowed from localhost
		is.True(!portOpen(t, "tester", "localhost", 8081, true))                             // udp mapped port 8081:80 of server is not allowed from localhost
		is.True(!portOpen(t, "tester", "localhost", 9001, false))                            // tcp mapped port 9001:9001 of server is not allowed from localhost
		is.True(!portOpen(t, "tester", "localhost", 9001, true))                             // udp mapped port 9001:9001 of server is not allowed from localhost
	}

	tempDir := t.TempDir()
	stopWhalewall := startWhalewall(t, is, tempDir)
	t.Cleanup(stopWhalewall)

	is.True(run(t, "docker", "compose", "-f=testdata/docker-compose.yml", "up", "-d") == 0)
	t.Cleanup(func() {
		run(t, "docker", "compose", "-f=testdata/docker-compose.yml", "down")
	})

	// wait until whalewall has created firewall rules
	time.Sleep(time.Second)

	checkFirewallRules()

	// ensure correct nftables chains exist
	dockerClient, err := client.NewClientWithOpts(client.FromEnv)
	is.NoErr(err)
	t.Cleanup(func() {
		dockerClient.Close()
	})
	containers, err := dockerClient.ContainerList(context.Background(), types.ContainerListOptions{})
	is.NoErr(err)

	clientChain := getContainerChain("client", containers)
	is.True(clientChain != nil)
	serverChain := getContainerChain("server", containers)
	is.True(serverChain != nil)

	nfc, err := nftables.New()
	is.NoErr(err)
	chains, err := nfc.ListChains()
	is.NoErr(err)

	is.True(chainExists(clientChain.Name, chains))
	is.True(chainExists(serverChain.Name, chains))

	// test stopping and starting containers when whalewall is running
	// and when it is stopped and started after
	for _, restart := range []bool{false, true} {
		name := "whalewall running"
		if restart {
			name = "whalewall stopped"
		}
		t.Run(name, func(t *testing.T) {
			// stop server container and verify that its chain is removed
			t.Run("stop server", func(t *testing.T) {
				if restart {
					stopWhalewall()
				}
				is.True(run(t, "docker", "compose", "-f=testdata/docker-compose.yml", "stop", "server") == 0)
				if restart {
					stopWhalewall = startWhalewall(t, is, tempDir)
				}
				time.Sleep(time.Second)

				chains, err := nfc.ListChains()
				is.NoErr(err)
				is.True(chainExists(clientChain.Name, chains))
				is.True(!chainExists(serverChain.Name, chains))
			})

			// stop client container and verify that its chain is removed
			t.Run("stop client", func(t *testing.T) {
				if restart {
					stopWhalewall()
				}
				is.True(run(t, "docker", "compose", "-f=testdata/docker-compose.yml", "stop", "client") == 0)
				if restart {
					stopWhalewall = startWhalewall(t, is, tempDir)
				}
				time.Sleep(time.Second)

				chains, err := nfc.ListChains()
				is.NoErr(err)
				is.True(!chainExists(clientChain.Name, chains))
				is.True(!chainExists(serverChain.Name, chains))
			})

			// start client container and verify that its chain is created
			t.Run("start client", func(t *testing.T) {
				if restart {
					stopWhalewall()
				}
				is.True(run(t, "docker", "compose", "-f=testdata/docker-compose.yml", "start", "client") == 0)
				if restart {
					stopWhalewall = startWhalewall(t, is, tempDir)
				}
				time.Sleep(time.Second)

				chains, err := nfc.ListChains()
				is.NoErr(err)
				is.True(chainExists(clientChain.Name, chains))
				is.True(!chainExists(serverChain.Name, chains))
			})

			// start server container and verify that its chain is created
			t.Run("start server", func(t *testing.T) {
				if restart {
					stopWhalewall()
				}
				is.True(run(t, "docker", "compose", "-f=testdata/docker-compose.yml", "start", "server") == 0)
				if restart {
					stopWhalewall = startWhalewall(t, is, tempDir)
				}
				time.Sleep(time.Second)

				chains, err := nfc.ListChains()
				is.NoErr(err)
				is.True(chainExists(clientChain.Name, chains))
				is.True(chainExists(serverChain.Name, chains))
			})

			// ensure rules are created properly again after recreating containers
			checkFirewallRules()
		})
	}
}

func startWhalewall(t *testing.T, is *is.I, tempDir string) func() {
	var stop func()
	var stopOnce sync.Once

	switch {
	case *binaryTests:
		stop = startBinary(t, is, tempDir)
	case *containerTests:
		stop = startContainer(t, is, tempDir)
	default:
		stop = startFunc(is, tempDir)
	}

	return func() {
		stopOnce.Do(stop)
	}
}

func startBinary(t *testing.T, is *is.I, tempDir string) func() {
	wwCmd := exec.Command(*whalewallBinary, "-debug", "-d", tempDir)
	wwCmd.Stdout = os.Stdout
	wwCmd.Stderr = os.Stderr
	err := wwCmd.Start()
	is.NoErr(err)

	return func() {
		err := wwCmd.Process.Signal(os.Interrupt)
		if err != nil {
			t.Errorf("error killing whalewall process: %v", err)
		}

		if err := wwCmd.Wait(); err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				t.Errorf("whalewall exited with error: %v", err)
			}
		}
	}
}

func startContainer(t *testing.T, is *is.I, tempDir string) func() {
	dockerCmd := exec.Command(
		"docker",
		"run",
		"--cap-add=NET_ADMIN",
		"--network=host",
		fmt.Sprintf("-v=%s:/data", tempDir),
		"-v=/var/run/docker.sock:/var/run/docker.sock:ro",
		"--rm",
		*whalewallImage,
		"-d=/data",
		"-debug",
	)
	dockerCmd.Stdout = os.Stdout
	dockerCmd.Stderr = os.Stderr
	err := dockerCmd.Start()
	is.NoErr(err)

	return func() {
		err := dockerCmd.Process.Signal(os.Interrupt)
		if err != nil {
			t.Errorf("error killing whalewall container: %v", err)
		}

		if err := dockerCmd.Wait(); err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				t.Errorf("whalewall container exited with error: %v", err)
			}
		}
	}
}

func startFunc(is *is.I, tempDir string) func() {
	logger, err := zap.NewDevelopment()
	is.NoErr(err)

	logger.Info("starting whalewall")
	ctx, cancel := context.WithCancel(context.Background())
	dbFile := filepath.Join(tempDir, "db.sqlite")
	r, err := NewRuleManager(ctx, logger, dbFile, defaultTimeout)
	is.NoErr(err)
	err = r.Start(ctx)
	is.NoErr(err)

	return func() {
		logger.Info("stopping whalewall")
		cancel()
		r.Stop()
	}
}

func portOpen(t *testing.T, container, host string, port uint16, udp bool) bool {
	var udpFlag string
	if udp {
		udpFlag = "-sU"
	}
	// use nmap to determine if port is open and grep for "open" not "open|filtered"
	nmapCmd := fmt.Sprintf(`nmap -n -p %d %s %s 2>&1 | egrep "open\s"`, port, udpFlag, host)

	return runCmd(t, container, nmapCmd) == 0
}

func runCmd(t *testing.T, container, command string) int {
	args := []string{
		"docker",
		"compose",
		"-f=testdata/docker-compose.yml",
		"exec",
		"-T",
		container,
		"sh",
		"-c",
		command,
	}

	return run(t, args...)
}

func run(t *testing.T, args ...string) int {
	t.Logf("running %v", args)

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		t.Fatalf("error running command %v: %v", args, err)
	}

	return 0
}

func getContainerChain(name string, containers []types.Container) *nftables.Chain {
	for _, container := range containers {
		if slices.ContainsFunc(container.Names, func(n string) bool {
			return stripName(n) == name
		}) {
			return &nftables.Chain{
				Name:  buildChainName(name, container.ID),
				Table: filterTable,
			}
		}
	}

	return nil
}

func chainExists(name string, chains []*nftables.Chain) bool {
	return slices.ContainsFunc(chains, func(c *nftables.Chain) bool {
		return c.Name == name
	})
}

var (
	cont1ID     = "container_one_ID"
	cont2ID     = "container_two_ID"
	cont1Name   = "container1"
	cont2Name   = "container2"
	gatewayAddr = netip.MustParseAddr("172.0.1.1")
	cont1Addr   = netip.MustParseAddr("172.0.1.2")
	cont2Addr   = netip.MustParseAddr("172.0.1.3")
	dstAddr     = netip.MustParseAddr("1.1.1.1")
	dstRange    = netipx.RangeOfPrefix(netip.MustParsePrefix("192.168.1.0/24"))
	lowDstAddr  = dstRange.From()
	highDstAddr = dstRange.To()
)

func TestRuleCreation(t *testing.T) {
	type ruleCreationTest struct {
		name          string
		containers    []types.ContainerJSON
		expectedRules map[*nftables.Chain][]*nftables.Rule
	}
	tests := []ruleCreationTest{
		{
			name: "deny all",
			containers: []types.ContainerJSON{
				{
					ContainerJSONBase: &types.ContainerJSONBase{
						ID:   cont1ID,
						Name: "/" + cont1Name,
					},
					Config: &container.Config{
						Labels: map[string]string{
							enabledLabel: "true",
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
			},
			expectedRules: map[*nftables.Chain][]*nftables.Rule{
				{
					Name:  buildChainName(cont1Name, cont1ID),
					Table: filterTable,
				}: {
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
			name: "allow HTTPS outbound",
			containers: []types.ContainerJSON{
				{
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
    port: 443`,
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
			containers: []types.ContainerJSON{
				{
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
    port: 443`,
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
			containers: []types.ContainerJSON{
				{
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
    port: 53`,
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
			name: "verdict with log prefix",
			containers: []types.ContainerJSON{
				{
					ContainerJSONBase: &types.ContainerJSONBase{
						ID:   cont1ID,
						Name: "/" + cont1Name,
					},
					Config: &container.Config{
						Labels: map[string]string{
							enabledLabel: "true",
							rulesLabel: `
output:
  - log_prefix: "logger pfx"
    proto: tcp
    port: 443`,
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
							matchConnStateExprs(stateNew),
							[]expr.Any{
								&expr.Counter{},
								logExpr(formatLogPrefix("logger pfx", cont1Name, cont1ID)),
								acceptVerdict,
							},
						),
						UserData: []byte(cont1ID),
					},
					{
						Exprs: slicesJoin(
							matchIPExprs(ref(cont1Addr.As4())[:], srcAddrOffset),
							matchProtoExprs(unix.IPPROTO_TCP),
							matchPortExprs(443, dstPortOffset),
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
			name: "verdict with queue",
			containers: []types.ContainerJSON{
				{
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
    verdict:
      queue: 1000`,
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
							matchConnStateExprs(stateNew),
							[]expr.Any{
								&expr.Counter{},
								&expr.Queue{
									Num: 1000,
								},
							},
						),
						UserData: []byte(cont1ID),
					},
					{
						Exprs: slicesJoin(
							matchIPExprs(ref(cont1Addr.As4())[:], srcAddrOffset),
							matchProtoExprs(unix.IPPROTO_TCP),
							matchPortExprs(443, dstPortOffset),
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
			name: "verdict with queue and est queues",
			containers: []types.ContainerJSON{
				{
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
    verdict:
      queue: 1000
      input_est_queue: 1001
      output_est_queue: 1002`,
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
							matchConnStateExprs(stateNew),
							[]expr.Any{
								&expr.Counter{},
								&expr.Queue{
									Num: 1000,
								},
							},
						),
						UserData: []byte(cont1ID),
					},
					{
						Exprs: slicesJoin(
							matchIPExprs(ref(cont1Addr.As4())[:], srcAddrOffset),
							matchProtoExprs(unix.IPPROTO_TCP),
							matchPortExprs(443, dstPortOffset),
							matchConnStateExprs(stateEst),
							[]expr.Any{
								&expr.Counter{},
								&expr.Queue{
									Num: 1002,
								},
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
								&expr.Queue{
									Num: 1001,
								},
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
			name: "verdict with queue and same output est queue",
			containers: []types.ContainerJSON{
				{
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
    verdict:
      queue: 1000
      input_est_queue: 1001
      output_est_queue: 1000`,
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
								&expr.Queue{
									Num: 1000,
								},
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
								&expr.Queue{
									Num: 1001,
								},
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
			name: "allow access to container",
			containers: []types.ContainerJSON{
				{
					ContainerJSONBase: &types.ContainerJSONBase{
						ID:   cont1ID,
						Name: "/" + cont1Name,
					},
					Config: &container.Config{
						Labels: map[string]string{
							enabledLabel: "true",
							rulesLabel: `
output:
  - container: container2
    network: cont_net
    proto: udp
    port: 9001`,
						},
					},
					NetworkSettings: &types.NetworkSettings{
						Networks: map[string]*network.EndpointSettings{
							"cont_net": {
								Gateway:   gatewayAddr.String(),
								IPAddress: cont1Addr.String(),
							},
						},
					},
				},
				{
					ContainerJSONBase: &types.ContainerJSONBase{
						ID:   cont2ID,
						Name: "/" + cont2Name,
					},
					Config: &container.Config{
						Labels: map[string]string{
							enabledLabel: "true",
						},
					},
					NetworkSettings: &types.NetworkSettings{
						Networks: map[string]*network.EndpointSettings{
							"cont_net": {
								Gateway:   gatewayAddr.String(),
								IPAddress: cont2Addr.String(),
							},
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
							matchIPExprs(ref(cont2Addr.As4())[:], dstAddrOffset),
							matchProtoExprs(unix.IPPROTO_UDP),
							matchPortExprs(9001, dstPortOffset),
							matchConnStateExprs(stateNewEst),
							[]expr.Any{
								&expr.Counter{},
								acceptVerdict,
							},
						),
						UserData: []byte(cont2ID),
					},
					createDropRule(
						&nftables.Chain{
							Name:  buildChainName(cont1Name, cont1ID),
							Table: filterTable,
						},
						cont1ID,
					),
				},
				{
					Name:  buildChainName(cont2Name, cont2ID),
					Table: filterTable,
				}: {
					{
						Exprs: slicesJoin(
							matchIPExprs(ref(cont2Addr.As4())[:], srcAddrOffset),
							matchIPExprs(ref(cont1Addr.As4())[:], dstAddrOffset),
							matchProtoExprs(unix.IPPROTO_UDP),
							matchPortExprs(9001, srcPortOffset),
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
							Name:  buildChainName(cont2Name, cont2ID),
							Table: filterTable,
						},
						cont2ID,
					),
				},
			},
		},
		{
			name: "allow containers to access each other",
			containers: []types.ContainerJSON{
				{
					ContainerJSONBase: &types.ContainerJSONBase{
						ID:   cont1ID,
						Name: "/" + cont1Name,
					},
					Config: &container.Config{
						Labels: map[string]string{
							enabledLabel: "true",
							rulesLabel: `
output:
  - container: container2
    network: cont_net
    proto: tcp
    port: 202`,
						},
					},
					NetworkSettings: &types.NetworkSettings{
						Networks: map[string]*network.EndpointSettings{
							"cont_net": {
								Gateway:   gatewayAddr.String(),
								IPAddress: cont1Addr.String(),
							},
						},
					},
				},
				{
					ContainerJSONBase: &types.ContainerJSONBase{
						ID:   cont2ID,
						Name: "/" + cont2Name,
					},
					Config: &container.Config{
						Labels: map[string]string{
							enabledLabel: "true",
							rulesLabel: `
output:
  - container: container1
    network: cont_net
    proto: tcp
    port: 101`,
						},
					},
					NetworkSettings: &types.NetworkSettings{
						Networks: map[string]*network.EndpointSettings{
							"cont_net": {
								Gateway:   gatewayAddr.String(),
								IPAddress: cont2Addr.String(),
							},
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
							matchIPExprs(ref(cont2Addr.As4())[:], dstAddrOffset),
							matchProtoExprs(unix.IPPROTO_TCP),
							matchPortExprs(101, srcPortOffset),
							matchConnStateExprs(stateEst),
							[]expr.Any{
								&expr.Counter{},
								acceptVerdict,
							},
						),
						UserData: []byte(cont2ID),
					},
					{
						Exprs: slicesJoin(
							matchIPExprs(ref(cont1Addr.As4())[:], srcAddrOffset),
							matchIPExprs(ref(cont2Addr.As4())[:], dstAddrOffset),
							matchProtoExprs(unix.IPPROTO_TCP),
							matchPortExprs(202, dstPortOffset),
							matchConnStateExprs(stateNewEst),
							[]expr.Any{
								&expr.Counter{},
								acceptVerdict,
							},
						),
						UserData: []byte(cont2ID),
					},
					createDropRule(
						&nftables.Chain{
							Name:  buildChainName(cont1Name, cont1ID),
							Table: filterTable,
						},
						cont1ID,
					),
				},
				{
					Name:  buildChainName(cont2Name, cont2ID),
					Table: filterTable,
				}: {
					{
						Exprs: slicesJoin(
							matchIPExprs(ref(cont2Addr.As4())[:], srcAddrOffset),
							matchIPExprs(ref(cont1Addr.As4())[:], dstAddrOffset),
							matchProtoExprs(unix.IPPROTO_TCP),
							matchPortExprs(101, dstPortOffset),
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
							matchIPExprs(ref(cont2Addr.As4())[:], srcAddrOffset),
							matchIPExprs(ref(cont1Addr.As4())[:], dstAddrOffset),
							matchProtoExprs(unix.IPPROTO_TCP),
							matchPortExprs(202, srcPortOffset),
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
							Name:  buildChainName(cont2Name, cont2ID),
							Table: filterTable,
						},
						cont2ID,
					),
				},
			},
		},
		{
			name: "allow external access to mapped ports",
			containers: []types.ContainerJSON{
				{
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
    allow: true`,
						},
					},
					NetworkSettings: &types.NetworkSettings{
						NetworkSettingsBase: types.NetworkSettingsBase{
							Ports: nat.PortMap{
								"80/tcp": []nat.PortBinding{
									{
										HostIP:   "0.0.0.0",
										HostPort: "80",
									},
									{
										HostIP:   "::",
										HostPort: "80",
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
			},
			expectedRules: map[*nftables.Chain][]*nftables.Rule{
				whalewallChain: {
					{
						Exprs: slicesJoin(
							matchIPExprs(ref(localAddr.As4())[:], srcAddrOffset),
							matchProtoExprs(unix.IPPROTO_UDP),
							matchPortExprs(5533, dstPortOffset),
							matchConnStateExprs(stateNew),
							[]expr.Any{
								&expr.Counter{},
								dropVerdict,
							},
						),
						UserData: []byte(cont1ID),
					},
					{
						Exprs: slicesJoin(
							matchIPExprs(ref(localAddr.As4())[:], srcAddrOffset),
							matchProtoExprs(unix.IPPROTO_TCP),
							matchPortExprs(80, dstPortOffset),
							matchConnStateExprs(stateNew),
							[]expr.Any{
								&expr.Counter{},
								dropVerdict,
							},
						),
						UserData: []byte(cont1ID),
					},
					srcJumpRule,
					dstJumpRule,
				},
				{
					Name:  buildChainName(cont1Name, cont1ID),
					Table: filterTable,
				}: {
					{
						Exprs: slicesJoin(
							matchIPExprs(ref(gatewayAddr.As4())[:], srcAddrOffset),
							matchIPExprs(ref(cont1Addr.As4())[:], dstAddrOffset),
							matchProtoExprs(unix.IPPROTO_UDP),
							matchPortExprs(53, dstPortOffset),
							matchConnStateExprs(stateNew),
							[]expr.Any{
								&expr.Counter{},
								dropVerdict,
							},
						),
						UserData: []byte(cont1ID),
					},
					{
						Exprs: slicesJoin(
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
							matchIPExprs(ref(gatewayAddr.As4())[:], srcAddrOffset),
							matchIPExprs(ref(cont1Addr.As4())[:], dstAddrOffset),
							matchProtoExprs(unix.IPPROTO_TCP),
							matchPortExprs(80, dstPortOffset),
							matchConnStateExprs(stateNew),
							[]expr.Any{
								&expr.Counter{},
								dropVerdict,
							},
						),
						UserData: []byte(cont1ID),
					},
					{
						Exprs: slicesJoin(
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
			name: "allow access from 192.168.1.0/24 to mapped ports",
			containers: []types.ContainerJSON{
				{
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
    ip: 192.168.1.0/24`,
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
							matchPortExprs(53, dstPortOffset),
							matchConnStateExprs(stateNew),
							[]expr.Any{
								&expr.Counter{},
								dropVerdict,
							},
						),
						UserData: []byte(cont1ID),
					},
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
							matchIPExprs(ref(gatewayAddr.As4())[:], srcAddrOffset),
							matchIPExprs(ref(cont1Addr.As4())[:], dstAddrOffset),
							matchProtoExprs(unix.IPPROTO_TCP),
							matchPortExprs(80, dstPortOffset),
							matchConnStateExprs(stateNew),
							[]expr.Any{
								&expr.Counter{},
								dropVerdict,
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
			containers: []types.ContainerJSON{
				{
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
    allow: true`,
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
		{
			name: "allow localhost access to mapped ports with queue",
			containers: []types.ContainerJSON{
				{
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
    verdict:
      queue: 1000`,
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
							matchConnStateExprs(stateNew),
							[]expr.Any{
								&expr.Counter{},
								&expr.Queue{
									Num: 1000,
								},
							},
						),
						UserData: []byte(cont1ID),
					},
					{
						Exprs: slicesJoin(
							matchIPExprs(ref(gatewayAddr.As4())[:], srcAddrOffset),
							matchIPExprs(ref(cont1Addr.As4())[:], dstAddrOffset),
							matchProtoExprs(unix.IPPROTO_UDP),
							matchPortExprs(443, dstPortOffset),
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
		{
			name: "allow localhost access to mapped ports with same input est queue",
			containers: []types.ContainerJSON{
				{
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
    verdict:
      queue: 1000
      input_est_queue: 1000
      output_est_queue: 1001`,
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
								&expr.Queue{
									Num: 1000,
								},
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
								&expr.Queue{
									Num: 1001,
								},
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

	testCreatingRules := func(tt ruleCreationTest, allContainersStarted bool, clearRules bool) func(*testing.T) {
		return func(t *testing.T) {
			is := is.New(t)

			dbFile := filepath.Join(t.TempDir(), "db.sqlite")
			r, err := NewRuleManager(context.Background(), logger, dbFile, defaultTimeout)
			is.NoErr(err)

			var dockerCli *mockDockerClient
			if allContainersStarted {
				dockerCli = newMockDockerClient(tt.containers)
			} else {
				dockerCli = newMockDockerClient(nil)
			}
			r.newDockerClient = func() (dockerClient, error) {
				return dockerCli, nil
			}

			// create mock nftables client and add required prerequisite
			// DOCKER-USER chain
			mfc := newMockFirewall(logger)
			mfc.AddTable(filterTable)
			mfc.AddChain(&nftables.Chain{
				Name:  dockerChainName,
				Table: filterTable,
				Type:  nftables.ChainTypeFilter,
			})
			is.NoErr(mfc.Flush())
			r.newFirewallClient = func() (firewallClient, error) {
				return mfc, nil
			}

			// create new database and base rules
			err = r.init(context.Background())
			is.NoErr(err)
			err = r.createBaseRules()
			is.NoErr(err)
			t.Cleanup(func() {
				err := r.clearRules(context.Background())
				is.NoErr(err)
			})

			// create new rules for containers then attempt to recreate
			// rules and verify no new rules were added
			for _, containerIsNew := range []bool{true, false} {
				// create rules
				for _, c := range tt.containers {
					if !allContainersStarted {
						dockerCli.containers = append(dockerCli.containers, c)
					}

					err := r.createContainerRules(context.Background(), c, containerIsNew)
					is.NoErr(err)
				}

				// check that created rules are what is expected
				for chain, expectedRules := range tt.expectedRules {
					rules, err := mfc.GetRules(chain.Table, chain)
					is.NoErr(err)

					compareRules(t, comparer, chain.Name, expectedRules, rules)
				}
			}

			if clearRules {
				// check that clearing rules removes all whalewall rules
				// and sets
				err := r.clearRules(context.Background())
				is.NoErr(err)

				is.True(len(mfc.tables[filterTableName].sets) == 0)
				chains := maps.Values(mfc.chains)
				slices.SortFunc(chains, func(a, b chain) bool {
					return a.chain.Name < b.chain.Name
				})
				is.True(len(chains) == 3)
				is.True(chains[0].chain.Name == dockerChainName)
				is.True(chains[1].chain.Name == inputChainName)
				is.True(chains[2].chain.Name == outputChainName)
			} else {
				// check that deleting container rules removes all rules
				// of that container
				for _, c := range tt.containers {
					contName := stripName(c.Name)
					err := r.deleteContainerRules(context.Background(), c.ID, contName)
					is.NoErr(err)

					checkMfc := mfc.clone()
					chain := &nftables.Chain{
						Name:  buildChainName(contName, c.ID),
						Table: filterTable,
					}
					_, err = checkMfc.GetRules(filterTable, chain)
					is.True(errors.Is(err, syscall.ENOENT))
				}
				is.True(len(mfc.tables[filterTableName].sets[containerAddrSetName]) == 0)
			}
		}
	}

	for _, tt := range tests {
		if len(tt.containers) == 1 {
			t.Run(tt.name+" | delete container rules", testCreatingRules(tt, true, false))
			t.Run(tt.name+" | clear all rules", testCreatingRules(tt, true, true))
		} else {
			t.Run(tt.name+" | all containers started | delete container rules", testCreatingRules(tt, true, false))
			t.Run(tt.name+" | all containers started | clear all rules", testCreatingRules(tt, true, true))
			t.Run(tt.name+" | one container at a time | delete container rules", testCreatingRules(tt, false, false))
			t.Run(tt.name+" | one container at a time | clear all rules", testCreatingRules(tt, false, true))
		}
	}
}

func TestDeletingContainers(t *testing.T) {
	containers := []types.ContainerJSON{
		{
			ContainerJSONBase: &types.ContainerJSONBase{
				ID:   cont1ID,
				Name: "/" + cont1Name,
			},
			Config: &container.Config{
				Labels: map[string]string{
					enabledLabel: "true",
					rulesLabel: `
output:
- container: container2
  network: cont_net
  proto: tcp
  port: 201
- container: container2
  network: cont_net
  proto: tcp
  port: 202`,
				},
			},
			NetworkSettings: &types.NetworkSettings{
				Networks: map[string]*network.EndpointSettings{
					"cont_net": {
						Gateway:   gatewayAddr.String(),
						IPAddress: cont1Addr.String(),
					},
				},
			},
		},
		{
			ContainerJSONBase: &types.ContainerJSONBase{
				ID:   cont2ID,
				Name: "/" + cont2Name,
			},
			Config: &container.Config{
				Labels: map[string]string{
					enabledLabel: "true",
				},
			},
			NetworkSettings: &types.NetworkSettings{
				Networks: map[string]*network.EndpointSettings{
					"cont_net": {
						Gateway:   gatewayAddr.String(),
						IPAddress: cont2Addr.String(),
					},
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

	dbFile := filepath.Join(t.TempDir(), "db.sqlite")
	r, err := NewRuleManager(context.Background(), logger, dbFile, defaultTimeout)
	is.NoErr(err)

	dockerCli := newMockDockerClient(nil)
	r.newDockerClient = func() (dockerClient, error) {
		return dockerCli, nil
	}

	// create mock nftables client and add required prerequisite
	// DOCKER-USER chain
	mfc := newMockFirewall(logger)
	mfc.AddTable(filterTable)
	mfc.AddChain(&nftables.Chain{
		Name:  dockerChainName,
		Table: filterTable,
		Type:  nftables.ChainTypeFilter,
	})
	is.NoErr(mfc.Flush())
	r.newFirewallClient = func() (firewallClient, error) {
		return mfc, nil
	}

	// create new database and base rules
	err = r.init(context.Background())
	is.NoErr(err)
	err = r.createBaseRules()
	is.NoErr(err)
	t.Cleanup(func() {
		err := r.clearRules(context.Background())
		is.NoErr(err)
	})

	// create rules
	for _, c := range containers {
		dockerCli.containers = append(dockerCli.containers, c)
		err := r.createContainerRules(context.Background(), c, true)
		is.NoErr(err)
	}

	cont1ChainName := buildChainName(cont1Name, cont1ID)
	cont1Chain := &nftables.Chain{
		Table: filterTable,
		Name:  cont1ChainName,
	}
	cont1RulesBefore, err := mfc.GetRules(filterTable, cont1Chain)
	is.NoErr(err)
	is.True(len(cont1RulesBefore) == 3)

	cont2ChainName := buildChainName(cont2Name, cont2ID)
	cont2Chain := &nftables.Chain{
		Table: filterTable,
		Name:  cont2ChainName,
	}
	cont2RulesBefore, err := mfc.GetRules(filterTable, cont2Chain)
	is.NoErr(err)
	is.True(len(cont2RulesBefore) == 3)

	// delete rules of container 2
	err = r.deleteContainerRules(context.Background(), cont2ID, cont2Name)
	is.NoErr(err)

	// ensure rules related to container 2 were from removed from
	// container 1's chain
	rulesAfterDeletion, err := mfc.GetRules(filterTable, cont1Chain)
	is.NoErr(err)
	is.True(len(rulesAfterDeletion) == 1)

	// recreate rules for container 2
	err = r.createContainerRules(context.Background(), containers[1], true)
	is.NoErr(err)

	// ensure rules of both containers are the same as before
	cont1RulesAfter, err := mfc.GetRules(filterTable, cont1Chain)
	is.NoErr(err)
	cont2RulesAfter, err := mfc.GetRules(filterTable, cont2Chain)
	is.NoErr(err)

	compareRules(t, comparer, cont1ChainName, cont1RulesBefore, cont1RulesAfter)
	compareRules(t, comparer, cont2ChainName, cont2RulesBefore, cont2RulesAfter)
}

type dbOnCommit struct {
	database.DB
	onCommit func(database.TX) error
}

func (d *dbOnCommit) Begin(ctx context.Context, logger *zap.Logger) (database.TX, error) {
	tx, err := d.DB.Begin(ctx, logger)
	if err != nil {
		return nil, err
	}
	return &txOnCommit{
		TX:       tx,
		onCommit: d.onCommit,
	}, nil
}

type txOnCommit struct {
	database.TX
	onCommit func(database.TX) error
}

func (t *txOnCommit) Commit() error {
	return t.onCommit(t.TX)
}

func TestCancelingCreation(t *testing.T) {
	container := types.ContainerJSON{
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
  port: 80
- proto: tcp
  port: 443`,
			},
		},
		NetworkSettings: &types.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{
				"cont_net": {
					Gateway:   gatewayAddr.String(),
					IPAddress: cont1Addr.String(),
				},
			},
		},
	}

	is := is.New(t)
	logger, err := zap.NewDevelopment()
	is.NoErr(err)

	dbFile := filepath.Join(t.TempDir(), "db.sqlite")
	r, err := NewRuleManager(context.Background(), logger, dbFile, defaultTimeout)
	is.NoErr(err)

	// configure database to pause before committing so we can cancel
	// the context
	committing := make(chan struct{})
	done := make(chan struct{})
	r.db = &dbOnCommit{
		DB: r.db,
		onCommit: func(tx database.TX) error {
			committing <- struct{}{}
			<-done
			return tx.Commit()
		},
	}

	dockerCli := newMockDockerClient(nil)
	dockerCli.containers = []types.ContainerJSON{container}
	r.newDockerClient = func() (dockerClient, error) {
		return dockerCli, nil
	}

	// create mock nftables client and add required prerequisite
	// DOCKER-USER chain
	mfc := newMockFirewall(logger)
	mfc.AddTable(filterTable)
	mfc.AddChain(&nftables.Chain{
		Name:  dockerChainName,
		Table: filterTable,
		Type:  nftables.ChainTypeFilter,
	})
	is.NoErr(mfc.Flush())
	r.newFirewallClient = func() (firewallClient, error) {
		return mfc, nil
	}

	// create new database and base rules
	err = r.init(context.Background())
	is.NoErr(err)
	err = r.createBaseRules()
	is.NoErr(err)
	t.Cleanup(func() {
		err := r.clearRules(context.Background())
		is.NoErr(err)
	})

	t.Run("cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		// create rules
		go func() {
			err = r.createContainerRules(ctx, container, true)
			is.True(errors.Is(err, context.Canceled))
			done <- struct{}{}
		}()

		// wait until database transaction is about to be committed
		<-committing

		// check that rules were created
		chainName := buildChainName(cont1Name, cont1ID)
		chain := &nftables.Chain{
			Table: filterTable,
			Name:  chainName,
		}
		rules, err := mfc.GetRules(filterTable, chain)
		is.NoErr(err)
		is.True(len(rules) != 0)

		// let database transaction error out
		cancel()
		done <- struct{}{}
		// wait for rules cleanup to finish
		<-done

		// check that container chain was deleted
		_, err = mfc.GetRules(filterTable, chain)
		is.True(errors.Is(err, syscall.ENOENT))
	})

	t.Run("delete", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		// create rules
		go func() {
			err = r.createContainerRules(ctx, container, true)
			is.True(errors.Is(err, context.Canceled))
			done <- struct{}{}
		}()

		// wait until database transaction is about to be committed
		<-committing

		// check that rules were created
		chainName := buildChainName(cont1Name, cont1ID)
		chain := &nftables.Chain{
			Table: filterTable,
			Name:  chainName,
		}
		rules, err := mfc.GetRules(filterTable, chain)
		is.NoErr(err)
		is.True(len(rules) != 0)

		// let database transaction error out
		err = r.deleteContainerRules(context.Background(), cont1ID, cont1Name)
		is.NoErr(err)
		done <- struct{}{}
		// wait for rules cleanup to finish
		<-done

		// check that container chain was deleted
		_, err = mfc.GetRules(filterTable, chain)
		is.True(errors.Is(err, syscall.ENOENT))
	})
}

func compareRules(t *testing.T, comparer func(r1, r2 *nftables.Rule) bool, chainName string, expectedRules, rules []*nftables.Rule) {
	if len(expectedRules) != len(rules) {
		t.Errorf("chain %s different amount of rules: want %d got %d", chainName, len(expectedRules), len(rules))
		return
	}
	for i := range expectedRules {
		// set rule's table here so we don't have to in test
		// cases above
		expectedRules[i].Table = filterTable

		if !cmp.Equal(expectedRules[i], rules[i], cmp.Comparer(comparer)) {
			t.Errorf("chain %s rule %d not equal:\n%s",
				chainName,
				i,
				cmp.Diff(expectedRules[i].Exprs, rules[i].Exprs),
			)
		}
		if !bytes.Equal(expectedRules[i].UserData, rules[i].UserData) {
			t.Errorf("chain %s rule %d user data not equal:\n%s",
				chainName,
				i,
				cmp.Diff(string(expectedRules[i].UserData), string(rules[i].UserData)),
			)
		}
	}
}

func slicesJoin[T any](s ...[]T) (ret []T) {
	for _, ss := range s {
		ret = append(ret, ss...)
	}

	return ret
}
