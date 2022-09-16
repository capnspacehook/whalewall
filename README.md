# whalewall

`go install github.com/capnspacehook/whalewall@latest`

Easily mange firewall rules for docker containers.

## Requirements

Linux with a recent kernel, around 5.10 or newer. Tested with nftables v1.0.2 and Docker 20.10.18,
though I'm sure some older versions of both will work with whalewall.

## Purpose

Docker by default creates iptables rules to handle container traffic that override any user-set
rules. There are two main ways to get around this:

1. Prevent Docker from creating any iptables rules by setting `"iptables": false` in `/etc/docker/daemon.json`
    - This is the nuclear approach. It will break most networking for containers, and require that
    you manage iptables for containers manually, which is a very involved process.
2. Add rules to the `DOCKER-USER` iptables chain
    - Docker ensures that rules in this chain are processed *before* any rules Docker creates.

Adding rules to the `DOCKER-USER` chain is what whalewall does to avoid managing more firewall rules
than it needs to. You may be wondering if whalewall is necessary, after all it is very easy to add
firewall rules to the `DOCKER-USER` chain yourself. Well, Docker containers and networks are ephemeral,
meaning every time a container or network is destroyed and recreated, the IP address and subnet
respectively will be randomized. Whalewall takes care of creating or deleting rules when containers
are created or killed, which would be very tedious and error-prone manually.

## Mechanism

Whalewall listens for Docker container `create` and `kill` events and creates or deletes nftables
rules appropriately. Why is nftables used instead of iptables? A few reasons:

- nftables can be configured programmatically unlike iptables, removing the need for whalewall to
execute any binaries
- nftables allows for first-class sets and maps in firewall rules which can greatly speed up
rule processing
- In most distros, iptables rules are translated to nftables rules under the hood, making iptables
rules compatible with nftables rules

## Security

whalewall needs the `NET_ADMIN` capability to manage nftables rules. It also needs to be a member
of the `docker` group in order to use `/var/run/docker/docker.sock` to receive events from the
local Docker daemon.

After installing whalewall, grant it required permissions by running:

```sh
# this must be run first, it will erase any set capabilities
chgrp docker whalewall
setcap 'cap_net_admin=+ep' whalewall

```

## Configuration



## Tips

- If you want a container to only be allowed outbound access on a port to localhost, use the IP
of the `docker0` network interface, which is often `172.17.0.1`.
- If no networks are explicitly configured, use the `default` network when creating container to
container rules.

## Examples
