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

Whalewall listens for Docker container `start` and `kill` events and creates or deletes nftables
rules appropriately. Why is nftables used instead of iptables? A few reasons:

- nftables can be configured programmatically unlike iptables, removing the need for whalewall to
execute any binaries
- nftables allows for first-class sets and maps in firewall rules which can greatly speed up
traffic matching in the kernel
- In most distros, iptables rules are translated to nftables rules under the hood, making iptables
rules compatible with nftables rules

## Security

Whalewall needs the `NET_ADMIN` capability to manage nftables rules. It also needs to be a member
of the `docker` group in order to use `/var/run/docker/docker.sock` to receive events from the
local Docker daemon.

After installing whalewall, grant it required permissions by running:

```sh
# this must be run first, it will erase any set capabilities
chgrp docker whalewall
setcap 'cap_net_admin=+ep' whalewall

```

## Configuration

Whalewall uses Docker labels for configuration:

- `whalewall.enabled` is used to enable or disable firewall rules for a container. If this rule is
not present and set to `true` for a container whalewall will not create any firewall rules for it.
- `whalewall.rules` specifies the firewall rules for a container. If this label is not specified but
`whalewall.enabled=true` is, no traffic will be allowed to or from the container (unless another
container has an output rule for this container).

The contents of the `whalewall.rules` label is a yaml config.

Whalewall creates rules with a default drop policy, meaning any traffic not explicitly allowed will
be dropped.

## Example

Below is an example Docker compose file that configures [Miniflux](https://github.com/miniflux/v2),
a feed reader. Miniflux needs to connect to a Postgresql database to store state and make outbound
HTTPS connections to fetch articles, so that's only what is allowed.

```yaml
version: "3"
services:
  miniflux:
    depends_on:
      - miniflux_db
    environment:
      - DATABASE_URL=postgres://miniflux:secret@miniflux_db/miniflux?sslmode=disable
      - RUN_MIGRATIONS=1
      - CREATE_ADMIN=1
      - ADMIN_USERNAME=admin
      - ADMIN_PASSWORD=password
    image: miniflux/miniflux:latest
    labels:
      whalewall.enabled: true
      whalewall.rules: |
        mapped_ports:
          # allow traffic to port 80 from localhost
          localhost:
            allow: true
          # allow traffic to port 80 from LAN
          external:
            allow: true
            ip: "192.168.1.0/24"
        output:
          # allow postgres connections
          - network: default
            container: miniflux_db
            proto: tcp
            port: 5432
          # allow DNS requests
          - log_prefix: "dns"
            proto: udp
            port: 53
          # allow HTTPS requests
          - log_prefix: "https"
            proto: tcp
            port: 443
    ports:
      - "80:8080/tcp"

  miniflux_db:
    environment:
      - POSTGRES_USER=miniflux
      - POSTGRES_PASSWORD=secret
    image: postgres:alpine
    labels:
      # no rules specified, drop all traffic
      whalewall.enabled: true
```

Note to make this Docker compose config as concise as possible, best practices were not followed.
This is merely intended to be an example of whalewall rules, not how to setup Miniflux securely.

## Rules config reference

```yaml
# controls traffic from localhost or external networks to a container on mapped ports
mapped_ports:
  # controls traffic from localhost
  localhost:
    # required; allow traffic from localhost or not 
    allowed: false
    # optional; log new inbound traffic that this rule will match
    log_prefix: ""
    # optional; settings that allow you to filter traffic further if desired
    verdict:
      # optional; a chain to jump to after matching traffic. This applies to new and established
      # inbound traffic, and established outbound traffic 
      chain: ""
      # optional; the userspace nfqueue to send new outbound packets to
      queue: 0
      # optional; the userspace nfqueue to send established inbound packets to. Required if
      # 'output_est_queue' is set
      input_est_queue: 0
      # optional; the userspace nfqueue to send established inbound packets to. Required if
      # 'input_est_queue' is set
      output_est_queue: 0
  # controls traffic from external networks (from any non-loopback network interface)
  external:
    # required; allow external traffic or not
    allowed: false
    # optional; log new inbound traffic that this rule will match
    log_prefix: ""
    # optional; an IP address, CIDR, or range of IP addresses to allow traffic from
    ip: ""
    # optional; settings that allow you to filter traffic further if desired
    verdict:
      # optional; a chain to jump to after matching traffic. This applies to new and established
      # inbound traffic, and established outbound traffic 
      chain: ""
      # optional; the userspace nfqueue to send new outbound packets to
      queue: 0
      # optional; the userspace nfqueue to send established inbound packets to. Required if
      # 'output_est_queue' is set
      input_est_queue: 0
      # optional; the userspace nfqueue to send established inbound packets to. Required if
      # 'input_est_queue' is set
      output_est_queue: 0
# controls traffic from a container to localhost, another container, or the internet
output:
    # optional; log new outbound traffic that this rule will match
  - log_prefix: ""
    # optional; a Docker network traffic will be allowed out of. If unset, will default to all 
    # networks the container is a member of. Required if 'container' is set
    network: ""
    # optional; an IP address, CIDR, or range of IP addresses to allow traffic to
    ip: ""
    # optional; a container to allow traffic to. This can be either the name of the container or
    # the service name of the container is docker compose is used
    container: ""
    # required; either 'tcp' or 'udp'
    proto: ""
    # required; the port to allow traffic to
    port: 0
    # optional; settings that allow you to filter traffic further if desired
    verdict:
      # optional; a chain to jump to after matching traffic. This applies to new and established
      # inbound traffic, and established outbound traffic 
      chain: ""
      # optional; the userspace nfqueue to send new outbound packets to
      queue: 0
      # optional; the userspace nfqueue to send established inbound packets to. Required if
      # 'output_est_queue' is set
      input_est_queue: 0
      # optional; the userspace nfqueue to send established inbound packets to. Required if
      # 'input_est_queue' is set
      output_est_queue: 0
```

## Tips

- Logged traffic is sent to the kernel log file, typically `/var/log/kern.log` for Debian based distros
and `/var/log/messages` for RHEL based distros
- If you want a container to only be allowed outbound access on a port to localhost, use the IP
of the `docker0` network interface, which is often `172.17.0.1`
- If no Docker networks are explicitly created, use the `default` network when creating container to
container rules
