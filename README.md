# whalewall

Automate management of firewall rules for Docker containers.

## Requirements

Linux with a recent kernel, around 5.10 or newer.

## Purpose

Docker by default creates iptables rules to handle container traffic that override almost all user-set
rules. There are two main ways to get around this:

1. Prevent Docker from creating any iptables rules by setting `"iptables": false` in `/etc/docker/daemon.json`
    - This is the nuclear approach. It will break most networking for containers, and require that
    you manage iptables for containers manually, which can be a very involved process.
2. Add rules to the `DOCKER-USER` iptables chain
    - Docker ensures that rules in this chain are processed *before* any rules Docker creates.

Adding rules to the `DOCKER-USER` chain is what whalewall does to avoid managing more firewall rules
than it needs to. You may be wondering if whalewall is necessary, after all it is very easy to add
firewall rules to the `DOCKER-USER` chain yourself. Well, Docker containers and networks are ephemeral,
meaning every time a container or network is destroyed and recreated, the IP address and subnet
respectively will be randomized. Whalewall takes care of creating or deleting rules when containers
are created or killed, which would be very tedious and error-prone manually. Finally, as well as
managing firewall rules to limit traffic to and from localhost and external interfaces, whalewall
can also enforce container network isolation by limiting traffic between containers.

## Mechanism

Whalewall listens for Docker container `start` and `die` events and creates or deletes
[nftables](https://wiki.nftables.org/wiki-nftables/index.php/What_is_nftables%3F)
rules appropriately. Why is nftables used instead of iptables? A few reasons:

- nftables can be configured programmatically unlike iptables, removing the need for whalewall to
execute any binaries
- nftables allows for first-class sets and maps in firewall rules which can greatly speed up
traffic matching in the kernel
- In most distros, iptables rules are translated to nftables rules under the hood, making iptables
rules compatible with nftables rules

Whalewall stores details of containers it is managing rules for in a SQLite database. If containers
are started or stopped while whalewall isn't running, whalewall will compare currently running
containers to what was last saved to the database and create/delete firewall rules appropriately.

## Security

Whalewall needs the `NET_ADMIN` capability to manage nftables rules. It also needs to be a member
of the `docker` group in order to use `/var/run/docker/docker.sock` to receive events from the
local Docker daemon.

To reduce attack surface, [landlock](https://docs.kernel.org/userspace-api/landlock.html) and
[seccomp](https://docs.kernel.org/next/userspace-api/seccomp_filter.html) are leveraged to ensure
only files and syscalls required by whalewall can be accessed and called respectively. This vastly
limits what whalewall is able to do in the event an attacker is able to execute code in the context
of its process. However, this will not prevent said attacker from taking advantage of the Docker
socket whalewall has access to which can trivially lead to privilege escalation.

## Installation

### Docker image

Download the Docker image:

```sh
docker pull ghcr.io/capnspacehook/whalewall:0.2.0
```

Ensure whalewall is given necessary permissions, and that it is using `host` network mode. This
allows the whalewall container to modify host firewall rules.

Example Docker compose file:

```yaml
version: "3"
services:
  whalewall:
    cap_add: 
      - NET_ADMIN
    image: ghcr.io/capnspacehook/whalewall
    network_mode: host
    volumes:
      - whalewall_data:/data
      - /var/run/docker.sock:/var/run/docker.sock:ro

volumes:
  whalewall_data:
```

### Binary install

If you want to run whalewall natively, download a release binary.

Or if you want to compile from source, assuming you have Go 1.19 installed:

```sh
go install github.com/capnspacehook/whalewall/cmd/whalewall@latest
```

After installing whalewall, grant it required permissions by running:

```sh
# this must be run first, it will erase any set capabilities
chgrp docker whalewall
setcap 'cap_net_admin=+ep' whalewall

```

## Configuration

Whalewall uses Docker labels for configuration:

- `whalewall.enabled` is used to enable or disable firewall rules for a container. If this label is
not present and set to `true` for a container, whalewall will not create any firewall rules for it.
- `whalewall.rules` specifies the firewall rules for a container. If this label is not specified but
`whalewall.enabled=true` is, no traffic will be allowed to or from the container (unless another
container has an output rule for this container).

The contents of the `whalewall.rules` label is a yaml config.

Whalewall creates rules with a default drop policy, meaning any traffic not explicitly allowed will
be dropped.

### Example

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
            ips:
              - "192.168.1.0/24"
        output:
          # allow postgres connections
          - network: default
            container: miniflux_db
            proto: tcp
            dst_ports:
              - 5432
          # allow DNS requests
          - log_prefix: "dns"
            proto: udp
            dst_ports:
              - 53
          # allow HTTPS requests
          - log_prefix: "https"
            proto: tcp
            dst_ports:
              - 443
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

### Rules config reference

```yaml
# controls traffic from localhost or external networks to a container on mapped ports
mapped_ports:
  # controls traffic from localhost
  localhost:
    # required; allow traffic from localhost or not 
    allow: false
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
    allow: false
    # optional; log new inbound traffic that this rule will match
    log_prefix: ""
    # optional; a list of IP addresses, CIDRs, or ranges of IP addresses to allow traffic from
    ips: []
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
    # optional; a list of IP addresses, CIDRs, or ranges of IP addresses to allow traffic to
    ips: []
    # optional; a container to allow traffic to. This can be either the name of the container or
    # the service name of the container is docker compose is used
    container: ""
    # required; either 'tcp' or 'udp'
    proto: ""
    # optional; a list of source ports to allow traffic to. Can be a single port or a
    # range of ports.
    src_ports: []
    # optional; a list of destination ports to allow traffic to. Can be a single port or a
    # range of ports.
    dst_ports: []
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

Port and IP ranges are inclusive. Examples:

- `4000-5000` will match all ports between and including port 4000 and port 5000
- `1.1.1.1-2.2.2.2` will match all IPs between and including 1.1.1.1 and 2.2.2.2

### Docker environmental variables

Whalewall accepts several environmental variables that can be used to configure how it connects to a Docker server:

- `DOCKER_HOST` to set the URL to the Docker server.
- `DOCKER_API_VERSION` to set the version of the Docker API to use, leave empty for latest.
- `DOCKER_CERT_PATH` to specify the directory from which to load the TLS certificates (ca.pem, cert.pem, key.pem).
- `DOCKER_TLS_VERIFY` to enable or disable TLS verification (off by default).

### Tips

- Logged traffic is sent to the kernel log file, typically `/var/log/kern.log` for Debian based distros
and `/var/log/messages` for RHEL based distros
- If you want a container to only be allowed outbound access on a port to localhost, use the IP
of the `docker0` network interface, which is often `172.17.0.1`
- If no Docker networks are explicitly created, use the `default` network when creating container to
container rules

## Verifying releases

Starting from v0.2.0, all Docker images and binary checksum files are signed. You can verify
images or released binaries to ensure they were not tampered with in transit.

Verifying Docker images or binaries both require [`cosign`](https://github.com/sigstore/cosign).

### Verifying Docker images

Simply check the signature of the image with `cosign`:

```sh
cosign verify ghcr.io/capnspacehook/whalewall:<version> | jq
```

You can verify the image was built by Github Actions by inspecting the `Issuer` and `Subject` fields of the output.

### Verifying binaries

Download the checksums file, certificate, signature and the archive to the same directory.

Extract the binary from the archive, verify the checksums file and verify the contents of the binary:

```sh
tar xfs whalewall_<version>_linux_amd64.tar.gz
cosign verify-blob --certificate checksums.txt.crt --signature checksums.txt.sig checksums.txt
sha256sum -c checksums.txt
```

### Reproducing released binaries

You can also reproduce the released binaries to verify that they were built from this unmodified
source code. Verifying binaries requires [`gorepro`](https://github.com/capnspacehook/gorepro).

First, download the release archive and extract it. Clone this repro and go into it.

Install `gorepro` and run it on the extracted release binary. `gorepro` will tell you if reproducing
the binary was successful. Don't worry about checking out the correct tag or commit, gorepro will
handle that for you.

If you don't trust `gorepro` you can run it again additionally passing the `-d` flag. This will
print the commands `gorepro` generated to reproduce the release binary. You can run the printed commands
and verify for yourself that the reproduced binary is bit for bit identical to the released one.

```sh
tar fxs whalewall_<version>_linux_amd64.tar.gz
git clone https://github.com/capnspacehook/whalewall whalewall-src
cd whalewall-src

# reproduce binary
go install github.com/capnspacehook/gorepro@latest
gorepro -b="-ldflags=-s -w -X main.version <version>" ../whalewall

# reproduce by manually running command from gorepro
BUILD_CMD="$(gorepro -d -b='-ldflags=-s -w -X main.version <version>' ../whalewall)"
echo "$BUILD_CMD"
"$BUILD_CMD"
sha256sum whalewall whalewall.repro
```
