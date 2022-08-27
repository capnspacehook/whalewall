## nftables rules

```sh
table ip filter {
        map whalewall-ipv4-input-allow {
                type ipv4_addr . inet_proto . inet_service . ct_state : verdict
        }
}

table ip filter {
        set whalewall-ipv4-drop {
                type ipv4_addr
        }
}

ip filter whalewall 59
  [ meta load l4proto => reg 1 ]
  [ cmp eq reg 1 0x00000006 ]
  [ payload load 4b @ network header + 16 => reg 1 ]
  [ payload load 1b @ network header + 9 => reg 9 ]
  [ payload load 2b @ transport header + 0 => reg 10 ]
  [ ct load state => reg 11 ]
  [ lookup reg 1 set whalewall-ipv4-input-allow dreg 0 0x0 ]

ip filter whalewall 60 59
  [ meta load l4proto => reg 1 ]
  [ cmp eq reg 1 0x00000011 ]
  [ payload load 4b @ network header + 16 => reg 1 ]
  [ payload load 1b @ network header + 9 => reg 9 ]
  [ payload load 2b @ transport header + 0 => reg 10 ]
  [ ct load state => reg 11 ]
  [ lookup reg 1 set whalewall-ipv4-input-allow dreg 0 0x0 ]

ip filter whalewall 61 60
  [ meta load l4proto => reg 1 ]
  [ cmp eq reg 1 0x00000006 ]
  [ payload load 4b @ network header + 12 => reg 1 ]
  [ payload load 1b @ network header + 9 => reg 9 ]
  [ payload load 2b @ transport header + 2 => reg 10 ]
  [ ct load state => reg 11 ]
  [ lookup reg 1 set whalewall-ipv4-output-allow dreg 0 0x0 ]

ip filter whalewall 62 61
  [ meta load l4proto => reg 1 ]
  [ cmp eq reg 1 0x00000011 ]
  [ payload load 4b @ network header + 12 => reg 1 ]
  [ payload load 1b @ network header + 9 => reg 9 ]
  [ payload load 2b @ transport header + 2 => reg 10 ]
  [ ct load state => reg 11 ]
  [ lookup reg 1 set whalewall-ipv4-output-allow dreg 0 0x0 ]

ip filter whalewall 63 62
  [ payload load 4b @ network header + 12 => reg 1 ]
  [ lookup reg 1 set whalewall-ipv4-drop 0x0 ]
  [ immediate reg 0 drop ]

ip filter whalewall 64 63
  [ payload load 4b @ network header + 16 => reg 1 ]
  [ lookup reg 1 set whalewall-ipv4-drop 0x0 ]
  [ immediate reg 0 drop ]

table ip filter {
        chain whalewall {
                ip daddr . ip protocol . tcp sport . ct state vmap @whalewall-ipv4-input-allow
                ip daddr . ip protocol . udp sport . ct state vmap @whalewall-ipv4-input-allow
                ip saddr . ip protocol . tcp dport . ct state vmap @whalewall-ipv4-output-allow
                ip saddr . ip protocol . udp dport . ct state vmap @whalewall-ipv4-output-allow
                ip saddr @whalewall-ipv4-drop drop
                ip daddr @whalewall-ipv4-drop drop
        }
}
```

## findings

- set elements can be added multiple times with no error, will not be duplicated
- sets can be created multiple times with no error, will not be overwritten

## DNS from container to host

- https://stackoverflow.com/questions/31324981/how-to-access-host-port-from-docker-container
- https://superuser.com/questions/1302921/tell-docker-to-use-the-dns-server-in-the-host-system
- set default DNS server for containers `/etc/docker/daemon.json`
  - `"dns": ["172.17.0.1"]`
- have unbound bind to `172.17.0.1` (IP of `docker0` interface)
- have unbound allow queries from `172.0.0.0/8`

## rules to use

- create "whalewall" table
- create multiple rules that use verdict maps to resolve verdicts
- behavior can easily be modified simply by adding/deleting elements form maps

rules:

- input:
  - src
    - input: src, new/est/related
    - output: dst, est/related
  - proto, dst port
    - input: proto, dst port, new/est/related
    - output: proto, src port, est/related
  - src, proto, dst port
    - input: src, proto, dst port, new/est/related
    - output: dst, proto, src port, est/related
- output:
  - dst
    - input: dst, new/est/related
    - output: src, est/related
  - proto, src port
    - input: proto, src port, new/est/related
    - output: proto, dst port, est/related
  - dst, proto, src port
    - input: dst, proto, src port, new/est/related
    - output: src, proto, dst port, est/related

```yaml
whalewall.input:
  src_ip: 
  src_container:
  proto: optional +
  port:  optional +
  queue: optional
  input_est_queue: optional  +
  output_est_queue: optional +

whalewall.output:
  dst_ip: 
  dst_container:
  proto: optional +
  port:  optional +
  queue: optional
  input_est_queue: optional  +
  output_est_queue: optional +
```

sudo nft add set ip filter whalewall-ipv4-drop "{ type ipv4_addr ; }"
sudo nft add map filter whalewall-ipv4-input-allow "{ type ipv4_addr . inet_proto . inet_service . ct_state : verdict ; }"
sudo nft add map filter whalewall-ipv4-output-allow "{ type ipv4_addr . inet_proto . inet_service . ct_state : verdict ; }"
sudo nft add element ip filter whalewall-ipv4-drop "{ 172.19.0.2 }"
sudo nft add element ip filter whalewall-ipv4-output-allow "{ 172.19.0.2 . udp . 53 . new : accept }"
sudo nft add element ip filter whalewall-ipv4-output-allow "{ 172.19.0.2 . udp . 53 . established : accept }"
sudo nft add element ip filter whalewall-ipv4-output-allow "{ 172.19.0.2 . udp . 53 . related : accept }"
sudo nft add element ip filter whalewall-ipv4-input-allow "{ 172.19.0.2 . udp . 53 . established : accept }" 
sudo nft add element ip filter whalewall-ipv4-input-allow "{ 172.19.0.2 . udp . 53 . related : accept }"
sudo nft add element ip filter whalewall-ipv4-output-allow "{ 172.19.0.2 . tcp . 443 . new : accept }"
sudo nft add element ip filter whalewall-ipv4-output-allow "{ 172.19.0.2 . tcp . 443 . established: accept }"
sudo nft add element ip filter whalewall-ipv4-output-allow "{ 172.19.0.2 . tcp . 443 . related: accept }"
sudo nft add element ip filter whalewall-ipv4-input-allow "{ 172.19.0.2 . tcp . 443 . established: accept }" 
sudo nft add element ip filter whalewall-ipv4-input-allow "{ 172.19.0.2 . tcp . 443 . related: accept }"
