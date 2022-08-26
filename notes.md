## iptables

-A testie -s 127.0.0.1/32 -d 172.19.0.2/32 -p tcp -m tcp --dport 8080 -j ACCEPT
-A testie -s 172.19.0.2/32 -j DROP

## nftables

ip filter testie 150
  [ meta load l4proto => reg 1 ]
  [ cmp eq reg 1 0x00000006 ]
  [ payload load 4b @ network header + 12 => reg 1 ]
  [ cmp eq reg 1 0x0100007f ]
  [ payload load 4b @ network header + 16 => reg 1 ]
  [ cmp eq reg 1 0x020013ac ]
  [ match name tcp rev 0 ]
  [ counter pkts 0 bytes 0 ]
  [ immediate reg 0 accept ]

ip filter testie 151 150
  [ payload load 4b @ network header + 12 => reg 1 ]
  [ cmp eq reg 1 0x020013ac ]
  [ counter pkts 0 bytes 0 ]
  [ immediate reg 0 drop ]

table ip filter {
        chain testie {
                meta l4proto tcp ip saddr 127.0.0.1 ip daddr 172.19.0.2 tcp dport 8080 counter packets 0 bytes 0 accept
                ip saddr 172.19.0.2 counter packets 0 bytes 0 drop
        }
}

## findings

- set elements can be added multiple times with no error, will not be duplicated
- sets can be created multiple times with no error, will not be overwritten


## DNS from container to host

- https://stackoverflow.com/questions/31324981/how-to-access-host-port-from-docker-container
- set container DNS to go IP of `docker0` interface

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

## docker

- https://superuser.com/questions/1302921/tell-docker-to-use-the-dns-server-in-the-host-system
- set default DNS server for containers `/etc/docker/daemon.json`
  - `"dns": ["172.17.0.1"]`
- have unbound bind to `172.17.0.1` (IP of `docker0` interface)
- have unbound allow queries from `172.0.0.0/8`
