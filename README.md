# whalewall

Example:

```yaml
version: "3"

services:
  nginx1:
    container_name: nginx1
    depends_on:
      - nginx2
    image: nginx:alpine
    labels:
      whalewall.enabled: true
      whalewall.rules: |
        mapped_ports:
          external:
            # allow Tailscale traffic to mapped ports
            allow: true
            ip: "100.64.0.0/10"
        output:
          # allow DNS and HTTPS outbound
          - ip: "172.17.0.1"
            proto: udp
            port: 53
          - proto: tcp
            port: 443
          # allow querying nginx2
          - network: test_net2
            container: nginx2
            proto: tcp
            port: 1337
    networks:
        test_net1:
        test_net2:
    ports:
      - 8080:80

  nginx2:
    container_name: nginx2
    environment:
      - NGINX_PORT=1337
    image: nginx:alpine
    labels:
      whalewall.enabled: true
    networks:
        test_net2:

networks:
    test_net1:
    test_net2:
```
