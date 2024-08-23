# W2E

**Window to Europe** — secured tunneling solution.

## Scheme

[![w2e_scheme.svg](./misc/w2e_scheme.svg)](https://app.diagrams.net/#H6uoMycop/W2E/main/misc/w2e_scheme.svg)


## Server

**OS:** `Linux`

**Operating principle:** Pass packets to userspace via `NFQUEUE`

**Dependencies:**

```
apt install -y build-essential git cmake libnetfilter-queue-dev libnetfilter-queue1 iptables #tcpdump
```


## Client

**OS:** `Windows`

**Operating principle:** Pass packets to userspace via `WinDivert`



## Related repos

[WinDivert](https://github.com/basil00/WinDivert)

[GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)

## Notes

- If your build fails with

```
CMake Error: failed to create symbolic link
```

you should elevate to Administrator mode.

- Example iptables rule to pass packets to `NFQUEUE` 0

```
iptables -t raw -A PREROUTING -p tcp --sport 80 -i ens4 -j NFQUEUE --queue-num 0 --queue-bypass
iptables -t raw -A PREROUTING -p tcp --sport 443 -i ens4 -j NFQUEUE --queue-num 0 --queue-bypass
iptables -t raw -A PREROUTING -p udp --dport 5256 -i ens4 -j NFQUEUE --queue-num 0 --queue-bypass
iptables -t raw -A PREROUTING -p udp --sport 53 -i ens4 -j NFQUEUE --queue-num 0 --queue-bypass


iptables -t raw -A PREROUTING -p tcp -i ens4 -j NFQUEUE --queue-num 0 --queue-bypass
iptables -t raw -A PREROUTING -p udp -i ens4 -j NFQUEUE --queue-num 0 --queue-bypass

```

- Enlarge MTU

```
ip l s dev ens4 mtu 1500
```


