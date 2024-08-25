# W2E

**Window to Europe** — secured tunneling solution.

## Scheme

[![w2e_scheme.svg](./misc/w2e_scheme.svg)](https://app.diagrams.net/#H6uoMycop/W2E/main/misc/w2e_scheme.svg)


## Args

You can pass custom `config` file as the only w2e_client/w2e_server CLI argument.

If none provided, program will try to use `default.config`


## Server

**OS:** `Linux`

**Operating principle:** Pass packets to userspace via `NFQUEUE`

**Dependencies:**

```
apt install -y build-essential git cmake libnetfilter-queue-dev libnetfilter-queue1 iptables #tcpdump
```

### Configuration file

#### Section **[server]**

##### dns= *{none, ip}*

Open DNS server address to substitute in DNS queries (may be empty = don't change)

##### ip= *ip*

Server's IP address

#### Section **[client]**

May be multiple sections. Describes clients.

##### id= *number in range [0, 255]*

Client's ID in range [0-255].
Corresponding client's source port is calculated as <prefix>|<id>.
Value must be unique in configuration file.

##### key= *string of key length*

Client's AES key.


## Client

**OS:** `Windows`

**Operating principle:** Pass packets to userspace via `WinDivert`

### Configuration file

#### Section **[server]**

##### ip= *ip*

Server's IP address

#### Section **[client]**

May be multiple sections. Describes clients.

##### id= *number in range [0, 255]*

Client's ID in range [0-255].
Corresponding client's source port is calculated as <prefix>|<id>.
Value must be unique in configuration file.

##### ip= *{none, ip}*

IP address to use as Source address of encapsulated packets.
If set empty -- will be used the same Source IP from plain packets.

##### key= *string of key length*

Client's AES key.


## Related repos

[WinDivert](https://github.com/basil00/WinDivert)

[GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)

[inih](https://github.com/benhoyt/inih)

## Notes

- If your build fails with

```
CMake Error: failed to create symbolic link
```

you should elevate to Administrator mode.

- Example iptables rule to pass packets to `NFQUEUE` 0

```
iptables -t raw -A PREROUTING -p tcp --sport 443 -i ens4 -j NFQUEUE --queue-num 0 --queue-bypass
iptables -t raw -A PREROUTING -p tcp --sport 80 -i ens4 -j NFQUEUE --queue-num 0 --queue-bypass
iptables -t raw -A PREROUTING -p udp --dport 5256 -i ens4 -j NFQUEUE --queue-num 0 --queue-bypass
iptables -t raw -A PREROUTING -p udp --sport 53 -i ens4 -j NFQUEUE --queue-num 0 --queue-bypass


iptables -t raw -A PREROUTING -p tcp -i ens4 -j NFQUEUE --queue-num 0 --queue-bypass
iptables -t raw -A PREROUTING -p udp -i ens4 -j NFQUEUE --queue-num 0 --queue-bypass

```

- Enlarge MTU

```
ip l s dev ens4 mtu 1500
```


