# W2E

**Window to Europe** � secured tunneling solution.

## Scheme

[![w2e_scheme.svg](./misc/w2e_scheme.svg)](https://app.diagrams.net/#H6uoMycop/W2E/main/misc/w2e_scheme.svg)


## Args

You can pass custom `config` file as the only w2e_client/w2e_server CLI argument.

If none provided, program will try to use `default.config`.


## Server

**OS:** `Linux`

**Operating principle:** Pass packets to userspace via `NFQUEUE`.

**Dependencies:**

```
apt install -y build-essential git cmake libnetfilter-queue-dev libnetfilter-queue1 iptables #tcpdump
```

### Scheme

<details>
	<summary>Server scheme...</summary>

	[![w2e_scheme_server.svg](./misc/w2e_scheme_server.svg)](https://app.diagrams.net/#H6uoMycop/W2E/main/misc/w2e_scheme_server.svg)
</details>

### Configuration file

<details>
	<summary>Server config...</summary>

	#### Section **[server]**
	
	##### dns= *{none, ip}*
	
	> Open DNS server address to substitute in DNS queries (may be empty = don't change)
	
	##### ip= *ip*
	
	> Server's IP address
	
	#### Section **[client]**
	
	> May be multiple sections. Describes clients.
	
	##### id= *number in range [0, 255]*
	
	> Client's ID in range [0-255].
	> Corresponding client's source port is calculated as \<prefix\>|\<id\>.
	> Value must be unique in configuration file.
	
	##### key= *string of key length*
	
	> Client's AES key.

</details>

## Client

**OS:** `Windows`

**Operating principle:** Pass packets to userspace via `WinDivert`.

### Configuration file

<details>
	<summary>Client config...</summary>

	#### Section **[server]**
	
	##### ip= *ip*
	
	> Server's IP address.
	
	#### Section **[client]**
	
	> May be multiple sections. Describes clients.
	
	##### id= *number in range [0, 255]*
	
	> Client's ID in range [0-255].
	> Corresponding client's source port is calculated as \<prefix\>|\<id\>.
	> Value must be unique in configuration file.
	
	##### ip= *{none, ip}*
	
	> IP address to use as Source address of encapsulated packets.
	> If set empty -- will be used the same Source IP from plain packets.
	
	##### key= *string of key length*
	
	> Client's AES key.
	
</details>

## Related repos

[WinDivert](https://github.com/basil00/WinDivert)

[GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)

[inih](https://github.com/benhoyt/inih)

[xxHash](https://github.com/Cyan4973/xxHash)

[linux](https://github.com/torvalds/linux)

## Notes

- You can stop `WinDivert` service on client using

```
sc stop WinDivert
```

- If your build fails with

```
CMake Error: failed to create symbolic link
```

you should elevate to Administrator mode.

- Example iptables rule to pass packets to `NFQUEUE` 0

```
iptables -t raw -A PREROUTING -p udp --sport 1900 -i ens4 -j NFQUEUE --queue-num 0 --queue-bypass
iptables -t raw -A PREROUTING -p udp --sport 443 -i ens4 -j NFQUEUE --queue-num 0 --queue-bypass
iptables -t raw -A PREROUTING -p tcp --sport 443 -i ens4 -j NFQUEUE --queue-num 0 --queue-bypass
iptables -t raw -A PREROUTING -p tcp --sport 80 -i ens4 -j NFQUEUE --queue-num 0 --queue-bypass
iptables -t raw -A PREROUTING -p udp --dport 5256 -i ens4 -j NFQUEUE --queue-num 0 --queue-bypass
iptables -t raw -A PREROUTING -p udp --sport 53 -i ens4 -j NFQUEUE --queue-num 0 --queue-bypass
```

- Enlarge MTU

```
ip l s dev ens4 mtu 1500
```


