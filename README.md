# W2E

![Logo](./misc/w2e_client_logo.png)

**Window to Europe** — secured tunneling solution.


## Features

- Encapsulation to IP/UDP, no additional fields
- AES encryption
- DNS proxy
- Multiple clients support using connection tracker


## Limitations

Project is in MVP status now, being updated and should be considered as unstable. So:

- Multithreading not implemented
- Connection tracker has minimal implementation
- Server contains error: some websites are not aaccessible


## Scheme

[![w2e_scheme.svg](./misc/w2e_scheme.svg)](https://app.diagrams.net/#H6uoMycop/W2E/master/misc/w2e_scheme.svg)


## Args

You can pass custom `config` file as the only w2e_client/w2e_server CLI argument.

If none provided, program will try to use `default.config`.


## Server

**OS:** `Linux`

**Operating principle:** Pass packets to userspace via `NFQUEUE`.

**Dependencies:**

```
apt install -y build-essential git cmake libnetfilter-queue-dev libnetfilter-queue1 iptables
```

### Build

```
cmake -B build
cmake --build build
```

### Scheme

[![w2e_scheme_server.svg](./misc/w2e_scheme_server.svg)](https://app.diagrams.net/#H6uoMycop/W2E/master/misc/w2e_scheme_server.svg)

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

### Build

```
cmake.exe -S . -B build
cmake.exe --build ./build --config Release
```

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

##### ip= *ip*

> IP address to use as Source address of encapsulated packets.

##### key= *string of key length*

> Client's AES key.

</details>

## Related repos

[WinDivert](https://github.com/basil00/WinDivert)

[GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)

[inih](https://github.com/benhoyt/inih)

[xxHash](https://github.com/Cyan4973/xxHash)

[linux](https://github.com/torvalds/linux)

[freebsd](https://github.com/freebsd/freebsd-src)

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
iptables -t raw -A PREROUTING -p udp --sport 53 -i ens4 -j NFQUEUE --queue-num 0 --queue-bypass
iptables -t raw -A PREROUTING -p udp --dport 43520:43775 -i ens4 -j NFQUEUE --queue-num 0 --queue-bypass
```

- Enlarge MTU (linux server)

```
ip l s dev ens4 mtu 1500
```

- Turn offloads off (linux server)

```
ethtool -K ens4 tx off sg off tso off gro off rx-gro-hw off
```

- Disable IPv6 (linux server)

```
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
```

- Decrease MTU (Windows client)

<details>
<summary>Windows decrease MTU...</summary>

```
netsh interface ipv4 show subinterfaces
```

>    MTU  Состояние определения носителя   Вх. байт  Исх. байт  Интерфейс
>
> ------  ---------------  ---------  ---------  -------------
>
> 4294967295                1          0     467389  Loopback Pseudo-Interface 1
>
>   1500                1  30151331950  479444648  Беспроводная сеть
>
>   1500                5          0          0  Подключение по локальной сети* 1
>
>   1500                1          0     363096  Ethernet 2
>
>   1500                5          0          0  Подключение по локальной сети* 2

```
netsh interface ipv4 set subinterface <INTERFACE_NAME> mtu=1440 store=active
```

> store        - одно из следующих значений:
>
>               active: настройка действует только до следующей перезагрузки.
>
>           persistent: постоянная настройка.

</details>

