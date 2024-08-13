# W2E

**Window to Europe** — secured tunneling solution.

## Server

**OS:** `Linux`

**Operating principle:** Pass packets to userspace via `NFQUEUE`

**Dependencies:**

```
apt install -y build-essential git cmake libnetfilter-queue-dev libnetfilter-queue1 #tcpdump
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



- To debug on WSL root access rights are needed. To do that set root as default user.
Create a `/etc/wsl.conf` in the instance with the following setting:

```
[user]
default=root
```

Then on host OS execute:

```
wsl --terminate <distroname>
wsl -d <distroname>
```

- Example iptables rule to pass packets to `NFQUEUE` 0

```
iptables -t raw -A PREROUTING -i ens4 -p icmp -j NFQUEUE --queue-num 0 --queue-bypass
```
