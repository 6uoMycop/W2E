# W2E

**Window to Europe** — secured tunneling solution.

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
iptables -t raw -A PREROUTING -i ens4 -j NFQUEUE --queue-num 0 --queue-bypass
```

- To enable `NFQUEUE` on WSL you need to recompile WSL kernel. The following guide was tested on Debian with linux-msft-wsl-5.15.146.1 kernel.

	- Install update MSI from [here](https://learn.microsoft.com/ru-ru/windows/wsl/install-manual#step-4---download-the-linux-kernel-update-package)

	- Install dependencies

	```
	apt install -y build-essential flex bison libssl-dev libelf-dev pkg-config bc libncurses-dev
	```

	- Clone WSL Linux kernel Source code

	```
	git clone https://github.com/microsoft/WSL2-Linux-Kernel.git
	cd WSL2-Linux-Kernel
	```

	- Determine kernel version

	```
	uname -a
	```

	- Checkout to appropriate kernel sources version
	
	```
	git checkout linux-msft-wsl-5.15.146.1
	```

	- Copy kernel config

	```
	cat /proc/config.gz | gunzip > .config
	////cp Microsoft/config-wsl .config
	```
	
	- Configure the kernel

	```
	make menuconfig
	```

	- Compile the kernel
	
	```
	make
	```

	- Copy compiled image outside WSL
	
	```
	cp arch/x86/boot/bzImage /mnt/c/...
	```

	- Exit WSL sessions and shutdown WSL system (cmd, powershell)

	```
	wsl --shutdown
	```

	- Backup old kernel

	In `C:\Windows\System32\lxss\tools` there is a file `kernel`. Rename it to `kernel.rollback`.

	- Copy new `bzImage` to `C:\Windows\System32\lxss\tools` as `kernel`.



