Linux sandbox manager - execute unsecure binaries in a controlled environment.
==============================================================================

Overview
--------
The project was developed as a need for [csacademy](https://csacademy.com/)'s jailing system so the user's code wouldn't be harmful for the evaluation machines and to limit its time/memory.

This version **only supports cgroups v2** and will not work with legacy cgroups v1 systems.

Design goals
------------
- Run and limit binaries with ease.
- Good default-values
- Accessible API
- Modern cgroups v2 support

Requirements
------------
- Linux kernel 5.19+ with cgroups v2 and Landlock enabled (`landlock` in `/sys/kernel/security/lsm`): Ubuntu 24.04+ by default, Ubuntu 22.04 only on its HWE kernel
- cgroups v2 mounted at `/sys/fs/cgroup` (standard on systemd systems)

Installation
------------
```sh
git clone https://github.com/establishment/sandman
cd sandman
make build 
```

Cgroups v2 Setup
----------------
Most modern Linux distributions (Ubuntu 21.10+, Debian 11+, RHEL 9+) use cgroups v2 by default.

To verify you have cgroups v2:
```sh
stat -fc %T /sys/fs/cgroup
```
This should return `cgroup2fs`. If it returns `tmpfs`, you're still using cgroups v1.

FAQ
---
#### What Operating Systems are supported?
##### Linux with cgroup support
##### OSX
- only recommended for testing/developing at the moment
- the OSX version is available on branch `osx`

#### How does it work?
It creates a sandbox in /tmp
Forks a child which will execute that command later.
Puts the child into a cgroup, limits it's permissions (like limiting the maximum number of processes which can be spawned from it, limiting max-file size, stack size)
Mounts selected linux core folders like /bin into it read-only, and gives it a /dev and a /tmp of its own.
Carries the command's stdout and stderr through pipes into their files itself, so what it prints is never counted as its memory.
Gives the command's uid an ACL entry on the box files its permission rules name, written straight into the files' extended attributes, and shuts everyone else out of the box.
Forbids the command to create symlinks (Landlock), and never follows one itself when it opens the command's files as root.
Refuses the system calls a solution has no use for (user namespaces, mounts, io_uring, bpf, keys, vsock) with seccomp.
Enters the cgroup and drops root only as the last step before the exec, so none of the setup is billed to the command.
Aplies disk-quotas and sandbox permissions.
Changes the root of the binary into that sandbox folder.
Runs the command from the forked child.
All this time, the main process watches over the boxed process so it doesn't exceed the time-limit.
If it does exceed the time limit, the forked process is killed.
In case it reaches the memory limit, it just cannot alloc more memory. The memory part is limited by the cgroup.

#### Can it be used as a library?
Yes, at the moment it's recommended to fork before using it, since it changes some signal handlers, if that's a problem.
Beside that, it should work as expected. (never tested, it will be integrated into [tumbletest](https://github.com/establishment/tumbletest))

Examples
--------
```sh
sudo ./isolate --box-id=0 --init
sudo cp my_binary /tmp/box/0/box
sudo ./isolate --box-id=0 --run --meta -- ./my_binary
```

A run may have at most 16 processes and threads unless `--processes` says otherwise.

To get the run stats, with its times as integer nanoseconds at the resolution the platform has, run
```sh
cat metares.txt
```

For more options like limiting time, memory or permissions use
```sh
./isolate --help
```
