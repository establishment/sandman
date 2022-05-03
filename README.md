Linux sandbox manager - execute unsecure binaries in a controlled environment.
==============================================================================

Overview
--------
The project was developed as a need for [csacademy](https://csacademy.com/)'s jailing system so the user's code wouldn't be harmfull for the evaluation machines and to limit it's time/memory.


Design goals
------------
- Run and limit binaries with ease.
- Good default-values
- Accesible API

Installation
------------
```sh
git clone https://github.com/establishment/sandman
cd sandman
make build 
```

Settings up cgroups
-------------------
On newer versions of linux you'll need to reimplement the old cgroup pattern
Modify /etc/default/grub :
GRUB_CMDLINE_LINUX="systemd.unified_cgroup_hierarchy=0"
Then run:
update-grub
reboot

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
Mounts selected linux core folders like /bin into it read-only.
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
sudo ./box --init
sudo cp my_binary /tmp/box/0/box
sudo ./box --run --meta -- ./my_binary
```

To get the run stats, run
```sh
cat metares.txt
```

For more options like limiting time, memory or permissions use
```sh
./box --help
```
