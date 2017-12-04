SandboxIt
=========

Simple to use sandboxing script (WIP / proof of concept code)

Using [bubblewrap](https://github.com/projectatomic/bubblewrap) and fuse,
redirects program away from your personal data, while sill allowing
read-only access to system files.


##### Usage examples:

```
[user@pc RimWorld]$ sandboxit.py ./RimWorldLinux.x86_64
[user@pc ~]$ sandboxit.py discord
```

Creates sandbox linked to program and runs that program in it. Same program
is always started in same sandbox, so it can, for example, load saved game
states from before.

```
[user@pc Observer]$ sandboxit.py -b GAMES ./TheObserver.sh
```

Runs program in sandbox named _GAMES_.

```
sandboxit.py -v --for ./RimWorldLinux.x86_64 mc
```

Runs Midnight Commander in sandbox of other program, so it can be explored freely. This
works with anything, not just `mc`. `bash` may be especially useful.


##### Dependencies

 - [bubblewrap](https://github.com/projectatomic/bubblewrap)
 - python
 - optionaly [fusepy](https://github.com/terencehonles/fusepy), for redirecting write operations to sandbox storage


##### Details

- Sandboxed program can't write outside of sandbox folder in `~/.local/share/sandboxit` and
temp folder in `/tmp/sandboxit`

- Sandboxed program has read-only access to following:
    * /usr, /bin/, /sbin/, /lib and /lib64
    * /opt and /etc
    * /proc and /dev, with same access to /dev/input as your user account

- Sandboxed program has access to X server, pulseaudio server and network.

- Sandboxed program has read-write access to its own, private /tmp, and home directory that _is not_ your actual home directory.