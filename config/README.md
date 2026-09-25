# Configuration as it runs

The four files in this folder are the running configuration of `decoy-01`,
copied verbatim on 25 September 2026. They are not templates.

| File | Belongs at | Owner |
|---|---|---|
| `cowrie.cfg` | `~cowrie/cowrie/etc/cowrie.cfg` | `cowrie:cowrie` |
| `userdb.txt` | `~cowrie/cowrie/etc/userdb.txt` | `cowrie:cowrie` |
| `cowrie.socket` | `/etc/systemd/system/cowrie.socket` | `root:root` |
| `cowrie.service` | `/etc/systemd/system/cowrie.service` | `root:root` |

`cowrie.cfg` and `userdb.txt` are **overrides only**. Cowrie's shipped
defaults live inside the installed package at
`src/cowrie/data/etc/cowrie.cfg.dist` and are never edited there — a `git
pull` would take the changes with them. Anything absent here is the default.

The two systemd units differ from the ones Cowrie ships under `docs/systemd/`:
paths point at the honeypot user's home rather than `/opt`, logging goes to
the journal rather than the deprecated syslog target, and the service runs
`--nodaemon` so systemd can supervise it. See `docs/build.md`.

After changing either unit: `sudo systemctl daemon-reload`, then restart.
After changing `cowrie.cfg`: `sudo systemctl restart cowrie`.
