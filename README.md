# Deception Grid

Two honeypots on one rented virtual machine, inbound attack data recorded for
eleven weeks, and what it means for a small manufacturer.

ReDI School Cybersecurity capstone · Hamburg · autumn 2026

> **Status: collecting.** IT door (SSH and telnet) open since 25 September 2026,
> 08:01:20 UTC. OT door (Modbus) open since 6 October 2026. Presenting
> 10–11 December 2026; teardown 12 December.
> Anything marked `[TBC]` is filled from the dataset once collection ends.

## What we found

`[TBC — the headline number, in the first screen: how many distinct sources contacted a machine that is not advertised anywhere]`

`[TBC — image: the IT-versus-controller split]`

Until then, the dated findings notes carry the figures, each with its as-of
time: [`docs/first-contact.md`](docs/first-contact.md) (the IT door's first
forty minutes), [`docs/first-weekend.md`](docs/first-weekend.md) (its first four
days), [`docs/first-ot-hours.md`](docs/first-ot-hours.md) (the OT door's first
fourteen hours: 2 h 32 min to the first stranger, and every request an
identification).

## What this is

A single Ubuntu VM exposes two decoy services to the internet and records
everything that arrives:

- **Cowrie** on ports 22 and 23 — imitates a Linux server with a weak password
- **Conpot** on port 502 — imitates an industrial controller speaking Modbus,
  the protocol factory equipment uses, with its own small-plant register
  emulation so the readings move the way a real controller's would

Neither executes anything sent to it. The machine only ever receives; it never
initiates a connection outward — enforced at the packet filter, not in
configuration, after four days when that was not true (see the rules of
engagement). `analysis/ingest.py` normalises both logs into one SQLite database
and re-derives every column from the original log line on every run.

The second decoy is the point. One honeypot shows that the internet is noisy.
The second, on the same address at the same moment, compares who knocks on an
office door against who goes looking for factory equipment — same scanners,
same country, same minute; the only difference between the doors is the door.

## How it was built

| Stage | What |
| --- | --- |
| Host | Azure B2ats_v2, Ubuntu 24.04 LTS, Austria East, 64 GiB Premium SSD (P6), 1 GB swap |
| Hardening | Admin SSH on a non-standard port, key-only, restricted to one address at the network security group (re-pointed daily by `scripts/allow-me.ps1`); `ufw` default-deny; outbound rejected for both decoy accounts |
| Decoys | Cowrie (22, 23) under systemd socket activation; Conpot (502) under `CAP_NET_BIND_SERVICE`, Python 3.14 via `uv` |
| Pipeline | `backup.ps1` pulls the logs to the laptop; `ingest.py` builds `decoy.sqlite` on the sensor; `weekly.sql` holds the nineteen standing questions; `figures.sh` refreshes every quoted figure with an as-of line |
| Analysis | MITRE ATT&CK mapping in the findings notes; static feature extraction for the captured files and TTY recordings (`analysis/features-*.py`); registration-country lookup (`analysis/geo-lookup.sh`) |

Full build steps, including what went wrong: [`docs/build.md`](docs/build.md).
What the mistakes taught, and what would be done differently:
[`docs/lessons-learnt.md`](docs/lessons-learnt.md).

## Ethics and legality

This project only ever receives traffic sent to its own machine. It never
scans, probes, replies to, or executes anything — and the two occasions on
which that rule was broken by the project itself are recorded, with their
windows, in the rules of engagement rather than quietly fixed.

- [`docs/rules-of-engagement.md`](docs/rules-of-engagement.md) — agreed before
  deployment, audited since. Its *Personal data* section states what is
  collected, why it is lawful to hold, and in what form it is published.
- Nothing Cowrie captured as a file is in this repository, and nothing
  captured ever leaves the sensor or is submitted to a third party, hashes
  included.
- The sensor's address, the analyst's addresses, host-key fingerprints and the
  analyst address list are deliberately not in this repository.

## Repository

```
analysis/     ingest.py, schema.sql, weekly.sql, figures.sh, geo-lookup.sh,
              features-files.py, features-tty.py, and the README that says
              what order to run them in and which traps each exists to prevent
config/       the running configuration of both decoys, copied verbatim, with
              a placement table and the reasoning for every change from default
docs/         build log, rules of engagement, findings notes, lessons learnt,
              the OT-door runbook, and the evidence screenshots
emulators/    the plant-register emulation that animates the OT decoy
scripts/      allow-me.ps1, backup.ps1, decoy-status
```

There is no dashboard and no aggregated-data directory; the figures live in the
documents, each with its as-of timestamp, and are frozen once before demo day.

## What I would do differently

[`docs/lessons-learnt.md`](docs/lessons-learnt.md), *What I would do
differently* — thirteen items as at 30 September, with dated addenda since.
Written while it was happening rather than after demo day.

## Licence

MIT for the code.
