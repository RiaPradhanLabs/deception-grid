# Deception Grid

Two honeypots on a rented virtual machine (VM), inbound attack data recorded for ~3 months, and what it means for a small manufacturer.

ReDI School Cybersecurity capstone · Hamburg · autumn 2026

> **Status: collecting.** Deployed 24 September 2026, presenting 10 December 2026.
> Anything marked `[TBC]` is filled from the dataset once collection ends.

## What we found

`[TBC — the headline number, in the first screen: how many distinct sources contacted a machine that is not advertised anywhere]`

`[TBC — image: attacks by country, or the IT-versus-controller split]`

## What this is

A single Ubuntu VM exposes two decoy services to the internet and records everything that arrives:

- **Cowrie** on ports 22 and 23 — imitates a Linux server with a weak password
- **Conpot** on port 502 — imitates an industrial controller speaking Modbus (protocol for factory equipment)

Neither executes anything sent to it. The machine only ever receives; it never initiates a connection outward. An hourly Python job normalises both logs into one SQLite database, and a local dashboard reads from it.

The second decoy provides the actually interesting information. The first one honeypot shows that the internet is noisy. The second, on the same address at the same time, compares who knocks on an office door vs who goes looking for factory equipment.

## How it was built

| Stage | What |
| --- | --- |
| Host | Azure B2ats_v2, Ubuntu 24.04 LTS, Austria East, 64 GiB Premium SSD |
| Hardening | Admin SSH on a non-standard port, key-only, restricted to one address at the network security group; `ufw` default-deny; 2 GB swap |
| Decoys | Cowrie (22, 23) and Conpot (502) |
| Pipeline | Hourly cron → Python → SQLite, one geolocation lookup per address |
| Analysis | MITRE ATT&CK mapping, risk register, CIS Controls IG1 mapping |

Full build steps, including what went wrong: [`docs/build.md`](docs/build.md)

## Ethics and legality

This project only ever received traffic sent to its own machine. It never scanned, probed, replied to, or executed anything.

- [`docs/rules-of-engagement.md`](docs/rules-of-engagement.md) — agreed before deployment, not after
- No raw source addresses are published. Counts are aggregated by country and network operator. Most of those addresses belong to compromised machines rather than to attackers, and a public list would be a liability with no analytical value.
- Nothing Cowrie captured as a file is in this repository.

## Repository

```
docs/          build notes, rules of engagement, analysis
pipeline/      ingest.py and the database schema
dashboard/     the six views
data/          aggregated extracts only
```

## What I would do differently

`[TBC — two or three honest sentences, written after demo day]`

## Licence

MIT for the code.
