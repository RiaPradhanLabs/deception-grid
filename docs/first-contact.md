# First contact — 25 September 2026

The decoys became reachable from the internet at **08:01:20 UTC**. This note
records the first forty minutes, because the first day produced results the
remaining eleven weeks will be measured against.

## Summary

| | |
|---|---|
| Firewall opened | 08:01:20 UTC |
| First uninvited connection | 08:02:03 UTC — **43 seconds** |
| First successful login | 08:10:04 UTC — **8 min 44 s** |
| Credential guessed | `root` / `root` |
| Protocol | Telnet (port 23) in every case |
| Distinct sources in 40 minutes | 6 |
| SSH (port 22) arrivals | 0 |

## Timeline

```
08:02:03  165.22.18.23    connect, telnet
08:02:35  165.22.18.23    root / anko                    refused
08:03:02  165.22.18.23    enable\x00 / linuxshell\x00    refused
08:03:36  165.22.18.23    system\x00 / shell\x00         refused
08:04:53  165.22.18.23    admin / smcadmin               refused
08:07:45  42.180.13.250   connect — then 20 more, ~13s apart, no credentials
08:10:04  62.108.202.22   admin / admin                  refused
08:10:04  62.108.202.22   root / root                    ACCEPTED
08:15:40  92.53.214.135   root / root                    ACCEPTED
```

The refused credentials are not server credentials. `root/anko` is a DVR
default and `admin/smcadmin` an SMC router default. **Four of the six pairs
seen on day one — `root/anko`, `admin/smcadmin`, `root/root` and
`admin/admin` — appear verbatim in the published Mirai credential table**,
checked against [SecLists][seclists] on 25 September.

The other two do not, and probably are not credentials at all.
`enable\x00 / linuxshell\x00` and `system\x00 / shell\x00` are absent from
that table — but `enable`, `system` and `shell` are the same words the
successful session sent as *commands* after logging in. The likely
explanation is that Cowrie's telnet handler read a command stream as login
input on sessions that never authenticated, and recorded it as a
username/password pair.

That matters for counting. If it is right, a share of what the log calls
*login attempts* are not attempts, and treating them as brute force would
overstate the credential-guessing volume — which is the headline figure of
the IT-door story.

**Checked on 29 September: it is right, and larger than it looked from one
day.** Over four days, 4,722 of 38,247 recorded attempts — one in eight — are
console words or non-printable bytes rather than credentials, and
`analysis/ingest.py` excludes them under the reason `artefact-command`. The
convention and the excluded pairs are printed in every run's output, so it can
be argued with rather than taken on trust.

The rule took two attempts. The first tested for a real NUL byte and matched
nothing, because Cowrie writes the escape as literal text. The second matched
any such escape and threw out real credentials that arrive with a trailing
null — `root/7ujMko0admin`, a known camera default, among them. The distinction
is semantic: `enable` and `blender` are identical in shape, so only a list of
console words separates a command from a password.

[seclists]: https://github.com/danielmiessler/SecLists/blob/master/Passwords/Malware/mirai-botnet.txt

## What the successful session did

Session `c62d723028d2`, from `62.108.202.22`, lasted **893 milliseconds**.
The first four commands land three thousandths of a second apart. Not a person.

| Sent | Purpose |
|---|---|
| `sh` → `shell` → `enable` → `system` | Console-escalation ladder for embedded devices. On a real router or camera one of the four opens a shell. It tries all of them because it does not know what it has reached |
| `ping; sh` | Command-injection probe. If the device runs `ping` *and then* `sh`, its input handling is broken in a useful way |
| `/bin/busybox HISILICON` | Liveness check, and the clearest signature in the session. HiSilicon makes the chipset in most cheap IP cameras and DVRs. There is no `HISILICON` applet — the bot wants busybox's exact *applet not found* error, which proves busybox is real and the device genuine. It also serves as a marker separating stages |
| `/bin/busybox cat /proc/self/exe` | Reading its own binary to determine the CPU architecture, so it knows which build of the payload to fetch — MIPS, ARM or x86 |
| `>/var/.f && chmod 777 /var/.f && /var/.f && cd /var/;` and eleven variants | Hunting for one writable directory across `/var`, `/var/tmp`, `/var/run`, `/dev`, `/dev/shm`, `/data`, `/etc`, `/mnt`, `/usr`, `/boot`, `/home` and `/root`. Create a file, make it executable, try to run it. The first that works is where the payload lands |

## Two hosts, one script

At 08:15:40 a different address, `92.53.214.135`, ran the same sequence.
Cowrie hashes every terminal recording, and both hosts produced the same two
hashes:

```
52e9b844cab6d6b643be95b12df186d807af346df86502511b741a…
d4c6234f92f0927070bd79f204505347896699a0825457681216dd…
```

Byte-identical, five minutes apart, from unrelated addresses. This is the
clearest available evidence that the traffic is commodity automation rather
than anything directed at this machine — and it can be stated as a hash
rather than as an adjective.

## A third behaviour, distinct from both

`42.180.13.250` produced more than twenty connections roughly thirteen seconds
apart and **never attempted a credential**. Connection without credential
attempt is behaviourally different from brute force and should be counted
separately: it is consistent with port enumeration, or with a bot whose later
stages fail. Whatever it is, folding it into "login attempts" would overstate
brute-force volume.

## What it did — corrected twice on 29 September

This section has been wrong twice, and both versions are recorded because the
sequence is instructive.

**Version one** said no payload was delivered, and proposed that the imitation
had failed the `HISILICON` liveness check. **Version two** accepted that the
liveness check had passed but still reported zero payloads, from a command list
truncated at the fifteen most frequent. **Version three, below, is checked
against the download events and the files on disk.** Payloads were delivered:
81 network fetches across 33 sessions, 33 distinct files, from 8 hosts.

Corrected against four days of data.

Cowrie records whether each command was accepted or rejected:

| Command | Times | Rejected |
|---|---|---|
| `enable` | 1,473 | **1,473** |
| `shell` | 1,448 | **1,448** |
| `system` | 1,440 | **1,440** |
| `sh` | 1,443 | 0 |
| `/bin/busybox HISILICON` | 1,471 | 0 |
| `ping; sh` | 984 | 0 |
| `>/var/.f && chmod 777 /var/.f && …` | 488 | 0 |

Only the three router-specific escalation words failed, because they are not
commands in Cowrie's emulated shell. Everything else was accepted. **The
liveness check passed 1,471 times.** The bot learned the CPU architecture and
was given a writable directory.

### How many got how far

| Stage reached | Sessions |
|---|---|
| Logged in and ran something | 1,473 |
| Probed for command injection (`ping; sh`) | 984 |
| Read its own binary for the CPU architecture | 493 |
| Hunted for a writable directory | 488 |
| **Fetched a payload over the network** | **33** |
| Pushed a file to it over SCP instead | 14 |

Stage counts, not a strict funnel: different bot families take different routes,
so the 33 are not all a subset of the 488. Read each row as "reached this
stage", never "of those above".

The writable-directory row and the SCP row are different things and are counted
separately on purpose. A first version of this table had a single row reading
"had a file pushed to it instead — 112", which merged SCP pushes with the 104
sessions that merely wrote a test file during the directory hunt. Those were
already counted on the row above, so the table double-counted them and
overstated delivery eightfold.

Roughly **one session in forty-five went the whole way**. The download events break
down as **81 successful fetches across 33 sessions** and 72 failures across 15
more, from **8 distinct hosts**, producing 33 distinct files stored under their
SHA-256 in `var/lib/cowrie/downloads/`.

**Fetching was more than twice as common as pushing: 33 sessions against 14.**
An earlier version of this paragraph claimed the opposite — "112 sessions pushed
a file against 33 that fetched one" — by lumping SCP pushes together with shell
redirections. That is the same conflation this whole section is about, committed
again inside it. The three kinds separate cleanly:

| Mechanism | Events | Sessions | Distinct files |
|---|---|---|---|
| Fetched over the network (`url` present) | 81 | 33 | 33 |
| Pushed over SCP (`file_upload`) | 79 | **14** | 24 |
| Shell redirection captured (`file_download`, no `url`) | 184 | 104 | **8** |

The third row is not payload delivery at all. It is the writable-directory probe:
`>/var/.f` creates a file, Cowrie stores its content, and 184 events yield only
eight distinct files because it is the same tiny file over and over. Counting it
as delivery inflated the sessions figure eightfold.

**Distinct captured content is 65 hashes** — not the 104 first reported, and not
the 106 files on disk either: redirection captures are named `redir_<uuid>`
rather than by hash, so the directory holds more files than there is distinct
content in it.

The commands behind the downloads are worth reading in the log: they are
architecture ladders. One script tries `net.x86_64`, `net.mips`, `net.mpsl`,
`net.arm`, `net.arm5`, `net.arm6`, `net.arm7`, `net.ppc`, `net.m68k`, `net.sh4`,
`net.spc`, `net.arc`, `net.i686`, `net.i486` in turn, each with `wget` and then
`curl` as a fallback. The bot does not know what it has reached and does not
care; it tries every build until one runs.

### The thing this cost us

Cowrie does not fake `wget`. It really fetched those files, which means the
sensor opened **153 outbound connections to 8 attacker-controlled hosts** between
25 and 29 September. `docs/rules-of-engagement.md` said the project only ever
receives and never connects back to an address in its own logs. Both statements
were false for four days.

This was found by checking the claim that no payload had been delivered. The
download behaviour was turned off the same day, at the firewall rather than in
configuration, and the whole episode is documented in
`docs/rules-of-engagement.md` under *The outbound download problem*.

So the answer to "what do they install" covers 25 to 29 September and stops
there. The URLs continue to be logged; the binaries do not continue to arrive.
That is a deliberate trade and the reasoning is written down.

## What this changes for the analysis

The telnet door is not attracting people looking for a Linux server. It is
attracting automated hunting for **embedded devices** — the same category of
equipment as the industrial controllers behind the OT door. The project was
designed around an IT/OT split; there may be a third category sitting between
the two, and it was visible in the first four minutes.

## Caveats

- **Loopback is in the log.** Local testing produced `127.0.0.1` sessions on
  25 September. These are excluded at ingest, and the exclusion is stated
  rather than done silently.
- **`dst_ip` is `172.16.0.4`**, the machine's private address, because Azure
  translates. Identify the sensor by the `sensor` field, never by destination.
- **Credentials can contain null bytes** (`enable\x00`). They arrive as
  `\u0000` in the JSON and must reach the database unmangled. The raw line is
  retained so a parsing decision can be revisited.
- **The command list was read truncated once, and it cost a finding.** A query
  returning the fifteen most frequent commands showed no download command, and
  that absence was reported as "no payload delivered". The download commands were
  there, spread thinly across a dozen variants, none of them frequent enough to
  reach a top-fifteen list. **An absence in a truncated result is not an
  absence.** Check `LIMIT` before reporting a zero.
- **Credential attribution: checked on 25 September.** Four of the six pairs
  are verbatim entries in the published Mirai credential table; two are not,
  and are more likely a parsing artefact — see above. The `HISILICON` and
  `/proc/self/exe` behaviour is still read as Mirai-family from the
  [published scanner source](https://github.com/jgamblin/Mirai-Source-Code/blob/master/mirai/bot/scanner.c)
  rather than confirmed line by line, so treat the family label itself as
  probable rather than established.
- **Technique mapping: checked on 25 September.** See the table below.

## Technique mapping

Checked against the ATT&CK matrix on 25 September. Checking changed it in two
places, which is the argument for doing it rather than asserting it.

| Technique | Where it appears | Status |
|---|---|---|
| **T1110.001** Password Guessing | The refused credential attempts | Verified. Not credential stuffing, which means breached username/password pairs, and not spraying, which means one password across many accounts |
| **T1078.001** Valid Accounts: Default Accounts | `root/root` succeeding | Verified, and missing from the first draft. ATT&CK covers factory-set credentials on devices left unchanged after installation |
| **T1082** System Information Discovery | `cat /proc/self/exe` | Verified as explicitly covering processor architecture |
| **T1105** Ingress Tool Transfer | 81 completed network fetches in 33 sessions, 33 distinct files, 8 hosts. Separately 79 SCP pushes in 14 sessions | Verified, and **observed completing** — corrected 29 September, having first been recorded as attempted but never completing. The SCP pushes are arguably T1105 too and arguably lateral tooling; not resolved |
| **T1497** Virtualization/Sandbox Evasion | `/bin/busybox HISILICON` | Probable, page not read in full. The check exists to confirm a real device rather than an analysis environment |
| **T1059.004** Unix Shell | `sh` / `shell` / `enable` / `system` | Sub-technique unverified; the parent T1059 is not in doubt |
| **T1083** File and Directory Discovery | The writable-directory hunt | Unverified. Defensible, but no ATT&CK technique cleanly describes *testing whether a directory is writable* |

**T1078.001 is the one that matters.** It was absent from the first draft and
it is the most actionable technique here: the break-in was not an exploit, it
was a default password nobody changed. That is a recommendation a
forty-person factory can act on this week, and it is now evidenced by a
specific event at a specific second.

**T1497 no longer reads as evidence against the instrument — corrected 29
September.** The first version of this note argued that if the bot ran a
liveness check and then left without delivering a payload, the imitation had
probably failed the check. Four days of command data say otherwise:
`/bin/busybox HISILICON` was accepted 1,471 times. If it is a sandbox or
liveness check, the decoy passed it. The technique mapping stands; the
inference drawn from it does not.

## The telnet skew was not real — corrected 28 and 29 September

Forty minutes, six sources, zero arrivals on port 22. Port 22 was tested from
an external address the same morning and answered correctly, so the skew was
not a fault in the instrument, and it was written up here as a finding.

**It was not a finding. It was forty minutes of data.** Over the first four
days the picture reverses: about 3.4 connections on port 22 for every one on
port 23 — 28,158 against 8,293, as of 29 September 11:23 UTC. See
`first-weekend.md`.

A first version of this correction, written on 28 September, said "roughly four
to one". It was itself derived from one log file rather than five, because
Cowrie rotates the log daily and only the current-day file was being read. The
direction of that correction was right; its size was never measured. Both
versions are left in.

The lesson holds twice over: an hour of anything looks like a pattern, and a
figure is only as wide as the data you actually opened. Nothing else in this
note depends on either claim — the forty-minute timeline above came from the
current-day file, read on the day, which is exactly what it says it is.

The port-22 test session appears in the log from the analyst's own address and
is excluded at ingest as `analyst`, alongside loopback.
