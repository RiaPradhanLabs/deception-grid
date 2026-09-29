# The first four days — 25 to 29 September 2026

**This note replaces an earlier version that was wrong about its own scope.**
The earlier version was titled "the first weekend" and reported 14,845 events
from 93 sources. Those figures came from reading a single file, `cowrie.json`,
in the belief that it held everything. It does not: Cowrie rotates the log
daily, so that file held one partial day out of five. Four days of data are
roughly fourteen times larger. Details in the corrections section below. Every
number here comes from the database built by `analysis/ingest.py`, **as of the
run at 29 September 11:23 UTC**. The dataset grows by roughly 47,000 events and
230 new sources a day, so these figures are a dated snapshot and are meant to be
refreshed once, deliberately, before the demo — not chased daily.

This note is written in plain words on purpose: the point of the project is to
say something useful to people who do not work in security.

## The numbers

| | |
|---|---|
| Period covered | 25 Sept 08:02 UTC to 29 Sept 11:23 UTC — **4 days, 3 hours** |
| Events recorded | 201,349 |
| Events that count | 196,591 (see exclusions) |
| **Different places they came from** | **967** |
| Connections | 36,451 — 28,158 on port 22, 8,293 on port 23 |
| Password attempts | 33,525 real, after removing 4,722 mis-recorded ones |
| Times somebody guessed right | **1,775, from 276 different places** |
| Log lines that would not parse | 0 |

Roughly **47,000 events and 230 new visitors a day**, at a machine nobody was
told about, that hosts nothing, and that nobody has any reason to want.

**276 of the 967 sources got in.** Not 276 break-ins into anything that
mattered — there was nothing behind the door — but 276 separate places on the
internet that guessed a working password on a machine they knew nothing about.

**One honest caveat about that figure, which has to be stated before anyone
quotes it.** Our decoy accepts exactly five passwords for the user `root`:
`root`, `admin`, `123456`, `1234` and `password`. So the 1,775 successes measure
*our configuration*, not attacker skill — a different list would give a different
number, and the five successful pairs are exactly the five we chose to accept.

The defensible claim is the one that does not depend on our choices: **276 of 967
sources tried at least one of five specific passwords that appear on published
lists, and 172 of them tried `root/root`.** That is a fact about the attackers.
"1,775 break-ins" is a fact about us.

## Events, connections, and why the difference matters

An **event** is one line in the log. A **connection** is one visitor arriving.
A single connection produces many events: the arrival, the client's version
string, the key exchange, each password tried, each command typed, the close.

The earlier note said "arrivals on the office door: 11,942". That was an event
count wearing the word *arrivals*, and it overstated what it claimed to measure
by about five times. Stated properly:

| | port 22 | port 23 |
|---|---|---|
| **Connections — arrivals** | **28,158** | **8,293** |
| Distinct sources | 533 | 547 |

So about **three and a half arrivals on the modern door for every one on the
old-fashioned door**, against the four to one the earlier note claimed.

**But look at the second row, because it is the more interesting one.** Nearly
the same number of separate places knocked on each door — 533 and 547 — and 1,080
is more than our 967 total, so some knocked on both. The port 22 door gets three
and a half times the arrivals from *no more visitors*. The difference is not how
many people are looking; it is how hard each one knocks. An SSH scanner comes
back dozens of times; a telnet scanner tries once or twice and moves on.

That is a statement about behaviour rather than volume, and it is the kind of
thing only a decoy can tell you. A firewall log would show the arrivals and not
the difference.

Connections are the figure to quote, not events. An event count per port is not
comparable across the two doors: a telnet session produces a different number of
log lines from an SSH one, and the mis-recorded credentials removed above were
almost all on telnet, so excluding them lowers the telnet event count without
any visitor having gone away. Arrivals are arrivals either way.

## Three corrections, kept in rather than edited away

### 1. The log rotates. We were reading one file of five

The largest of the three, and the cause of the other numbers being wrong.
`cowrie.json` holds the current day; `cowrie.json.2026-09-25` and its siblings
hold the days before. Every figure published between 25 and 28 September came
from the current-day file alone.

Nothing was lost — the twice-weekly backup tarballs the whole log directory, so
every rotated file had been on the analyst's laptop the entire time. The data
was always there. We were not reading it.

`ingest.py` now reads `cowrie.json*` and prints the list of files it read at
the top of every run, so this cannot happen quietly again.

### 2. Day one's telnet skew was not a finding

On 25 September every arrival came in on port 23 and none on port 22, and that
was written up as a finding. It was forty minutes of data. Over four days the
picture is the other way round. An hour of anything looks like a pattern.

### 3. One in eight "password attempts" is not a password attempt

The two commonest entries in the whole dataset are not credentials:

```
enable\x00 / linuxshell\x00    2,249
system\x00 / shell\x00         2,016
```

Those are words attackers type *after* getting in, on devices like routers, to
reach a command prompt. Cowrie's telnet handling reads that stream of commands
as if it were somebody typing a username and password. Also in this group:
`enable/system`, `shell/sh`, `sh` with `/bin/busybox UNSTABLE`, and a long tail
of rows whose fields are entirely non-printable bytes.

Together they are **4,722 of 38,247 recorded attempts — 12%**. Left in, they
would inflate the headline and would sit at the top of any most-tried-passwords
table, which is where a reader's eye goes first.

They are excluded, and the exclusion is stated rather than done quietly. The
rule took two attempts to get right, and both failures are worth recording.

The first version tested for a real NUL byte and matched **nothing at all**,
because Cowrie writes the escape as literal text — the four characters `\`, `x`,
`0`, `0`. Caught by the tool printing what it had excluded and the answer coming
back `none`.

The second version matched any such escape, and over-corrected: it threw out
`root/7ujMko0admin`, `root/founder88`, `root/blender` and
`telnetadmin/telnetadmin`, which are real credential attempts that happen to
arrive with a trailing null byte. `7ujMko0admin` is a well-known camera default.
The lesson is that the distinction is **semantic, not syntactic** — `enable` and
`blender` are the same shape to a pattern, and only a list of console words can
separate them. Caught by reading the excluded rows rather than trusting the
total.

## Three different kinds of visitor

This is the part worth explaining to a general audience, because "we were
attacked two hundred thousand times" tells them nothing and this tells them
something.

### 1. The door-rattlers

The overwhelming majority. Automated programs working through a list of
factory-default passwords, a few seconds apart, never pausing to look at what
they have reached. The passwords they try are not clever:

| Username | Password | Attempts | Where it comes from |
|---|---|---|---|
| root | root | 1,180 | The oldest default there is |
| admin | admin | 710 | Home routers, by the thousand |
| root | xc3511 | 273 | A particular make of cheap security camera |
| root | admin | 255 | Digital video recorders |
| root | vizxv | 226 | Dahua cameras, shipped this way |
| root | 123456 | 163 | Not a device default — just a bad password |
| root | 888888 | 140 | More recorders, another factory setting |
| support | support | 132 | Service accounts nobody renamed |

These are not guesses at *our* password. They are a list of what other people's
equipment came with from the factory, tried on everything that answers.

### 2. The ones that knock and leave

Connections that never attempt a credential at all. On day one, one address
connected more than twenty times, thirteen seconds apart, and never tried a
password once. Not breaking in — taking an inventory. Somebody, somewhere, now
has our address on a list of machines that answer.

Worth counting separately. Folding it into "login attempts" would overstate how
much of this traffic is an attempted break-in.

### 3. The ones that wanted a lift

**Three sources, over three days, doing two different things.** An earlier
version of this note described one visitor at 02:40 on the Monday. That was the
last of the three, and the least interesting.

Two of them asked our machine to fetch a website that reports the caller's own
IP address:

| Source | Asked us to fetch | When | Requests |
|---|---|---|---|
| `171.243.149.238` | `ip-who.com` | 26 Sept 13:29 → 28 Sept 02:44 | 11 |
| `94.154.43.234` | `ipv4.icanhazip.com` | 26 Sept 20:36 | 1 |

That is **casing the joint**. They were not interested in our machine or
anything on it. They wanted to know what the rest of the internet would see if
they routed their own traffic *through* us — because a borrowed address that
belongs to somebody else is worth money, and the first thing you check is whose
address you would be borrowing. Two unrelated sources using two different
"what's my IP" services is the same move twice, which is what makes it a
pattern rather than a curiosity.

The third did something else entirely:

| Source | Asked us to connect to | When | Requests |
|---|---|---|---|
| `193.46.255.86` | `62.210.131.144` port 2535 | 28 Sept 08:00 → 10:46 | 2 |

That is not a question about itself. It is an attempt to open a connection to
one specific machine somewhere else, through ours. **Both halves of the abuse
are in the data: the reconnaissance and then the thing it is reconnaissance
for.** Whether the three are related is unknown and should not be claimed.

Our decoy refused all of them. It logged each request and threw it away:

```
direct-tcp connection request to ip-who.com:80
GET /json/
discarded
```

This matters beyond being a good story. The project's one hard rule is that the
machine **only ever receives — it never sends anything to anyone**. That was a
design promise in a document. Three separate people tried fourteen times over
three days to make it send, and it refused every time. The promise is now a
tested one.

There is a symmetry here worth noticing. Three days earlier we found our own
honeypot software quietly looking up its public address on startup, and put it
on the list to switch off because it broke the same rule. Same request, same
reason — *what does the world see me as?* One of us was being careful and one
was casing the joint, and the two requests are identical.

Likely technique mapping: **T1090** Proxy and **T1016.001** Internet Connection
Discovery, neither yet verified against the ATT&CK pages. Cowrie also recorded a
**JA4H fingerprint** for each forwarded HTTP request, which is a
client-identification artefact worth a line in the analysis.

## Where it came from, and why that says less than it looks

The fifty most persistent sources were looked up in the regional internet
registries — the `country:` field, which states who was *allocated* the address
block. Those fifty account for **29,692 of 36,451 arrivals, 81%**.

| Registered in | Arrivals | Sources | Share of all arrivals |
|---|---|---|---|
| United States | 15,205 | 18 | 42% |
| France | 9,549 | 17 | 26% |
| St Kitts & Nevis | 2,485 | **1** | 7% |
| Russia | 603 | 2 | 2% |
| Andorra | 402 | 2 | 1% |
| India | 344 | 2 | 1% |
| Netherlands | 342 | 3 | 1% |
| Vietnam | 290 | 1 | 1% |
| South Korea, Britain, Iran, unknown | 472 | 4 | 1% |

Percentages are of *all* arrivals and do not sum to 100: the 917 sources never
looked up are the remainder.

**Two thirds of it is registered in the United States and France.** That is not
a finding about Americans and French people. It is a finding about where servers
are cheap to rent. France is the giveaway — 17 of the 50 busiest sources, and
France is not known for a botnet industry; it is known for OVH and Scaleway.
Renting a machine in Kansas or Roubaix costs a few euros a month and can be
driven from anywhere on earth.

So the honest version of this table is: **it says where the traffic arrived
from, and nothing about who sent it.** If somebody asks whether a particular
country is attacking us, the answer is that we cannot tell, and neither can
anyone else from this data alone.

**One line is worth more than the rest of the table.** St Kitts & Nevis is a
single machine — one address, 2,485 arrivals, seven per cent of everything that
knocked in four days. A country-level chart puts a Caribbean island above Russia
on the strength of one rented server, which is the same lesson as "don't quote
the event count", arriving from a different direction.

Method note: this is `whois`, not a geolocation database. The two answer
different questions — a registry says who holds the block, a geolocation
database estimates where the machine sits. The claim being made here is
registration, so the registry is the right source. `analysis/geo-lookup.sh`
reproduces it.

## Two notes on honesty in the numbers

**Don't quote the event count.** A handful of addresses produce a large share of
all events; on the 28th alone, one address produced 27% of that day's traffic.
An event total mostly measures how stubborn the most persistent scanner was.
**Distinct sources** is the honest headline and **connections** is the honest
measure of arrivals.

**Every number in this note is a query, not a recollection.** They come from
`decoy.sqlite`, built by `analysis/ingest.py`, which loads every line including
the ones that do not count, labels each exclusion with a reason, and prints its
own totals. Re-running it cannot double-count. All three corrections above were
found by building that tool, and two of them were found by the tool disagreeing
with what had already been published.

## What this is evidence for

Nothing here was aimed at us. The machine has no name, no website, no users and
nothing worth stealing. It was found within seconds by programs that do not know
or care what it is, and four days later 967 separate places had knocked.

That is the argument for a small manufacturer: **you do not have to be a target
to be attacked.** You only have to be reachable.

And the successful break-ins were not clever. Every one used a password that was
on a published list. The fix costs nothing.
