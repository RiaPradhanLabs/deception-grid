# analysis/

Nine files. This is what each one is for, what order to run them in, and the
traps that are specific to this data.

The one rule that governs all of it:

> **Before quoting a count, look at five of the rows it counts.**

Six of the eight mistakes recorded in `docs/build.md` were found by reading rows.
None were found by reading totals. A wrong total looks exactly like a right one.

---

## Order of use

| Step | File | Where it runs | What it does |
| --- | --- | --- | --- |
| 1 | `ingest.py` | sensor | Reads the decoys' logs into `decoy.sqlite`. Re-derives every column each run. |
| 2 | `schema.sql` | — | Applied by `ingest.py`. Tables and the `v_*` views. Not run by hand. |
| 3 | `weekly.sql` | sensor | The 19 standing questions. Never retype a query — add it here. |
| 4 | `figures.sh` | sensor | Refreshes the database, runs every query, prints an as-of line and the figure map. **Use this, not the queries directly, whenever a number is going into a document.** |
| 5 | `geo-lookup.sh` | sensor | Fills `geo.sqlite` for query 17. Optional; queries 1–16 work without it. |
| 6 | `features-files.py` | **sensor only** | Static features of the captured files → one CSV. |
| 7 | `features-tty.py` | laptop or sensor | Command timeline per TTY recording → one CSV. NOT keystroke timing; see below. |
| 8 | `exclude-ips.txt.example` | — | The format for `exclude-ips.txt`, which is never committed. |
| 9 | `overlap-test.py` | sensor | Read-only premise test for ML options 2 and 5: do sources share credential dictionaries? Prints aggregates only. |

---

## ingest.py

Reads `cowrie.json*` and `conpot.json*` — the glob matters. Cowrie rotates
daily, and reading `cowrie.json` alone was the first and largest mistake in this
project: every figure for a week came from one file of five.

It re-derives **all** derived columns from the stored `raw` JSON on every run,
and prints what moved. This is deliberate. The code is the single authority and
the database is its cache, because fixing a parsing rule and finding that nothing
already stored had changed happened twice before this was built.

Conpot's records need normalising on the way in: `event_type` is **null** on
protocol records, and `request` is a Python bytes *repr* stored as a JSON string.
Both are handled, and both were found by reading values rather than keys.

### Which addresses count as ours

Two files, and they are not interchangeable.

`exclude-ips.txt` is the hand-maintained list of bare addresses. It carries no
dates, so every address in it is excluded **for all time**. Mode 600, never
committed; `exclude-ips.txt.example` documents the format.

`analyst-addresses.log` is written by `allow-me.ps1` on every run, one line of
`<UTC> <address>`, since 5 October 2026. From it, `ingest.py` gives each address
a **window**: ours from its first observation until the first observation of a
different address, with the latest address running open-ended.

The reason is over-exclusion. A residential address rotates, and one excluded
permanently may belong to a real scanner next month — whose traffic would then
be discarded as ours, with nothing in the output to show it had been.

Two things the run output tells you, and both matter:

- **window checks: N inside, N outside, N undated.** If every check is undated,
  the event timestamp is not being read and the windows are doing nothing. The
  first version of this code had exactly that bug — it read `event.get('ts')`,
  but `ts` is only the database column and the event dict carries `timestamp`.
- **MALFORMED n line(s).** An unparsed history is indistinguishable from no
  rotations, so bad lines are counted rather than skipped.

The honest limitation, printed on every run: the history only begins on
5 October 2026. The addresses already in `exclude-ips.txt` stay unbounded,
because nothing recorded when they were held and inventing windows would be
worse than saying so.

Adding a new address to `exclude-ips.txt` still works and is still safe. It is
simply blunter than letting the log do it, and if an address is in both files
the unbounded entry wins — the run output warns when that happens.

## weekly.sql

Read the comments in it. Each one records a mistake that query exists to prevent.
Three to know about before quoting anything:

- **Query 3** — what was excluded and why. State this alongside any figure. At
  figure-freeze time, take the exclusion tally *from here* rather than adjusting
  an older number: the exclusion rule went through six versions, so the old
  figures cannot be arithmetically updated.
- **Query 12** — login rows that contain an escape sequence and still count. It
  points the opposite way from query 3 on purpose. Query 3 shows what the rule
  threw out; query 12 shows what it let through.
- **Query 13** — the file taxonomy. Cowrie logs three different things under the
  single event id `cowrie.session.file_download`, and conflating them produced
  five wrong figures in one morning. The discriminator is **not** simply whether
  the event carries a `url` field — that wrong rule sat in this file's own
  comments until 5 October and made `figures.sh` raise a false alarm on every
  run for a week. Read the four cases in the query itself: a fetch is
  `file_download` with a url *and* a `shasum`/`outfile`; `file_download.failed`
  carries a url and is the block working. Never count files in the downloads
  directory as a proxy for any of the kinds.
- **Queries 14–16, 18 and 19** — the OT door and the comparison. The first
  fourteen hours are written up in `docs/first-ot-hours.md`; the figures there
  are the ones to compare any later run against. Query 18 is the one that tests
  the README's claim that the same sources visit both doors; 19 shows return
  visits as a distribution. Both print aggregates only. They sit before query
  17 in the file because 17 attaches `geo.sqlite` and is kept last.

## figures.sh

Prints an as-of timestamp, every query, the figure that must be zero, and a map
of which document and which slide carries which number. Run it rather than
cherry-picking a query, because the map is what stops a figure being updated in
one place and not another.

## features-files.py

**Runs on the sensor. The captured files never leave the VM.**

```
sudo python3 ~/analysis/features-files.py --out ~/analysis/file-features.csv
```

Standard library only: no TLSH, no ssdeep, no compiler. A 256-bin byte histogram
plus an eight-window entropy profile separates recompiled and repacked variants
well enough to cluster, and installing three C libraries on a honeypot to do
marginally better is the wrong trade.

It does not execute anything, does not open a socket, and submits nothing
anywhere — including no hash to a multi-scanner, because submitting a hash
discloses that this sensor collected that sample.

It labels `redir_<uuid>` files as shell-redirection captures rather than dropping
them, so they can be excluded by a `WHERE` clause and the count stated. Quote
**distinct sha256**, never the file count.

Only the CSV comes back to the laptop. After the machine is deleted that CSV is
the only record of what was captured at byte level, so it has to exist before
teardown or the analysis becomes impossible rather than merely undone.

## features-tty.py

Runs on the **laptop or the sensor** — pure parsing, no access to anything live.
On the laptop, against an extracted backup tarball: the recordings are under
`home/cowrie/cowrie/var/lib/cowrie/tty/` inside it.

```
python3 features-tty.py --dir <tty dir> --verify              # one recording, every chunk
python3 features-tty.py --dir <tty dir> --census              # the dataset's shape
python3 features-tty.py --dir <tty dir> --out tty-timeline.csv
```

**It is not a keystroke-timing tool, and until 5 October 2026 it was written as
one.** That was wrong, and the measurement is a finding worth keeping. Across all
130 recordings:

| | |
| --- | --- |
| Input records from visitors | 593 (67,669 bytes) |
| Mean bytes per input record | 114.1 |
| Records of exactly one character | 5 — `e`, `x`, `i`, `t`, `w` |
| Records containing a backspace | 1 |
| Recordings that are a single pasted command | 62 of 130 |
| Inter-command gaps available | 464 |

A keystroke is one byte. Cowrie writes one record per chunk arriving on the wire,
so a 114-byte record is a whole command line pasted or piped in. The only
characters ever typed one at a time in this dataset spell `exit`. So the
intervals this script reports are gaps between **commands**, and the columns are
named `icg` for that reason. ML spin-off option 3 was withdrawn on this evidence.

The `scripted` / `typed` / `unlabelled` weak label was **removed**. It keyed off a
backspace count and a 5 ms threshold, and would have labelled command pacing
while calling it typing rhythm.

Cowrie's TTY log format is undocumented. The header layout the parser uses was
derived from a hex dump of a real recording, not from the source, after an
assumed layout failed — it is documented at the top of the script. Two fields
were wrong: the order (`length, direction, sec, usec`, not `direction, sec, usec,
length`) and the op constants (open 1, **close 2, write 3**).

It is checked rather than trusted. Every record is validated, a file that does
not parse is reported by name, and a parse failure exits non-zero so a scheduled
run cannot read it as success. All 130 recordings walk to their exact end with
zero trailing bytes and yield exactly one open and one close record — a wrong
layout desynchronises within a handful of records. `--verify` prints every chunk
one visitor sent, in order, with the gap before each, for cross-checking against
Cowrie's own player:

```
/home/cowrie/cowrie/bin/playlog -f <that same file>
```

The tty directory also holds a `.gitignore`. The script skips it **by name and
says so** — earlier passes used `glob`, which silently omits dotfiles, and a
total computed over a quietly filtered set looks exactly like a total.

Rows with no interval at all are kept, not dropped. 62 of 130 recordings are one
pasted command, and that proportion is itself the result.
---

## overlap-test.py

Written and run on 6 October 2026 because the recommended ML sequence — option 2
(credential sets as campaign fingerprints) then option 5 (source–credential
communities), about fifty hours — rested on a premise nobody had measured: that
sources on this sensor *share* credential dictionaries. Read-only; one set of
`(username, password)` pairs per source from `v_logins`; pairwise Jaccard over
every source with at least five distinct pairs; aggregates only, no address or
credential printed.

**Result, as at 6 October 2026, 18:40 UTC** (91,345 login rows, 1,259 sources
that tried a credential, 781 fingerprintable):

| | |
| --- | --- |
| Sources with a near-identical twin (Jaccard ≥ 0.9 to some other source) | 171 of 781 — 22% |
| Sources with a neighbour ≥ 0.3 | 405 — 52% |
| Sources sharing nothing with anyone | 26 — 3% |
| Components at ≥ 0.3 | 104, covering 405 sources |
| Largest component | 41 sources, **0 pairs common to all** — a chain, not a dictionary |
| Genuine shared lists | 18 sources with 893 pairs common to all; 10 with 146; 12 with 75 |

So the premise holds **for a minority**: a few campaigns run large shared lists
inside a majority of small or idiosyncratic scanners, and half the fingerprintable
sources belong to no component at all. Two consequences for options 2 and 5:
cluster with a common-core requirement or a higher threshold, because
single-linkage at 0.3 reports a 41-source chain with no shared credential as the
biggest campaign; and state the denominator — 781 fingerprintable of 2,507
sources, 478 too small to say anything about. The finding is better than the one
planned, because it has a result either way.

Tested before use against a synthetic database with two planted dictionaries
(30 and 20 sources), 40 loners and 50 too-small sources: both dictionaries
recovered exactly, loners untouched, the small ones dropped and counted.

## Not in this repository

- `exclude-ips.txt` — a record of one person's home addresses over time. Mode
  600, never committed. `exclude-ips.txt.example` documents the format.
- `decoy.sqlite`, `geo.sqlite` — rebuilt by `ingest.py` and `geo-lookup.sh`.
- Any strings file from `features-files.py --strings` — extracted strings can
  contain attacker URLs and addresses.
- Anything in `var/lib/cowrie/downloads/`. Much of it is live malware.
