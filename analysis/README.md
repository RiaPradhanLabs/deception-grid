# analysis/

Eight files. This is what each one is for, what order to run them in, and the
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
| 3 | `weekly.sql` | sensor | The 17 standing questions. Never retype a query — add it here. |
| 4 | `figures.sh` | sensor | Refreshes the database, runs every query, prints an as-of line and the figure map. **Use this, not the queries directly, whenever a number is going into a document.** |
| 5 | `geo-lookup.sh` | sensor | Fills `geo.sqlite` for query 17. Optional; queries 1–16 work without it. |
| 6 | `features-files.py` | **sensor only** | Static features of the captured files → one CSV. |
| 7 | `features-tty.py` | **laptop** | Keystroke timing from the TTY recordings → one CSV. |
| 8 | `exclude-ips.txt.example` | — | The format for `exclude-ips.txt`, which is never committed. |

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
  an older number: the exclusion rule was rewritten five times, so the old
  figures cannot be arithmetically updated.
- **Query 12** — login rows that contain an escape sequence and still count. It
  points the opposite way from query 3 on purpose. Query 3 shows what the rule
  threw out; query 12 shows what it let through.
- **Query 13** — the file taxonomy. Cowrie logs three different things under the
  single event id `cowrie.session.file_download`, and conflating them produced
  five wrong figures in one morning. The discriminator is whether the event
  carries a `url` field. Never count files in the downloads directory as a proxy
  for any of the three.

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

Runs on the **laptop**, against an extracted backup tarball — the recordings are
under `home/cowrie/cowrie/var/lib/cowrie/tty/` inside it.

```
python3 features-tty.py --dir <tty dir> --verify      # do this FIRST
python3 features-tty.py --dir <tty dir> --out tty-features.csv
```

Cowrie's TTY log format is undocumented and is not guaranteed for this build
(`3.0.16.dev4+g9dc1ea8f3`). The parser therefore validates every record and
**fails loudly** rather than half-reading a file. `--verify` prints one
recording's parse and says to cross-check it against Cowrie's own player:

```
/home/cowrie/cowrie/bin/playlog -f <that same file>
```

If the byte counts and the time span do not line up, the parser is wrong for this
build and the features mean nothing. That is a normal thing to discover. A parser
that quietly produced plausible-looking numbers would be the bad outcome.

The weak labels it assigns — `scripted`, `typed`, `unlabelled` — are a guess from
thresholds, and the thresholds are printed in the script's docstring. The
`unlabelled` rows are the finding, not a residue to be tidied away.

---

## Not in this repository

- `exclude-ips.txt` — a record of one person's home addresses over time. Mode
  600, never committed. `exclude-ips.txt.example` documents the format.
- `decoy.sqlite`, `geo.sqlite` — rebuilt by `ingest.py` and `geo-lookup.sh`.
- Any strings file from `features-files.py --strings` — extracted strings can
  contain attacker URLs and addresses.
- Anything in `var/lib/cowrie/downloads/`. Much of it is live malware.
