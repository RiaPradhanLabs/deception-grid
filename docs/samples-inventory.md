# What the decoys captured — the sample inventory

**As at 3 November 2026, 06:33 UTC** (the moment `features-files.py` finished
writing `file-features.csv`; the capture directory grows while the sensor runs,
so every figure below carries that time).

The IT decoy's capture directory held **10,346 files** and **164 distinct
contents** — 164 is the number of samples, and the file count is not. The
two differ by a factor of sixty because one telnet loader wrote the same one
byte 9,391 times. This note records what the 164 are, how they arrived, when,
and what the collection looks like at byte level, from the two tools that
exist for the purpose: `analysis/features-files.py` (one CSV row per file,
computed on the sensor; the files never leave it) and `analysis/inventory.py`
(the tables below, from that CSV, the files' modification times and the
database). Nothing was executed, nothing was unpacked, nothing was submitted
to any outside service — not a file and not a hash. The rules of engagement
say why.

## How the files were counted

`features-files.py --verify` first, against `file(1)`: **323 ELF binaries
agreed on class and architecture, 0 disagreed**, 10,023 files were not ELF by
either reading; 323 + 10,023 = 10,346, the `.gitignore` in the directory
skipped by name and said so. Then `--out`, which hashed every file whole
(seven are larger than the 16 MiB read limit for the *feature* columns; their
sha256 is still of the whole file) and wrote 10,346 rows. The CSV came back to
the laptop as 14,381,499 bytes on both machines. The script on the sensor was
HEAD's (`3c10747d…`) before it ran.

## By route

Cowrie names a captured file in one of two ways. A file it fetched for an
attacker (before 29 September, when that was still possible) or that an
attacker pushed over scp is named by its content hash; a file produced by a
shell redirection inside the decoy is named `redir_<uuid>`, one file per
write, however many times the same bytes are written.

| Route | Files | Distinct contents | Bytes on disk | Median file |
| --- | --- | --- | --- | --- |
| Hash-named (fetched before the block, or pushed over scp) | 140 | 140 | 261.4 MiB | 242.2 KiB |
| Shell-redirect captures (`redir_*`) | 10,206 | 26 | 424.3 KiB | 1 B |
| **All** | **10,346** | **164** | 261.8 MiB | 1 B |

Two contents arrived by both routes, and neither is a sample: the one-byte
newline (a hash-named file once, a redirect capture 9,391 times) and the
empty file (once each). No binary did. **151 of the 164 contents were
captured exactly once.** The collection is almost entirely singletons, plus
one loader that never stopped.

Every one of the 140 hash-named files is known to the database by its shasum,
and the database's three groups add up to it: 85 pushed over scp, 33 fetched
before the block, 22 redirect captures that Cowrie also hashed. Nothing on
disk is unknown to the log and nothing in the log is missing from disk.

## What the 164 are

**99 distinct ELF binaries** and **65 distinct non-ELF contents.**

### ELF, by architecture (distinct contents first, files second)

| Architecture | Distinct | Files | Of the files, hash-named / redirect | Stripped | No section table | Truncated | Median size |
| --- | --- | --- | --- | --- | --- | --- | --- |
| x86-64 | 53 | 53 | 52 / 1 | 31 | 26 | 0 | 438.8 KiB |
| ARM | 14 | 14 | 10 / 4 | 11 | 2 | 0 | 130.2 KiB |
| MIPS | 10 | 10 | 6 / 4 | 9 | 0 | 0 | 205.6 KiB |
| SuperH | 7 | **231** | 1 / 230 | 7 | 0 | 0 | 2.5 KiB |
| AArch64 | 3 | 3 | 2 / 1 | 3 | 1 | 0 | 206.0 KiB |
| m68k | 3 | 3 | 3 / 0 | 3 | 0 | 0 | 188.5 KiB |
| PowerPC | 3 | 3 | 3 / 0 | 3 | 0 | 0 | 175.2 KiB |
| x86 | 3 | 3 | 3 / 0 | 3 | 1 | 0 | 130.2 KiB |
| SPARC | 2 | 2 | 1 / 1 | 2 | 0 | 0 | 22.0 KiB |
| RISC-V | 1 | 1 | 1 / 0 | 1 | 1 | 0 | 1.7 MiB |
| **All ELF** | **99** | **323** | 82 / 241 | 73 | 31 | **0** | |

Three things in that table are worth a sentence each.

The **x86-64 majority** that the 5 October run showed (20 of 50) has
strengthened (53 of 99). An IoT-targeting profile predicts ARM and MIPS; what
arrived was mostly built for servers. The seven files above 16 MiB are all
x86-64.

The **SuperH column is one loader, not seven campaigns.** Seven small
binaries (median 2.5 KiB) were written 231 times, 230 of them as redirect
captures: a telnet loader that assembles its payload byte by byte with
`echo -ne`, session after session, and leaves a complete binary behind each
time. Counted as files it is the largest architecture on the sensor; counted
as contents it is seven samples.

**No truncated download remains.** On 5 October a truncated ELF was a normal
find — an infection that failed to complete. Every binary on disk today parses
to its last byte.

31 of the 99 have no section table, and 31 sit in the ≥ 7.5 bits-per-byte
entropy band (whole-file Shannon entropy): consistent with the same 31 being
packed, which was not checked, because checking would mean unpacking.

| Whole-file entropy (bits per byte) | Distinct ELF | Files |
| --- | --- | --- |
| 1.0 – 5.0 | 10 | 12 |
| 5.0 – 6.5 (typical code) | 57 | 279 |
| 6.5 – 7.5 | 1 | 1 |
| ≥ 7.5 (consistent with compression or packing) | 31 | 31 |

### Not ELF, by what `file(1)` called them

| Class | Distinct | Files | Median size |
| --- | --- | --- | --- |
| Text | 16 | 36 | 34 B |
| Shell script | 15 | 561 | 494 B |
| Windows PE32 executable, GUI | 15 | 15 | 240.4 KiB |
| Archive or compressed | 12 | 12 | 2.3 MiB |
| OpenSSH RSA public key | 3 | 3 | 389 B |
| Windows PE32 DLL | 1 | 1 | 893.0 KiB |
| Windows PE32 executable, console | 1 | 1 | 160.0 KiB |
| Empty file | 1 | 2 | 0 B |
| One byte (a newline) | 1 | 9,392 | 1 B |
| **All non-ELF** | **65** | **10,023** | |

Two of these rows say something about who is knocking. **Seventeen Windows
executables** were pushed over scp at a host that announces itself as Linux —
the pushing was not conditioned on what answered. And **three SSH public
keys** arrived as files: the shape of an `authorized_keys` persistence attempt,
dropped into a decoy that will never read them.

### Size

| Size of the content | Distinct | Files | Of which ELF |
| --- | --- | --- | --- |
| 1 byte | 1 | 9,392 | 0 |
| 2 B – 1 KiB | 29 | 595 | 2 |
| 1 KiB – 64 KiB | 24 | 248 | 17 |
| 64 KiB – 1 MiB | 73 | 73 | 53 |
| 1 MiB – 16 MiB | 29 | 29 | 20 |
| 16 MiB and above | 7 | 7 | 7 |

The seven largest (16.2 to 28.9 MiB) are all x86-64 ELF; their feature
columns in the CSV were computed over the first 16 MiB and the `features_bytes`
column says so, row by row.

### The most-copied contents

| Copies | Size | What | Route |
| --- | --- | --- | --- |
| 9,392 | 1 B | a newline | redirect ×9,391, hash-named ×1 |
| 512 | 202 B | shell script | redirect |
| 204 | 1.2 KiB | SuperH ELF | redirect |
| 31 | 139 B | shell script | redirect |
| 11 | 1.2 KiB | SuperH ELF | redirect |
| 11 | 9 B | text | redirect |
| 11 | 9 B | text | redirect |
| 10 | 1.2 KiB | SuperH ELF | redirect |

Everything that was copied more than three times came by redirect. The
hash-named files are 140 files and 140 contents: a file named by its hash is
overwritten by a re-capture of the same bytes, so that route cannot show
repetition and the database has to (below).

## When

From the files' modification times (`stat()` only; the time a capture
finished, as the filesystem recorded it). The first file landed at
**25 September 09:13 UTC, seventy-two minutes after the IT door opened**; the
last at 05:34 UTC today.

| ISO week | Hash-named | Redirect | Files | Contents seen for the first time |
| --- | --- | --- | --- | --- |
| 2026-W39 (21–27 Sep) | 49 | 28 | 77 | 54 |
| 2026-W40 | 34 | 25 | 59 | 34 |
| 2026-W41 | 10 | 336 | 346 | 10 |
| 2026-W42 | 7 | 3,933 | 3,940 | 12 |
| 2026-W43 | 23 | 2,274 | 2,297 | 32 |
| 2026-W44 | 16 | 3,415 | 3,431 | 21 |
| 2026-W45 (to 3 Nov 05:34) | 1 | 195 | 196 | 1 |

Half the contents arrived in the first two weeks. The redirect flood from
W41 — the loader that arrived on 10 October — multiplied the file count
twenty-fold and added almost nothing new; the one later bump in new contents
(32 in W43) is the week the check-ins recorded the IT door's source rate
doubling. For hash-named files the time shown is the *last* capture of that
content, since a re-capture overwrites the file.

## How they arrived — the four kinds of file event, from the database

Cowrie logs four different things under two similar event ids, and the
discriminator is the event id *and* the url together, never the url alone
(`analysis/weekly.sql`, query 13, and the reason it exists). As at the
database refresh of 05:58 UTC today:

| Kind | Events | Sessions | Sources | Distinct shasums | Distinct URLs | First | Last |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Fetch attempted, **blocked** by the outbound rule | 16,436 | 2,469 | 386 | — | 110 | 25 Sep 15:33 | 2 Nov 16:55 |
| Shell redirection captured | 1,645 | 926 | 125 | 22 | — | 25 Sep 09:13 | 2 Nov 16:56 |
| Pushed over scp | 572 | 292 | 80 | 85 | — | 25 Sep 11:15 | 3 Nov 04:44 |
| **Fetched by the decoy** (outbound) | 81 | 33 | 6 | 33 | 24 | 25 Sep 17:14 | **29 Sep 05:55** |

**Fetches after the block went in at 29 September 12:00 UTC: 0.** That is the
figure this inventory exists to confirm. The 81 fetches before it, from six
sources and 24 URLs, produced the 33 fetched files, all 33 still on disk; the
16,436 attempts since were the control working, and the loader kept asking —
9,023 attempts in W41 alone.

The redirect numbers differ between the database and the disk — 1,645 events
and 22 shasums against 10,206 files and 26 contents — because Cowrie does not
log every redirect write as a file event. They are two populations and both are
right; the disk is the inventory, the log is the activity.

Sources and URLs are counts here and everywhere in this repository. The
database holds the values for the analysis that needs them.

## What this inventory is for

`file-features.csv` is on the laptop and is the only byte-level record of the
collection that survives the machine's deletion on 12 December. The 19 November
acquisition session reuses it rather than re-running; the ML spin-off option
that clusters captured files (option 6) runs against it. The figures above are
the inventory for the project report; `analysis/figures.sh` lists this note in
its map so they are refreshed, with a new as-of line, at the 9 December
freeze.

## Caveats that must survive every edit

- **164 is the sample count. 10,346 is not**, and neither is 323 (ELF files)
  or 231 (SuperH files). Say "distinct contents" or "samples", never "files",
  when the question is how many.
- Entropy ≥ 7.5 is *consistent with* packing. Nothing was unpacked.
- Architecture is what the ELF header says and `file(1)` agreed with; it is
  not evidence the binary ran anywhere.
- The hash-named route cannot show repetition; the database's session and
  source counts can, and are stated beside it.
- Fetched means *before 29 September 12:00 UTC*. Every later url is a blocked
  attempt, and `figures.sh`'s must-be-zero line is the check.
