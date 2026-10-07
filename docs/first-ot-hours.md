# First hours at the OT door — 6–7 October 2026

The second decoy, Conpot speaking Modbus on port 502, became reachable from the
internet at **17:42:02 UTC on 6 October 2026** (`docs/build.md`, *Order of
opening*). This note records its first fourteen hours, for the same reason
`first-contact.md` records the IT door's first forty minutes: the first stretch
is the one the rest of the collection is measured against, and the comparison
between the two doors is the question this project exists to answer.

Every figure is as at **08:16 UTC on 7 October**, from `ingest.py` and queries
14–16 of `weekly.sql`, with the analyst's own test connections excluded by the
date-scoped window. No source address appears here, by the rules of engagement;
sources are counted, not named.

## Summary

| | IT door (22/23) | OT door (502) |
|---|---|---|
| Opened | 25 Sep 08:01:20 UTC | 6 Oct 17:42:02 UTC |
| First uninvited connection | 08:02:03 — **43 seconds** | 20:14 — **2 h 32 min** |
| Distinct sources in the first 14 h | *not measured at the time* | **11** |
| Distinct sources, whole collection | 2,635 | 11 |
| Spoke the protocol | — | 6 of the 11 |
| Asked what the device is (code 43 or 17) | — | 6 of 6 |
| Read a register (codes 1–4) | — | 0 |
| Tried to write (codes 5, 6, 15, 16) | — | **0** |

## What happened

Nobody came for the first 91 minutes. The opening session closed at 17:51 UTC
with `sources 1 external` — the analyst's own probe — and a look at 19:13 UTC
showed the same. The first stranger connected at **20:14 UTC**, two and a half
hours after the door opened. Against the IT door's 43 seconds that gap is itself
a finding: scanners that sweep for SSH and telnet sweep continuously; the ones
that look for Modbus come round on a longer cycle.

By 08:16 UTC on 7 October, eleven distinct sources had connected. Five
connected and closed without sending a Modbus request. Six sent exactly one
request each:

```
function code  meaning                      requests  sources
43             read device identification   5         5
17             report server id             1         1
```

Both are the same question — *what are you?* — in two generations of the
protocol. Code 43 asks for vendor, product and version; code 17 is the older
serial-line form of the same request. Nothing read a holding register, nothing
read a coil, and nothing attempted a write. The first fourteen hours at the OT
door were identification and nothing else.

That is consistent with what port 502 scanning is known to be: internet-wide
inventories fingerprinting whatever answers, cataloguing it, and moving on. It
is not consistent, so far, with anyone trying to operate the plant the decoy
pretends to be. Whether that changes over the next nine weeks — whether a
catalogued "controller" is later visited by something that reads or writes — is
the thing to watch, and query 15 is where it will show.

## How to read the comparison

- **The doors are not the same age.** The IT door has run eleven days longer.
  Figures are compared per unit of time or stated with both opening dates, never
  as raw totals side by side without the dates.
- **Distinct sources, not events.** 34 events on port 502 against 536,049 on 22
  and 23 says nothing a reader can use; 11 sources against 2,635 does.
- **The analyst's own records are excluded**, not deleted: five Conpot records
  from the opening evening carry the analyst's address and sit in the database
  with `excluded = analyst`, inside the window `analyst-addresses.log` gives
  them. `ingest.py` reports `window checks 5 inside` on every run, and will
  until the next time the analyst connects to a decoy port.
- **Code 17 was labelled "other / unhandled"** by query 15 until this note was
  written; it is a defined code, Report Server ID, and the label was corrected
  in the same commit. The count was right throughout.

## What was not seen

No write attempt and no register read. Fourteen connections from eleven sources
means three were return visits, which the per-source query has not yet been
written to show. Whether any of the eleven had already visited the IT door is
a claim that needs its own query and has not been run; it is listed here so it
is not quoted before it is measured.

## Next look

The recurring check-in reads the OT section of `decoy-status` on Mondays and
Thursdays. The figure-freeze on 9 December takes the final numbers for both
doors from queries 14–16 and states both opening dates beside them.
