# First hours at the OT door — 6–7 October 2026

The second decoy, Conpot speaking Modbus on port 502, became reachable from the
internet at **17:42:02 UTC on 6 October 2026** (`docs/build.md`, *Order of
opening*). This note records its first fourteen hours, for the same reason
`first-contact.md` records the IT door's first forty minutes: the first stretch
is the one the rest of the collection is measured against, and the comparison
between the two doors is the question this project exists to answer.

Every figure is as at **08:16 UTC on 7 October** unless a paragraph says
otherwise, from `ingest.py` and queries 14–16 of `weekly.sql`, with the
analyst's own test connections excluded by the date-scoped window. No source
address appears here, by the rules of engagement; sources are counted, not
named.

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

**Measured later the same morning (7 October, 09:30 UTC; queries 18 and 19,
added in commit `8bcda64`).** Of the eleven OT sources, **two had already
visited the IT door**, 4.1 and 8.8 days earlier; nine had not. Ten sources
connected once; one connected four times. So on the first data point the
visitors to the factory door are mostly not the visitors to the office door,
and the two that were both took days, not minutes, between the doors — the
pattern of a scanner working through ports over time, not one sweeping both at
once. Two of eleven supports no stronger sentence than that; the queries now
run at every check-in, and this paragraph is the baseline later runs are read
against.

**Measured again on 9 October, 07:59 UTC — the first re-run against the
baseline above.** 41 sources, 87 connections, 29 Modbus requests from 27
sources: code 43 ×27 (25 sources) and code 17 ×2 (2 sources). Still no read
(codes 1–4) and still no write (5, 6, 15, 16). A thirtieth record carries
function code 0 and is not Modbus: its fourteen bytes have protocol identifier
`0001` where Modbus/TCP requires `0000`, and the decoy answered nothing — a
fixed probe thrown at port 502, labelled *other / unhandled* by query 15 and
left out of the request count here. Arrivals ran 30, 28 and 28 a day on 7, 8
and 9 October (the last to 07:59), from 15, 15 and 12 sources a day — steady,
not climbing.

Query 18: **8 of the 41 (19.5 %) had already been to the IT door**, against 2 of
11 on the first morning. The shortest gap between a source's two doors is now
under about seventy minutes (`0.0` days at one decimal) where the first morning's
shortest was 4.1 days; the longest is 13.4 days. So the "days, not minutes"
sentence above held for the first eleven and not for the next thirty: at least
one visitor is sweeping both doors in one pass. Query 19: **14 of 41 returned**
— six came twice, one three times, three four times, one six, two seven and one
thirteen — against 1 of 11 on the first morning. Twenty-seven came once. The
2-of-11 paragraph stands as the baseline it said it was; this is the second
point, and the figure-freeze on 9 December takes the third.

## Next look

The recurring check-in reads the OT section of `decoy-status` on Mondays and
Thursdays. The figure-freeze on 9 December takes the final numbers for both
doors from queries 14–16, 18 and 19 and states both opening dates beside
them.
