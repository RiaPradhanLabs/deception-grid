# Who gets in — twelve clients, 9 October 2026

Two measurements run on 9 October 2026 for a different purpose — deciding
whether ML option 4 (escalation prediction) was feasible — produced a finding
about the IT door that belongs in the write-up on its own: of the sessions that
reach a successful login, the SSH ones announce **twelve** client programs
between them, and **what a session does after it logs in is almost entirely
decided by which program it is.**

Figures are as at **09:26 UTC** (`analysis/option4-telemetry.sql`) and
**09:39 UTC** (`analysis/option4-clients.sql`) on 9 October, with the analyst's
own records excluded. Clients are named by the version string they announced
and counted; sources are counted, never named.

## Summary

| | SSH (port 22) | telnet (port 23) |
|---|---|---|
| Sessions that reached a successful login | **672** | **3,199** |
| Logins per such session | 1 | 1 |
| Failed a credential before succeeding | 31 (4.6 %) | 4 (0.1 %) |
| Pre-login telemetry per session | client version + key exchange, every session | one option negotiation (none in 177) |
| Went on to run a command or touch a file | 553 (82.3 %) | 2,919 (91.2 %) |
| Went on to a file event (fetch attempt, push, redirection) | 366 (54.5 %) | 278 (8.7 %) |

Across both doors, 3,871 sessions logged in and every one of them logged in
exactly once: 3,871 successes, 3,871 sessions. These visitors arrive with the
credential already in hand — 35 of 3,871 needed a second try.

## The twelve clients

Every SSH client announces a version string before authentication. Among the
672 sessions there are twelve:

```
version string                           sessions  sources  escalated  file event  failed first
SSH-2.0-Go                               508       90       98.6 %     329         0
SSH-2.0-AsyncSSH_2.1.0                   61        15       0.0 %      0           0
SSH-2.0-libssh2_1.11.1                   26        25       50.0 %     0           3
SSH-2.0-libssh_0.9.5                     22        11       50.0 %     11          0
SSH-2.0-paramiko_5.0.0                   16        1        100.0 %    16          0
SSH-2.0-PuTTY_Release_0.84               14        1        0.0 %      0           14
SSH-2.0-libssh_0.9.6                     9         9        100.0 %    9           0
SSH-2.0-OpenSSH_10.5                     9         9        0.0 %      0           9
SSH-2.0-OpenSSH_10.6                     4         4        0.0 %      0           4
SSH-2.0-russh_0.51.1                     1         1        100.0 %    1           1
SSH-2.0-libssh2_1.11.0                   1         1        100.0 %    0           0
SSH-2.0-Renci.SshNet.SshClient.2026.0.0  1         1        100.0 %    0           0
```

Three quarters of everything that gets in over SSH announces `SSH-2.0-Go` —
the default banner of Go's SSH library, which many tools share, so this is a
language's default and not one program. Underneath it the key-exchange
fingerprint (HASSH, an MD5 over the algorithm lists the client offers)
separates **seven** distinct implementations; the largest, 303 sessions, drops
or fetches a file in every single session, and the next, 109 sessions, runs
commands and never touches a file. Eighteen fingerprints in all against twelve
strings.

## What they do, by client

**Escalation is a property of the program, not of the session.** The Go
clients escalate in 98.6 % of sessions; paramiko and libssh 0.9.6 in 100 %,
every one with a file event. AsyncSSH 2.1.0 — 61 sessions from 15 sources —
escalates in **none**. PuTTY and OpenSSH escalate in none either. The two
strings at 50 % are two programs sharing a banner: libssh2 1.11.1 has two
fingerprints and 13 of its 26 sessions escalated, which is consistent with the
two 13-session fingerprints at 100 % and 0 % in the fingerprint table, though
the pairing was not printed row by row.

**The ones that fumble are the ones that do nothing.** Of the 31 SSH sessions
that failed a credential before succeeding, 27 are PuTTY (all 14 of its
sessions, one source) and OpenSSH 10.5 and 10.6 (all 13, from 13 sources) —
the clients ordinary people and ordinary scripts use — and not one of the 27
ran a command or touched a file afterwards. Whether a person or a tool was
behind them this data cannot say. What it can say is that the sessions that
look least automated are the only ones that log in and leave, and that the
sessions that look most automated do the most once inside.

**File events split by door.** 54.5 % of SSH sessions that got in attempted a
fetch, pushed a file over scp, or wrote one by shell redirection; 8.7 % of
telnet sessions did. Telnet logins are more numerous and do less.

**Measured later the same day (15:31 UTC, `analysis/fingerprints.py
--clients --success`, commit `259b879`).** The credential lists the visitors
try were clustered into campaigns the same afternoon (a cluster = sources whose
lists share a core of at least ten pairs and at least half the median list,
after the 52 pairs that more than 5 % of all sources carry are set aside). Of
the 39 campaigns with three or more sources, **32 are one client program**, and
every one of the eight largest is: the biggest — nineteen sources sharing 868
of a ~1,100-pair dictionary over thirteen days — is `SSH-2.0-Go`; the
`admin/Admin@20xx` list is `libssh_0.9.5`, eleven of eleven. And the AsyncSSH
sessions above have a name now: **fifteen sources running one `admin/1111`
list, every one of which logged in (61 logins) and none of which did anything
afterwards.** The sixty-one sessions, the fifteen sources, the one list and the
zero escalations are the same campaign seen from four sides. The only telnet
campaign among the eight largest — the Mirai list, `root/xmhdipc`,
`root/juantech`, `root/888888`, eight sources — accounts for **1,035 of the
3,871 successful logins** on the sensor.

One caveat travels with every "got in" figure in this note: **the decoy
decides what succeeds.** Cowrie's `userdb.txt` accepts broadly by design, so a
long dictionary logs in because the list is long, not because the attacker is
good. "Got in" describes the honeypot's door as much as the visitor.

## How to read it

- **Counts are sessions, not sources.** 508 Go sessions came from 90 sources;
  16 paramiko sessions from one. Sources per client are in the table; they do
  not sum to a sources total because a source may use more than one client.
- **"Escalated" is a low bar on purpose** — any command or any file event
  after the login. It is the label option 4 would have predicted.
- **The exclusion rule is the usual one**: analyst, loopback and artefact
  credential rows are out before anything is counted.
- **These figures move.** They were taken on a Friday morning in week three of
  an eleven-week collection, and the 9 December freeze will re-run both files.
  Twelve strings and eighteen fingerprints are counts of what has arrived so
  far, not of what exists.

## What this changed

ML option 4 was parked behind the question "how many sessions carry enough
telemetry before the login to predict from". The answer is: every SSH session,
and the telemetry is so decisive that predicting escalation from it is a lookup
table at roughly 97 %. That is not a research question, so option 4 was
re-framed the same morning as a question about *stability* — does the
client-to-behaviour mapping learned in the first weeks hold for the rest of the
collection, and what does a model do with a client it has never seen — with
this table as the baseline. The ML plan records the decision; this note records
the table.

## Next look

The 9 December freeze re-runs `option4-telemetry.sql` and
`option4-clients.sql` and states, beside the frozen table, how many of the
clients first seen after 9 October were new strings and how many were new
fingerprints under an old string. That count is the first data point of the
re-framed option 4.
