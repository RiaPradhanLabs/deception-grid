# Opening the OT door — runbook for 6 October 2026

Everything on the decoy side is already done and verified. This is **only** the
two firewall layers, and it is written out because it will be done a week after
the work it completes, probably without the reasoning fresh.

> **Corrected 6 October 2026, before use.** A read of every file in the
> repository that morning found four statements here that were wrong or
> missing: the closing line claimed `exclude-ips.txt` already held the
> analyst's addresses (it did not hold the current one, and the date-scoped
> window built on 5 October replaces that mechanism); nothing said that
> `backup.ps1` must run first so that the day's address is on the sensor with
> a timestamp before any test connection; step 5's expectation that the test
> would appear in query 14 was wrong, because the analyst's rows are excluded
> and `v_ot` hides excluded rows; and step 3b overwrote the live script in
> place. Each is fixed where it occurs. `docs/lessons-learnt.md` records the
> first of these under *Two corrections owed to other documents*.

Nothing here changes the decoy. `modbus.toml` already says `port = 502`,
`conpot.service` already binds it with `CAP_NET_BIND_SERVICE`, and `decoy-status`
already reports it. The only thing standing between the internet and the OT decoy
is two closed doors.

**Both layers must open.** The Azure NSG answers *who may reach the machine*; ufw
answers *what on the machine may be reached*. Opening one and not the other looks
like an open door and is not one, and the mistake is invisible from the side you
opened.

---

## Before you start: write down the time

The OT door's opening time is a **datum**, not paperwork. Every comparison
between the IT and OT doors depends on knowing that the IT door opened
25 September 08:01:20 UTC and the OT door opened whenever this happens. Get it
before you change anything:

```
date -u '+%Y-%m-%dT%H:%M:%SZ'
```

Record it in `docs/build.md` and in the findings note. UTC, always.

## Step 0 — `backup.ps1` first, from PowerShell on the laptop

```
& $HOME\repos\deception-grid\scripts\backup.ps1
```

Not optional, and not only for the archive. It runs `allow-me.ps1`, which puts
today's address into the admin rule **and appends it to
`analyst-addresses.log` with a UTC timestamp**; it then copies that history to
the sensor. From that moment `ingest.py` knows the address is ours, for a
window starting now. Every test connection below is made from this address,
and without this step the first external source in the OT dataset would be
you. It also takes a baseline archive before anything changes, and prints
`decoy-status`, so the state of both decoys is on record before the door
moves.

If the admin rule was updated (the script says `Updating`), the sensor can take
a minute to become reachable again; an `exit 255` from the archive step is that
delay, not a fault — wait and run it again.

## Step 1 — check the current state, both layers

On the sensor:

```
sudo decoy-status | sed -n '/OT DECOY/,/^$/p'
```

Expect `listening 0.0.0.0:502` and `ufw 502 closed`.

Then the NSG, from PowerShell on the laptop. First confirm which subscription
the commands will act on — this account can also see the university's:

```
az account show --subscription $env:DECOY_SUBSCRIPTION --query name -o tsv
```

The NSG is `decoy-01-nsg` (the name `allow-me.ps1` rewrites daily). List its
rules so the new one gets a free priority rather than colliding:

```
az network nsg rule list --subscription $env:DECOY_SUBSCRIPTION -g deception-grid --nsg-name decoy-01-nsg --query "[].[priority,name,destinationPortRange,sourceAddressPrefix,protocol,access]" -o table
```

The columns are unlabelled: priority, name, port, source, protocol, access.

**Read this before continuing.** You need to know three things. Which priority
numbers are taken, and whether the admin SSH rule (62222, restricted to one
address) sits *above* or *below* where you are about to insert — lower number
wins in an NSG, so pick a number that is free and higher than the admin rule's.
And **what source prefix and protocol the port-22 and port-23 rules use** —
the 502 rule copies them exactly, so that the only difference between the two
doors is the door.

## Step 2 — open the NSG

Replace the placeholders with what step 1 showed — never run it with one left in:

```
az network nsg rule create --subscription $env:DECOY_SUBSCRIPTION -g deception-grid --nsg-name decoy-01-nsg --name allow-modbus-502 --priority <PRIORITY> --direction Inbound --access Allow --protocol <as the 22/23 rules> --source-address-prefixes <as the 22/23 rules> --source-port-ranges '*' --destination-address-prefixes '*' --destination-port-ranges 502 --description "OT decoy Modbus, opened 2026-10-06"
```

Then confirm it is there and where you expect, with the same listing as step 1.

Nothing is reachable yet — ufw is still closed. That order is deliberate: if the
NSG rule is wrong, you find out with the second door still shut.

## Step 3 — open ufw

On the sensor:

```
sudo ufw allow 502/tcp comment "OT decoy Modbus, opened $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
sudo ufw status numbered | grep -E '502|62222|22|23'
```

The comment carries the opening timestamp into the firewall itself, so the date
survives even if the documents do not.

## Step 3b — deploy the updated `decoy-status`, and not before now

`decoy-status` holds the opening date in `OT_OPEN`, and uses it to decide whether
"no external traffic" is the correct answer or a fault. The copy on the sensor
still says the door is not open yet.

Deploy it **after** step 3, never before. Installed while the firewalls were
still shut, it would report the door as open with no traffic and warn about it —
a false alarm on the one tool whose job is to not cry wolf.

Never download onto the live path: a transfer that stops halfway leaves a
truncated script where a working one was, and a redirect has already emptied
one file on this project. Fetch to `/tmp`, check it, then install it:

```
curl -fsS -H 'Cache-Control: no-cache' -o /tmp/decoy-status.new "https://raw.githubusercontent.com/RiaPradhanLabs/deception-grid/main/scripts/decoy-status?v=$(date +%s)"
git hash-object /tmp/decoy-status.new
```

The blob id must equal `git rev-parse HEAD:scripts/decoy-status` on the laptop
checkout. Only then:

```
bash -n /tmp/decoy-status.new && sudo install -m 755 -o root -g root /tmp/decoy-status.new /usr/local/bin/decoy-status
sudo decoy-status | sed -n '/OT DECOY/,/^$/p'
```

**Compare the hash in the command, not by eye, when the fetch and the install
are chained.** On 7 October 2026 a one-liner of the form `curl … && git
hash-object … && mv …` moved a stale copy into place: the CDN had served the
previous commit, the hash was *printed* and nobody was comparing it, and `&&`
only tests that `hash-object` ran. It was harmless once — the stale copy was
byte-identical to the file already there — and wrong as a pattern. The form
that cannot do that, with `<blob>` from the laptop's `git rev-parse HEAD:<path>`:

```
curl -fsS -H 'Cache-Control: no-cache' -o /tmp/x.new "<raw url>?v=$(date +%s)" && [ "$(git hash-object /tmp/x.new)" = "<blob>" ] && bash -n /tmp/x.new && sudo install -m 755 -o root -g root /tmp/x.new /usr/local/bin/x && echo DEPLOYED || echo "NOT DEPLOYED: $(git hash-object /tmp/x.new)"
```

`DEPLOYED` or the stale blob id; nothing moves on a mismatch. A raw-content
CDN can lag a push by a few minutes, so `NOT DEPLOYED` with the previous
commit's id means wait and run the same line again, not fetch some other way.

Expect `ufw 502 ALLOW` and, until the first visitor arrives,
`WARNING OT door open since 2026-10-06 and no external traffic at all`. **That
warning firing now is correct, and is the first time it has been seen to fire
at all** — note it, because an alarm that has only ever been read is an alarm
that has never been tested. It becomes worth investigating if it is still
printing after a day. If a scanner has already arrived, `sources N external`
replaces it; also correct.

## Step 4 — prove it end to end, from outside

From PowerShell on the laptop — this is the only test that crosses both layers:

```
Test-NetConnection -ComputerName $env:DECOY_HOST -Port 502 -InformationLevel Detailed
```

`TcpTestSucceeded : True` is the door open. `PingSucceeded : False`, with a
yellow *Ping … failed* line above it, is normal — the NSG does not pass ICMP and
only the TCP line is the test. `False` means one of the two layers is still
shut, or Conpot is not listening: check `ss -tln | grep 502` on the sensor,
then `ufw status`, then the NSG rule, in that order, and fix the one that
disagrees. If all three are right and TCP still fails, the laptop's own network
is filtering outbound 502 — test from another network before touching the
sensor.

## Step 5 — prove the decoy recorded you

Reaching it is not the same as recording it. First make the test
self-identifying inside the data, not only by address: one Modbus read with a
transaction id nobody else will send. From PowerShell on the laptop, one line:

```
$c=New-Object Net.Sockets.TcpClient($env:DECOY_HOST,502);$s=$c.GetStream();$s.ReadTimeout=5000;$q=[byte[]](0xA5,0xA5,0,0,0,6,1,3,0,7,0,1);$s.Write($q,0,12);$b=New-Object byte[] 64;$n=$s.Read($b,0,64);($b[0..($n-1)]|%{$_.ToString('x2')}) -join '';$c.Close()
```

That reads holding register 7 (the fault word) under transaction id `A5A5`.
The reply begins `a5a5 0000 0005 01 03 02`. Then, on the sensor:

```
sudo grep -ic a5a5 /home/conpot/log/conpot.json
sudo tail -n 12 /home/conpot/log/conpot.json | cut -c1-240
```

The count is at least 1, and the tail shows your own address, `dst_port 502`,
`NEW_CONNECTION` and a Modbus request. Count the lines that carry your address —
call it *R* — because step 6's expected output is stated in terms of it.

One thing that will look odd and is correct: `decoy-status` will now report
`sources 1 external`, counting **you**, and the warning from step 3b is gone —
the alarm has now been seen in both states. Its OT source count excludes
loopback only, not the analyst's addresses — it says as much at the bottom of
the screen, and `ingest.py` is the figure to quote because it also applies the
analyst exclusions. So your test connection is excluded from the analysis and
visible in the status screen. That is the intended split, not a bug.

Run `backup.ps1` once more here, so the sensor's copy of the address history
is current before the pipeline reads it.

## Step 6 — the pipeline

```
cd ~/analysis && sudo python3 ingest.py | sed -n '/OT door/,/^$/p'
```

Then the standing OT questions:

```
cd ~/analysis && sqlite3 -header -column decoy.sqlite < weekly.sql 2>/dev/null | sed -n '/14\. The OT door/,/17\./p'
```

What to expect from the `ingest.py` run, stated before it runs:

- `date-scoped N from analyst-addresses.log` with N ≥ 1 — your address with a
  window that started at step 0.
- `window checks N inside, 0 outside, 0 undated` — **the first time this line
  has ever printed**, because no event from a windowed address had reached a
  decoy before today. N equals *R*: the counter is printed before the re-derive
  pass runs, so it covers the insert pass only (a first draft of this line said
  2 × *R*, and the 6 October run said 5 where 10 was predicted — the code was
  right and the prediction was not). `0 inside` with a non-zero `outside` means
  the window starts after your probe and you are in the day-one dataset as a
  stranger — stop and compare the history's timestamp with the event's.
- Under *the OT door*: if no real scanner has arrived yet, `no OT events that
  count` followed by `(R excluded as analyst)`. If real traffic has arrived,
  that breakdown is not printed; query 3's `analyst` row rises by *R* instead.

Queries 14, 15 and 16 are the OT ones — what arrived, which Modbus function
codes were asked for, and the IT-versus-OT comparison. **Your own test does
not appear in any of them**: it is excluded as `analyst`, and `v_ot` hides
excluded rows. On day one, query 14 shows real external traffic only, or
nothing at all if nobody has arrived yet — and an empty query 14 after a day
is the thing to investigate, per the note above it in `weekly.sql`.

## If it needs closing again

Both, and in the reverse order — ufw first, so the machine stops answering before
the NSG stops delivering:

```
sudo ufw status numbered | grep 502      # note the rule number
sudo ufw delete <number>
```

```
az network nsg rule delete --subscription $env:DECOY_SUBSCRIPTION -g deception-grid --nsg-name decoy-01-nsg --name allow-modbus-502
```

## What to record afterwards

- The opening timestamp, UTC, in `docs/build.md` under *Order of opening*.
- The NSG rule name and priority, so teardown in December is not archaeology.
- In the next findings note: **the two doors did not open on the same day.** The
  IT door opened 25 September, the OT door 6 October. Any table comparing them
  has different denominators, and saying so is the difference between a
  comparison and a coincidence.

## What has NOT changed and does not need touching

- `modbus.toml` already says 502, tested on 5020 first and verified on 502.
- `conpot.service` binds it with one capability, not root, not socket activation.
- The outbound block covers both decoy uids. Opening an inbound port does not
  affect it — but `decoy-status` will confirm it on the next run anyway.
- `exclude-ips.txt` is not touched. Your addresses are handled by the window
  that `allow-me.ps1` and `ingest.py` keep between them (see
  `analysis/README.md`, *Which addresses count as ours*). An earlier version
  of this line said the file already held your addresses; it did not hold the
  current one, and the address rotates daily.
