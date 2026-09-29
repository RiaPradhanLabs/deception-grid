# Opening the OT door — runbook for 6 October 2026

Everything on the decoy side is already done and verified. This is **only** the
two firewall layers, and it is written out because it will be done a week after
the work it completes, probably without the reasoning fresh.

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

## Step 1 — check the current state, both layers

On the sensor:

```
sudo decoy-status | sed -n '/OT DECOY/,/^$/p'
```

Expect `listening 0.0.0.0:502` and `ufw 502 closed`.

Then the NSG, from PowerShell on the laptop. This lists existing rules so the new
one gets a free priority rather than colliding:

```
az network nsg list --subscription $env:DECOY_SUBSCRIPTION -g DECEPTION-GRID --query "[].name" -o tsv
```

Take the name it prints — call it `<NSG>` below — and list its rules:

```
az network nsg rule list --subscription $env:DECOY_SUBSCRIPTION -g DECEPTION-GRID --nsg-name <NSG> --query "sort_by([].{priority:priority,name:name,port:destinationPortRange,src:sourceAddressPrefix,access:access}, &priority)" -o table
```

**Read this before continuing.** You need to know: which priority numbers are
taken, and whether the admin SSH rule (62222, restricted to one address) sits
*above* or *below* where you are about to insert. Lower number wins in an NSG.
The new rule allows 502 from the internet and must not be numbered in a way that
disturbs the admin rule — pick a priority that is free and higher (numerically)
than the admin rule.

## Step 2 — open the NSG

Replace `<NSG>` and `<PRIORITY>` with what you found:

```
az network nsg rule create --subscription $env:DECOY_SUBSCRIPTION -g DECEPTION-GRID --nsg-name <NSG> --name allow-modbus-502 --priority <PRIORITY> --direction Inbound --access Allow --protocol Tcp --source-address-prefixes Internet --source-port-ranges '*' --destination-address-prefixes '*' --destination-port-ranges 502 --description "OT decoy: Modbus/TCP. Opened 2026-10-06. Deception Grid capstone."
```

Then confirm it is there and where you expect:

```
az network nsg rule list --subscription $env:DECOY_SUBSCRIPTION -g DECEPTION-GRID --nsg-name <NSG> --query "sort_by([].{priority:priority,name:name,port:destinationPortRange,src:sourceAddressPrefix,access:access}, &priority)" -o table
```

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

```
sudo curl -fsS -H 'Cache-Control: no-cache' -o /usr/local/bin/decoy-status "https://raw.githubusercontent.com/RiaPradhanLabs/deception-grid/main/scripts/decoy-status?v=$(date +%s)"
sudo chown root:root /usr/local/bin/decoy-status
sudo chmod 755 /usr/local/bin/decoy-status
sudo bash -n /usr/local/bin/decoy-status && echo "syntax OK"
sudo decoy-status | sed -n '/OT DECOY/,/^$/p'
```

Expect `ufw 502 ALLOW` and, until the first visitor arrives, a line saying the
door is open and nothing has come yet. That is correct for the first few hours
and becomes worth investigating if it is still true after a day.

## Step 4 — prove it end to end, from outside

From PowerShell on the laptop — this is the only test that crosses both layers:

```
Test-NetConnection -ComputerName $env:DECOY_HOST -Port 502 -InformationLevel Detailed
```

`TcpTestSucceeded : True` is the door open. `False` means one of the two layers
is still shut, and Step 1's listings say which.

## Step 5 — prove the decoy recorded you

Reaching it is not the same as recording it. On the sensor:

```
sudo tail -3 /home/conpot/log/conpot.json | sudo python3 -c "import sys,json;[print(json.loads(l).get('event_time'), json.loads(l).get('src_ip'), json.loads(l).get('dst_port'), json.loads(l).get('event_type')) for l in sys.stdin]"
```

You should see your own address, `dst_port 502`, `NEW_CONNECTION`.

One thing that will look odd and is correct: `decoy-status` will now report
`sources 1 external`, counting **you**. Its OT source count excludes loopback
only, not the analyst's addresses — it says as much at the bottom of the screen,
and `ingest.py` is the figure to quote because it also applies
`exclude-ips.txt`. So your test connection is excluded from the analysis and
visible in the status screen. That is the intended split, not a bug.

## Step 6 — the pipeline

```
cd ~/analysis && sudo python3 ingest.py | sed -n '/OT door/,/^$/p'
```

Then the standing OT questions:

```
cd ~/analysis && sqlite3 -header -column decoy.sqlite < weekly.sql 2>/dev/null | sed -n '/14\. The OT door/,/17\./p'
```

Queries 14, 15 and 16 are the OT ones — what arrived, which Modbus function codes
were asked for, and the IT-versus-OT comparison. On day one expect query 14 to
hold only your own test, correctly excluded from query 16.

## If it needs closing again

Both, and in the reverse order — ufw first, so the machine stops answering before
the NSG stops delivering:

```
sudo ufw status numbered | grep 502      # note the rule number
sudo ufw delete <number>
```

```
az network nsg rule delete --subscription $env:DECOY_SUBSCRIPTION -g DECEPTION-GRID --nsg-name <NSG> --name allow-modbus-502
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
- `exclude-ips.txt` already holds your addresses.
