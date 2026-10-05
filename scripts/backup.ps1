# backup.ps1
#
# Pulls the collection off decoy-01 and reports whether it is still alive.
# Run it whenever you check in - a few times a week is enough.
#
# One-time setup on each machine that runs this:
#   [Environment]::SetEnvironmentVariable('DECOY_HOST','<address>','User')
# then open a new PowerShell window.

$ErrorActionPreference = 'Stop'

$DecoyHost = $env:DECOY_HOST
if (-not $DecoyHost) {
    throw "DECOY_HOST is not set. See the note at the top of this file."
}

# 62222, not 22. Port 22 belongs to Cowrie, which will happily complete a key
# exchange with you and offer its own host key -- at which point ssh reports
# REMOTE HOST IDENTIFICATION HAS CHANGED and looks exactly like a compromise.
# That happened on 29 September 2026; see docs/build.md, "Connecting to the
# sensor, and the warning that means you reached the decoy".
$Port  = 62222
$User  = 'aster'
$Stamp = [DateTime]::UtcNow.ToString('yyyy-MM-dd-HHmm') + 'Z'
$Dest  = Join-Path $HOME 'deception-grid\backups'
New-Item -ItemType Directory -Force -Path $Dest | Out-Null

# The admin rule allows one address and a home connection changes daily,
# so make sure we can get in before trying to.
& "$PSScriptRoot\allow-me.ps1"

# --- the address history, to the machine that actually reads it -----------
#
# allow-me.ps1 has just appended today's line to this file. It lives HERE, on
# the laptop. ingest.py reads it on the SENSOR, to decide that one of our own
# addresses was ours only for the window we really held it, rather than for
# all time.
#
# Those are two different machines, and when the date-scoped exclusion was
# written on 5 October 2026 nobody joined them up: ingest.py looked for a file
# that was never going to be there, found nothing, and scoped nothing. It said
# so in its own output, which is the only reason it was caught within the hour.
#
# Copying it up on every run keeps the sensor's copy at most one check-in out
# of date, which is as fresh as it needs to be -- the address cannot change
# without allow-me.ps1 noticing on the next run anyway.
$history = Join-Path $HOME 'deception-grid\analyst-addresses.log'
if (Test-Path $history) {
    scp -P $Port $history "${User}@${DecoyHost}:/home/$User/analysis/analyst-addresses.log"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  WARNING  address history not copied (exit $LASTEXITCODE)."
        Write-Host "           ingest.py will fall back to excluding every own address"
        Write-Host "           for all time -- safe, but blunt, and it will say so."
    }
} else {
    Write-Host "  WARNING  $history does not exist. allow-me.ps1 is supposed to"
    Write-Host "           write it on every run; without it the date-scoped"
    Write-Host "           exclusion has no data to work from."
}

Write-Host ''
Write-Host '--- status ------------------------------------------------'
ssh -p $Port "$User@$DecoyHost" 'sudo decoy-status'

Write-Host '--- backup ------------------------------------------------'
$remote = "/home/$User/staging/decoy-$Stamp.tar.gz"

# Built on the server and then copied down, rather than streamed:
# piping binary through PowerShell corrupts it.
#
# TWO decoys since 29 September 2026. Cowrie's logs and TTY recordings, and
# Conpot's JSON log. A backup that quietly held only the IT decoy's data would
# be discovered at the worst possible moment, so the OT log is not optional
# below: if /home/conpot/log is missing, tar fails and this script stops. That
# is deliberate. A missing OT log means the decoy is answering Modbus and
# recording nothing, which is the failure this project most wants to be loud.
#
# Paths are relative to / so the archive keeps them in full. The previous
# version used -C /home/cowrie/cowrie/var and stored `log/cowrie`, which left
# nowhere unambiguous to put Conpot's own `log` directory. Full paths also mean
# an archive says which decoy each file came from without anyone remembering.
#
# var/lib/cowrie/downloads is deliberately NOT included. That directory holds
# whatever attackers uploaded, much of it live malware, and it has no business
# on a Windows laptop.
$paths = @(
    'home/cowrie/cowrie/var/log/cowrie',
    'home/cowrie/cowrie/var/lib/cowrie/tty',
    'home/conpot/log'
) -join ' '

ssh -p $Port "$User@$DecoyHost" "sudo tar czf $remote -C / $paths && sudo chown ${User}:${User} $remote"

if ($LASTEXITCODE -ge 2) {
    throw "Remote archive step failed (exit $LASTEXITCODE). Nothing downloaded. Exit 255 usually means ssh could not connect; 2 or above means tar failed."
}

scp -P $Port "${User}@${DecoyHost}:$remote" $Dest

ssh -p $Port "$User@$DecoyHost" "rm -f $remote"

$file = Join-Path $Dest "decoy-$Stamp.tar.gz"
$size = [math]::Round((Get-Item $file).Length / 1MB, 3)
Write-Host ''
Write-Host "  saved  $file  ($size MB)"

# --- verify what is actually inside it -------------------------------------
#
# The point of this block: a backup that ran without error is not a backup that
# contains anything. `tar czf` succeeds on an empty directory, so a stopped
# decoy, a rotated-away log or a renamed path all produce a healthy-looking run
# and a useless archive. Counting entries per decoy is the difference between
# "the command worked" and "the data is here".
Write-Host ''
Write-Host '--- what is in the archive --------------------------------'

$entries = & tar -tzf $file

$cowrieLogs = ($entries | Select-String -Pattern 'var/log/cowrie/cowrie\.json'   ).Count
$cowrieTty  = ($entries | Select-String -Pattern 'var/lib/cowrie/tty/'           ).Count
$conpotLogs = ($entries | Select-String -Pattern 'home/conpot/log/conpot\.json'  ).Count

Write-Host ("  IT  cowrie.json files   {0}" -f $cowrieLogs)
Write-Host ("  IT  tty recordings      {0}" -f $cowrieTty)
Write-Host ("  OT  conpot.json files   {0}" -f $conpotLogs)

# Cowrie rotates daily, so more than one cowrie.json* is normal and exactly one
# after several days of collection means rotation is being lost somewhere.
if ($cowrieLogs -lt 1) {
    Write-Host '  *** NO COWRIE LOGS IN THE ARCHIVE - do not trust this backup ***'
}
if ($conpotLogs -lt 1) {
    Write-Host '  *** NO CONPOT LOG IN THE ARCHIVE - the OT decoy may not be recording ***'
    Write-Host '      check: sudo systemctl is-active conpot, and [json] in conpot.cfg'
}

Write-Host ''
