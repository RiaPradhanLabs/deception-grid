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

$Port  = 62222
$User  = 'aster'
$Stamp = Get-Date -Format 'yyyy-MM-dd-HHmm'
$Dest  = Join-Path $HOME 'deception-grid\backups'
New-Item -ItemType Directory -Force -Path $Dest | Out-Null

# The admin rule allows one address and a home connection changes daily,
# so make sure we can get in before trying to.
& "$PSScriptRoot\allow-me.ps1"

Write-Host ''
Write-Host '--- status ------------------------------------------------'
ssh -p $Port "$User@$DecoyHost" 'sudo decoy-status'

Write-Host '--- backup ------------------------------------------------'
$remote = "/tmp/decoy-$Stamp.tar.gz"

# Built on the server and then copied down, rather than streamed:
# piping binary through PowerShell corrupts it.
#
# var/lib/cowrie/downloads is deliberately NOT included. That directory
# holds whatever attackers uploaded, much of it live malware, and it has
# no business on a Windows laptop.
ssh -p $Port "$User@$DecoyHost" "sudo tar czf $remote -C /home/cowrie/cowrie/var log/cowrie lib/cowrie/tty && sudo chown ${User}:${User} $remote"

scp -P $Port "${User}@${DecoyHost}:$remote" $Dest

ssh -p $Port "$User@$DecoyHost" "rm -f $remote"

$file = Join-Path $Dest "decoy-$Stamp.tar.gz"
$size = [math]::Round((Get-Item $file).Length / 1MB, 3)
Write-Host ''
Write-Host "  saved  $file  ($size MB)"
Write-Host ''