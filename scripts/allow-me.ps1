# allow-me.ps1
#
# Points the admin SSH firewall rule at this laptop's current public address.
#
# Why this exists: the rule allows exactly one source address, which is the
# control we want. A home connection gets a new address roughly daily, so the
# rule needs rewriting before each session. Doing that by hand costs four
# minutes of clicking and gets skipped; doing it here costs one command, which
# is what makes the strict rule affordable to keep.
#
# One-time setup, on each machine that runs this:
#   [Environment]::SetEnvironmentVariable('DECOY_SUBSCRIPTION','<id>','User')
# then open a new PowerShell window. The subscription id is not a secret, but
# it is not published either: see docs/rules-of-engagement.md.

$ErrorActionPreference = 'Stop'

# Named explicitly, never inherited from the CLI default. This account can also
# see the university IT subscription, and a firewall command must never land
# there by accident.
$Subscription = $env:DECOY_SUBSCRIPTION
if (-not $Subscription) {
    throw "DECOY_SUBSCRIPTION is not set. See the setup note at the top of this file."
}

$ResourceGroup = 'deception-grid'
$Nsg           = 'decoy-01-nsg'
$Rule          = 'allow-admin-ssh-home'

Write-Host 'Asking for this laptop public IPv4 address...'
$ip = (Invoke-RestMethod 'https://api4.ipify.org').Trim()

# Never write an unchecked value into a firewall rule. If the lookup service
# returns an error page, a redirect or an IPv6 address, stop here.
if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
    throw "Not an IPv4 address: '$ip'. Refusing to put that in a firewall rule."
}

Write-Host "This laptop is $ip"

$current = az network nsg rule show --subscription $Subscription `
    --resource-group $ResourceGroup --nsg-name $Nsg --name $Rule `
    --query 'sourceAddressPrefix' --output tsv

if ($current -eq "$ip/32") {
    Write-Host "Rule already allows $ip/32. Nothing to do."
    exit 0
}

Write-Host "Rule currently allows $current. Updating..."

az network nsg rule update --subscription $Subscription `
    --resource-group $ResourceGroup --nsg-name $Nsg --name $Rule `
    --source-address-prefixes "$ip/32" --output none

$new = az network nsg rule show --subscription $Subscription `
    --resource-group $ResourceGroup --nsg-name $Nsg --name $Rule `
    --query 'sourceAddressPrefix' --output tsv

if ($new -ne "$ip/32") {
    throw "Update did not take. Rule says '$new', expected '$ip/32'."
}

Write-Host "Done. Rule now allows $new"
Write-Host "Now: ssh -p 62222 aster@<your machine>"
