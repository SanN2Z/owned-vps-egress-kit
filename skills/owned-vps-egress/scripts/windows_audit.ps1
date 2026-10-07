param([string]$OutputPath)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
chcp 65001 | Out-Null

# Read-only: no rule changes, adapter changes, controller writes or probe traffic.
try {
    $profiles = @(Get-NetFirewallProfile | ForEach-Object {
        [pscustomobject]@{ Name=$_.Name; Enabled=[string]$_.Enabled;
            DefaultOutbound=[string]$_.DefaultOutboundAction }
    })
    $allows = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Enabled True -Action Allow | ForEach-Object {
        $rule = $_
        [pscustomobject]@{
            Name=$rule.Name; DisplayName=$rule.DisplayName; Profile=[string]$rule.Profile;
            Source=[string]$rule.PolicyStoreSourceType;
            PackageFamilyName=$rule.PackageFamilyName; PolicyAppId=$rule.PolicyAppId;
            Application=@($rule | Get-NetFirewallApplicationFilter | Select-Object Program,Package);
            Address=@($rule | Get-NetFirewallAddressFilter | Select-Object RemoteAddress);
            Port=@($rule | Get-NetFirewallPortFilter | Select-Object Protocol,LocalPort,RemotePort);
            Interface=@($rule | Get-NetFirewallInterfaceFilter | Select-Object InterfaceAlias)
        }
    })
    $adapters = @(Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,ifIndex,HardwareInterface)
    $ipv6 = @(Get-NetAdapterBinding -ComponentID ms_tcpip6 | Select-Object Name,Enabled)
    $processes = @(Get-Process | Where-Object ProcessName -match '^(clash-verge|verge-mihomo|mihomo)$' |
        Select-Object Id,ProcessName,Path)
    $report = [ordered]@{ mode='read-only'; collectedAt=(Get-Date).ToUniversalTime().ToString('o');
        profiles=$profiles; outboundAllows=$allows; adapters=$adapters; ipv6Bindings=$ipv6;
        processes=$processes; needsReview='Compare every allowance with approved baseline, including app packages and virtual adapters.' }
    $json = $report | ConvertTo-Json -Depth 9
    if ($OutputPath) {
        if (Test-Path -LiteralPath $OutputPath) { throw 'Refusing to overwrite an existing audit.' }
        $json | Set-Content -LiteralPath $OutputPath -Encoding UTF8
        Write-Output 'READ_ONLY_AUDIT_SAVED; no network state changed'
    } else { Write-Output $json }
} catch {
    Write-Error ('[fail] Read-only Windows audit: ' + $_.Exception.Message)
    exit 1
}
