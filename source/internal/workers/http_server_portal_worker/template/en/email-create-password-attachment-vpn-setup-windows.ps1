$VpnName = "{{ $.Form.ServerHost }}"

Write-Host "Configuring $VpnName VPN connection"

# Remove any existing VPN connection with the same name to ensure it is not misconfigured.
# '-Force' removes the connection without asking for confirmation.
# '-ErrorAction SilentlyContinue' suppresses any error messages if the connection doesn't exist.
Write-Host -NoNewLine "Deleting old settings... "
Remove-VpnConnection -Name "$VpnName" -Force -ErrorAction SilentlyContinue
Write-Host "done"

# Add a new VPN connection with the specified settings.
Write-Host -NoNewLine "Creating new settings... "
Add-VpnConnection `
     -Name $VpnName `
     -AuthenticationMethod Eap `
     -DnsSuffix "{{ $.Form.DnsSuffix }}" `
     -EncryptionLevel Required `
     -IdleDisconnectSeconds 86400 `
     -RememberCredential `
     -ServerAddress "$VpnName" `
     -SplitTunneling `
     -TunnelType Ikev2

# Split tunneling allows traffic destined for specific destination subnets to use the VPN tunnel, while other traffic bypasses the VPN.
# Here we specify the subnets for which the traffic should be routed through the VPN.
{{ range $destinationPrefix := $.Form.DestinationPrefixes }}
Add-VpnConnectionRoute -ConnectionName "$VpnName"  -DestinationPrefix "{{ $destinationPrefix }}" -RouteMetric 1
{{ end }}
Write-Host "done"

# Modifying VPN configuration files directly to achieve settings not exposed by the PowerShell API.
# This operation involves updating configuration files directly since there is no built-in API to modify certain settings.
# Pause execution for 5 seconds to ensure any asynchronous writes have completed before making modifications.
Write-Host -NoNewLine "Waiting for pending activities... "
Start-Sleep -Seconds 5
Write-Host "done"

Write-Host -NoNewLine "Updating interface metrics... "
# Adjust the IPv4 and IPv6 metrics to prioritize the DNS servers from the remote network.
# This ensures that name resolution works correctly via the VPN connection.

$RoamingPath = [Environment]::GetFolderPath("ApplicationData")

# The phonebook used by Remote Access Services (RAS). VPN settings are saved here.
$PhoneBookSourcePath = Join-Path $roamingPath "Microsoft\Network\Connections\Pbk\rasphone.pbk"

# Create a new file for temporary updates and move it over to the source after modifications are complete.
# This way operation is atomic and file will not be damaged by partial updates.
$PhoneBookTargetPath = Join-Path $roamingPath "Microsoft\Network\Connections\Pbk\rasphone.pbk.new"

# Backup the existing configuration file before making any changes to preserve a fallback option.
$PhoneBookBackupPath = Join-Path $roamingPath "Microsoft\Network\Connections\Pbk\rasphone-$(Get-Date -Format 'yyyyMMddHHmmss').bak"

$IsInConnectionSection = $false
$TargetLines = @()

# Read through the original phonebook file line by line.
# Look for the section related to the specific VPN connection, and modify the interface metrics as needed.
Get-Content $PhoneBookSourcePath | ForEach-Object {
    $line = $_

    if ($line -eq "[$VpnName]") {
        $IsInConnectionSection = $true
    } elseif ($line.StartsWith("[")) {
        $IsInConnectionSection = $false
    }

    # Modify the IPv4 and IPv6 interface metrics if they are set to 0.
    # This ensures that these metrics are updated to 1 to prioritize VPN DNS resolution.
    if ($IsInConnectionSection -and $line -eq "IpInterfaceMetric=0") {
        $TargetLines += "IpInterfaceMetric=1"
    } elseif ($IsInConnectionSection -and $line -eq "Ipv6InterfaceMetric=0") {
        $TargetLines += "Ipv6InterfaceMetric=1"
    } else {
        $TargetLines += $line
    }
}

# Save the modified configuration to a temporary file.
Set-Content -Path $PhoneBookTargetPath -Value $TargetLines

# Backup the original configuration before overwriting it with the new version.
Copy-Item -Path $PhoneBookSourcePath -Destination $PhoneBookBackupPath -Force

# Replace the old configuration file with the newly modified one.
Move-Item -Path $PhoneBookTargetPath -Destination $PhoneBookSourcePath -Force

Write-Host "done"

Write-Host -NoNewLine 'Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
