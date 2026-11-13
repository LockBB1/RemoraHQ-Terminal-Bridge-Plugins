param(
    [ValidateSet('install', 'reinstall', 'remove')][string]$Mode,
    [ValidatePattern('^[a-f0-9]{32}$')][string]$OperationId,
    [string]$Installer,
    [ValidatePattern('^[a-f0-9]{64}$')][string]$InstallerSha256
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$started = $false
$locked = $false
$result = 'outcome_unknown'
$runDirectory = $null
$root = Join-Path $env:ProgramData 'RemoraHQ-RemoteInstall'
$lock = Join-Path $root 'active'
try {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'admin_required' }
    if (Test-Path -LiteralPath $root) {
        if ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'unsafe_target_state' }
    } else {
        $null = New-Item -ItemType Directory -Path $root
        # Local administrators/SYSTEM only; remote commands run with the push account.
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
        foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
            $identity = New-Object Security.Principal.SecurityIdentifier($sid)
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        }
        Set-Acl -LiteralPath $root -AclObject $acl
    }
    $acl = Get-Acl -LiteralPath $root
    $trustedSids = @('S-1-5-18', 'S-1-5-32-544')
    if ($trustedSids -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { throw 'unsafe_target_state' }
    if (-not $acl.AreAccessRulesProtected) { throw 'unsafe_target_state' }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $trustedSids -notcontains $rule.IdentityReference.Value) { throw 'unsafe_target_state' }
    }
    # Preserve unsigned MeshAgent Install support while verifying transport integrity.
    if (-not $Installer -or -not (Test-Path -LiteralPath $Installer -PathType Leaf)) { throw 'installer_missing' }
    if ((Get-FileHash -LiteralPath $Installer -Algorithm SHA256).Hash.ToLowerInvariant() -cne $InstallerSha256) { throw 'installer_unverified' }
    # CreateNew is atomic across WinRM sessions, aliases and independent servers.
    try {
        $file = [IO.File]::Open($lock, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $file.Dispose()
        $locked = $true
    } catch { throw 'target_busy_or_unknown' }
    $receipt = Join-Path $root ($OperationId + '.receipt')
    if (Test-Path -LiteralPath $receipt) { throw 'operation_already_seen' }
    $file = [IO.File]::Open($receipt, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $file.Dispose()
    # Execute only a hash-checked copy in our protected directory, without adjacent policy/DB files.
    $candidateDirectory = Join-Path $root $OperationId
    $null = New-Item -ItemType Directory -Path $candidateDirectory
    $runDirectory = $candidateDirectory
    $verifiedInstaller = Join-Path $runDirectory 'installer.exe'
    Copy-Item -LiteralPath $Installer -Destination $verifiedInstaller
    if ((Get-FileHash -LiteralPath $verifiedInstaller -Algorithm SHA256).Hash.ToLowerInvariant() -cne $InstallerSha256) { throw 'installer_unverified' }
    $Installer = $verifiedInstaller

    $services = @(Get-CimInstance Win32_Service)
    $agents = @()
    foreach ($service in $services) {
        $match = [regex]::Match([string]$service.PathName, '^\s*(?:"(?<exe>[^"]+\.exe)"|(?<exe>.+?\.exe))(?:\s|$)', 'IgnoreCase')
        $exe = if ($match.Success) { [Environment]::ExpandEnvironmentVariables($match.Groups['exe'].Value) } else { $null }
        $knownName = $service.Name -eq 'Mesh Agent' -or $service.Name -eq 'meshagent' -or $service.DisplayName -eq 'Mesh Agent'
        $policy = if ($exe) { [IO.Path]::ChangeExtension($exe, '.msh') } else { $null }
        $meshPolicy = $policy -and (Test-Path -LiteralPath $policy -PathType Leaf) -and ((Get-Content -LiteralPath $policy -Raw) -match '(?m)^MeshID=') -and ((Get-Content -LiteralPath $policy -Raw) -match '(?m)^ServerID=')
        if ($knownName -or $meshPolicy) { $agents += @{ Service = $service; Exe = $exe; Policy = $meshPolicy; PolicyFile = $policy; KnownName = $knownName } }
    }
    $primaryNames = @($agents | ForEach-Object { $_.Service.Name })
    $agents = @($agents | Where-Object { -not ($_.Service.Name.EndsWith('Diagnostic', [StringComparison]::OrdinalIgnoreCase) -and $primaryNames -contains $_.Service.Name.Substring(0, $_.Service.Name.Length - 10)) })
    if ($agents.Count -gt 1) { throw 'agent_ambiguous' }
    if ($Mode -eq 'install' -and $agents.Count -ne 0) { throw 'agent_exists' }
    if ($Mode -ne 'install') {
        if ($agents.Count -eq 0) { throw 'agent_not_found' }
        $agent = $agents[0]
        if (-not $agent.Exe -or -not (Test-Path -LiteralPath $agent.Exe -PathType Leaf)) { throw 'agent_binary_missing' }
        $name = $agent.Service.Name
        if ($name -notmatch '^[A-Za-z0-9 ._-]{1,128}$') { throw 'agent_unverified' }
        if (-not $agent.Policy -and -not ($agent.KnownName -and [IO.Path]::GetFileName($agent.Exe) -ieq 'MeshAgent.exe')) { throw 'agent_unverified' }
        # Upstream also deletes the Diagnostic service binary; preflight both before starting.
        $removalServices = @($agent.Service) + @($services | Where-Object { $_.Name -eq ($name + 'Diagnostic') })
        $removalFiles = @()
        $agentDirectory = [IO.Path]::GetDirectoryName($agent.Exe)
        foreach ($service in $removalServices) {
            $raw = [string]$service.PathName
            # service-manager.appLocation uses a literal, case-sensitive split('.exe').
            # Reject a different interpretation, shell expansion and unsafe cleanup prefixes.
            $nativeExe = ($raw -csplit '\.exe', 2)[0] + '.exe'
            if ($nativeExe.StartsWith('"')) { $nativeExe = $nativeExe.Substring(1) }
            if ($nativeExe -notmatch '^[A-Za-z]:\\' -or $nativeExe -match '[%!?&|<>^"\r\n]' -or [IO.Path]::GetFullPath($nativeExe) -cne $nativeExe -or [IO.Path]::GetFileNameWithoutExtension($nativeExe) -notmatch '^[A-Za-z0-9_][A-Za-z0-9 _.-]*$') { throw 'agent_unverified' }
            $directory = [IO.Path]::GetDirectoryName($nativeExe)
            if ($directory -ine $agentDirectory -or -not (Test-Path -LiteralPath $nativeExe -PathType Leaf)) { throw 'agent_unverified' }
            foreach ($reserved in @([IO.Path]::GetPathRoot($nativeExe), $env:windir, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, $root)) {
                if ($reserved -and ($directory.TrimEnd('\') -ieq $reserved.TrimEnd('\') -or ($reserved -eq $env:windir -and $directory.StartsWith($reserved.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)))) { throw 'agent_unverified' }
            }
            $entry = Get-Item -LiteralPath $nativeExe
            $ancestor = $entry
            while ($ancestor) {
                if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'agent_unverified' }
                $ancestor = if ($ancestor -is [IO.FileInfo]) { $ancestor.Directory } else { $ancestor.Parent }
            }
            foreach ($file in @(Get-ChildItem -LiteralPath $directory -Filter ($entry.BaseName + '.*') -Force)) {
                if ($file.PSIsContainer -or $file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'agent_unverified' }
            }
            $removalFiles += @($nativeExe, [IO.Path]::ChangeExtension($nativeExe, '.msh'))
        }
        $started = $true
        # The fresh server installer removes the named service; never run its installed EXE.
        $process = Start-Process -FilePath $Installer -ArgumentList @('-fulluninstall', ('--meshServiceName="' + $name + '"')) -PassThru -WindowStyle Hidden
        if (-not $process.WaitForExit(60000)) { throw 'outcome_unknown' }
        if ($process.ExitCode -ne 0) { throw 'removal_unconfirmed' }
        # Upstream self-delete helper can wait 10 s after exit; never race it with a fresh install.
        Start-Sleep -Seconds 12
        for ($attempt = 0; $attempt -lt 40; $attempt++) {
            $remaining = @(Get-CimInstance Win32_Service | Where-Object { $_.Name -eq $name -or $_.Name -eq ($name + 'Diagnostic') })
            $filesRemain = @($removalFiles | Where-Object { Test-Path -LiteralPath $_ }).Count -ne 0
            if ($remaining.Count -eq 0 -and -not $filesRemain) { break }
            Start-Sleep -Milliseconds 500
        }
        if ($remaining.Count -ne 0 -or $filesRemain) { throw 'removal_unconfirmed' }
    }
    if ($Mode -ne 'remove') {
        if (-not $Installer -or -not (Test-Path -LiteralPath $Installer -PathType Leaf)) { throw 'installer_missing' }
        # Even Install must guard the default service locally; old-server nodes are absent from this DB.
        if (@(Get-CimInstance Win32_Service | Where-Object { $_.Name -eq 'Mesh Agent' -or $_.Name -eq 'meshagent' }).Count -ne 0) { throw 'agent_exists' }
        $started = $true
        $process = Start-Process -FilePath $Installer -ArgumentList '-fullinstall' -PassThru -WindowStyle Hidden
        if (-not $process.WaitForExit(60000)) { throw 'outcome_unknown' }
        if ($process.ExitCode -ne 0) { throw 'install_failed' }
        $result = 'installer_completed'
    } else { $result = 'removed' }
    $started = $false
} catch {
    $allowed = @('admin_required', 'unsafe_target_state', 'target_busy_or_unknown', 'operation_already_seen', 'agent_ambiguous', 'agent_exists', 'agent_not_found', 'agent_binary_missing', 'agent_unverified', 'installer_missing', 'installer_unverified', 'install_failed', 'removal_unconfirmed')
    if (-not $started -and $allowed -contains $_.Exception.Message) { $result = $_.Exception.Message }
    # Once a destructive command starts, an exception is an unknown outcome.
} finally {
    if ($runDirectory -and -not $started) { Remove-Item -LiteralPath $runDirectory -Recurse -Force -ErrorAction SilentlyContinue }
    if ($locked -and -not $started) { Remove-Item -LiteralPath $lock -Force -ErrorAction SilentlyContinue }
}
Write-Output ('ri-result:' + $result)
