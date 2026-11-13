$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) ('remora-lifecycle-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
try {
$source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../remote-install/lifecycle.ps1') -Raw
# Run only a temporary copy; platform identity and ACL are outside this synthetic test.
$source = $source -replace "(?m)^    if \(-not \(\[Security\.Principal\.WindowsPrincipal\].*throw 'admin_required' \}\r?\n", ''
$source = [regex]::Replace($source, '(?s)    if \(Test-Path -LiteralPath \$root\) \{.*?    # Preserve unsigned', "    New-Item -ItemType Directory -Force -Path `$root | Out-Null`n    # Preserve unsigned", 1)
$copy = Join-Path $root 'lifecycle-copy.ps1'
[IO.File]::WriteAllText($copy, $source)

$global:riCert = [pscustomobject]@{ RawData = [byte[]](1, 2, 3) }
function Get-AuthenticodeSignature { param($LiteralPath) [pscustomobject]@{ Status = 'UnknownError'; SignerCertificate = $global:riCert } }
function Get-CimInstance { param($ClassName) $global:riServices }
function Start-Sleep {
    param($Seconds, $Milliseconds)
    if ($Seconds -eq 12) {
        $global:riGrace = $true
        if ($global:riDeleteAfterGrace) {
            [IO.File]::Delete($global:riOldExe)
            [IO.File]::Delete([IO.Path]::ChangeExtension($global:riOldExe, '.msh'))
            foreach ($path in $global:riDiagnosticFiles) { [IO.File]::Delete($path) }
        }
    }
}
function Start-Process {
    param($FilePath, $ArgumentList, [switch]$PassThru, $WindowStyle)
    $global:riCalls += [string]::Join(' ', $ArgumentList)
    if ($FilePath -eq $global:riOldExe) { throw 'Installed service executable must never run' }
    if (-not $FilePath.StartsWith((Join-Path $env:ProgramData 'RemoraHQ-RemoteInstall') + '\')) { throw 'Installer must run from the protected operation directory' }
    if ((Get-FileHash -LiteralPath $FilePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sha) { throw 'Only the transferred installer may run' }
    if (($ArgumentList -join ' ') -match 'fulluninstall' -and $global:riRemoveSucceeds -and -not $global:riTimeout) { $global:riServices = @() }
    $process = [pscustomobject]@{ ExitCode = 0 }
    $process | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($ms) return -not $global:riTimeout }
    return $process
}

function Invoke-Case($name, $mode, $existing, $removal, $timeout, $cleanup, $expected, $count) {
    $env:ProgramData = Join-Path $root $name
    New-Item -ItemType Directory -Path $env:ProgramData | Out-Null
    $installedDirectory = Join-Path $env:ProgramData 'installed'
    New-Item -ItemType Directory -Path $installedDirectory | Out-Null
    $global:riOldExe = Join-Path $installedDirectory 'agent.exe'
    if ($name -eq 'reparse-parent') {
        $junction = Join-Path $env:ProgramData 'linked'
        New-Item -ItemType Junction -Path $junction -Target $installedDirectory | Out-Null
        $global:riOldExe = Join-Path $junction 'agent.exe'
    }
    if ($name -eq 'expansion-path') { $global:riOldExe = Join-Path $installedDirectory 'agent!fixture.exe' }
    if ($name -eq 'uppercase-exe') { $global:riOldExe = Join-Path $installedDirectory 'agent.EXE' }
    [IO.File]::WriteAllText($global:riOldExe, 'fixture')
    [IO.File]::WriteAllText([IO.Path]::ChangeExtension($global:riOldExe, '.msh'), "MeshID=fixture`nServerID=fixture`n")
    $service = [pscustomobject]@{ Name = 'Mesh Agent'; DisplayName = 'Mesh Agent'; PathName = ('"' + $global:riOldExe + '"') }
    $global:riServices = @(if ($existing) { $service })
    $global:riDiagnosticFiles = @()
    if ($name -eq 'unrelated-binary') { [IO.File]::Delete([IO.Path]::ChangeExtension($global:riOldExe, '.msh')) }
    if ($name -eq 'multiple') { $global:riServices += [pscustomobject]@{ Name = 'Other Agent'; DisplayName = 'Other Agent'; PathName = $service.PathName } }
    if ($name -eq 'diagnostic' -or $name -eq 'unsafe-diagnostic') {
        $diagnosticDirectory = $installedDirectory
        if ($name -eq 'unsafe-diagnostic') {
            $diagnosticDirectory = Join-Path $env:ProgramData 'other'
            New-Item -ItemType Directory -Path $diagnosticDirectory | Out-Null
        }
        $diagnostic = Join-Path $diagnosticDirectory 'diagnostic.exe'
        [IO.File]::WriteAllText($diagnostic, 'fixture')
        $global:riServices += [pscustomobject]@{ Name = 'Mesh AgentDiagnostic'; DisplayName = 'Diagnostic'; PathName = ('"' + $diagnostic + '"') }
        $global:riDiagnosticFiles = @($diagnostic, [IO.Path]::ChangeExtension($diagnostic, '.msh'))
        if ($name -eq 'diagnostic') { [IO.File]::WriteAllText($global:riDiagnosticFiles[1], "MeshID=fixture`nServerID=fixture`n") }
    }
    $global:riRemoveSucceeds = $removal; $global:riTimeout = $timeout; $global:riDeleteAfterGrace = $cleanup
    $global:riCalls = @(); $global:riGrace = $false
    $expectedSha = if ($name -eq 'hash-mismatch') { '0' * 64 } else { $sha }
    $result = & $copy -Mode $mode -OperationId ([guid]::NewGuid().ToString('N')) -Installer $installer -InstallerSha256 $expectedSha
    if ($name -eq 'reparse-parent') { [IO.Directory]::Delete($junction) }
    if (@($result | Where-Object { $_ -like 'ri-result:*' }) -cne ('ri-result:' + $expected)) { throw "$name returned $result" }
    if ($result -notcontains ('ri-cleanup:' + $(if ($expected -eq 'outcome_unknown') { 'unknown' } else { 'confirmed' }))) { throw "$name cleanup result missing" }
    if ($global:riCalls.Count -ne $count) { throw "$name made $($global:riCalls.Count) process calls" }
    if ($name -eq 'reinstall' -and (-not $global:riGrace -or $global:riCalls[0] -notmatch 'fulluninstall' -or $global:riCalls[1] -ne '-fullinstall')) { throw 'reinstall ordering or cleanup wait failed' }
    if ($timeout -and -not (Test-Path -LiteralPath (Join-Path $env:ProgramData 'RemoraHQ-RemoteInstall/active'))) { throw 'unknown result must keep target lock' }
    Write-Output "$name PASS"
}
$installer = Join-Path $root 'installer.exe'
[IO.File]::WriteAllText($installer, 'fixture')
$sha = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
Invoke-Case 'install-existing' 'install' $true $true $false $true 'agent_exists' 0
Invoke-Case 'install-clean' 'install' $false $true $false $true 'installer_completed' 1
Invoke-Case 'reinstall' 'reinstall' $true $true $false $true 'installer_completed' 2
Invoke-Case 'remove' 'remove' $true $true $false $true 'removed' 1
Invoke-Case 'diagnostic' 'remove' $true $true $false $true 'removed' 1
Invoke-Case 'unsafe-diagnostic' 'remove' $true $true $false $true 'agent_unverified' 0
Invoke-Case 'unrelated-binary' 'remove' $true $true $false $true 'agent_unverified' 0
Invoke-Case 'expansion-path' 'remove' $true $true $false $true 'agent_unverified' 0
Invoke-Case 'reparse-parent' 'remove' $true $true $false $true 'agent_unverified' 0
Invoke-Case 'uppercase-exe' 'remove' $true $true $false $true 'agent_unverified' 0
Invoke-Case 'multiple' 'remove' $true $true $false $true 'agent_ambiguous' 0
Invoke-Case 'hash-mismatch' 'remove' $true $true $false $true 'installer_unverified' 0
Invoke-Case 'failed-removal' 'reinstall' $true $false $false $false 'outcome_unknown' 1
Invoke-Case 'pending-files' 'reinstall' $true $true $false $false 'outcome_unknown' 1
Invoke-Case 'timeout' 'reinstall' $true $true $true $false 'outcome_unknown' 1
Invoke-Case 'absent' 'remove' $false $true $false $false 'agent_not_found' 0
} finally {
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    $resolved = [IO.Path]::GetFullPath($root)
    if (-not $resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or -not [IO.Path]::GetFileName($resolved).StartsWith('remora-lifecycle-test-')) { throw 'Unsafe temporary test path' }
    [IO.Directory]::Delete($resolved, $true)
}
