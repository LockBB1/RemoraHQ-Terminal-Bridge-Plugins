param(
    [ValidateSet('create', 'remove')][string]$Action,
    [ValidatePattern('^[a-f0-9]{32}$')][string]$OperationId
)
$ErrorActionPreference = 'Stop'
try {
    $parent = Get-Item -LiteralPath $env:ProgramData -Force
    for ($entry = $parent; $entry; $entry = $entry.Parent) {
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'unsafe' }
    }
    $dir = Join-Path $parent.FullName ('RemoraHQ-Diagnostic-' + $OperationId)
    if ($Action -eq 'create') {
        if (Test-Path -LiteralPath $dir) { throw 'exists' }
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
        foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
            $identity = New-Object Security.Principal.SecurityIdentifier($sid)
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        }
        [IO.Directory]::CreateDirectory($dir, $acl) | Out-Null
    }
    $entry = Get-Item -LiteralPath $dir -Force
    if (-not $entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'unsafe' }
    $acl = Get-Acl -LiteralPath $dir
    $trusted = @('S-1-5-18', 'S-1-5-32-544')
    if ($trusted -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -or -not $acl.AreAccessRulesProtected) { throw 'unsafe' }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $trusted -notcontains $rule.IdentityReference.Value) { throw 'unsafe' }
    }
    if ($Action -eq 'create') {
        Write-Output ('ri-directory:' + (Join-Path $dir 'installer.exe'))
    } else {
        $file = Join-Path $dir 'installer.exe'
        if (Test-Path -LiteralPath $file) {
            if ((Get-Item -LiteralPath $file -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'unsafe' }
            Remove-Item -LiteralPath $file -Force
        }
        [IO.Directory]::Delete($dir, $false)
        if (Test-Path -LiteralPath $dir) { throw 'cleanup' }
        Write-Output 'ri-directory:removed'
    }
} catch { Write-Output 'ri-directory:unknown' }
