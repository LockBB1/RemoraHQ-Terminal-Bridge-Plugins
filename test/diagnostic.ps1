$ErrorActionPreference = 'Stop'
Import-Module Microsoft.PowerShell.Utility
$script = Join-Path $PSScriptRoot '../remote-install/diagnostic.ps1'
$global:hashValue = 'a' * 64
$global:signatureStatus = 'Valid'
$global:signatureCalls = 0
function Get-FileHash { param($LiteralPath, $Algorithm, $ErrorAction) [pscustomobject]@{ Hash = $global:hashValue } }
function Get-AuthenticodeSignature {
    param($LiteralPath, $ErrorAction)
    $global:signatureCalls++
    [pscustomobject]@{ Status = $global:signatureStatus; SignerCertificate = [object]::new() }
}
$result = & $script -Installer 'fixture' -InstallerSha256 ('a' * 64)
if ($result -ne 'ri-diagnostic:match:valid:present') { throw 'matching result failed' }
$global:hashValue = 'b' * 64
$global:signatureStatus = 'UnknownError'
$result = & $script -Installer 'fixture' -InstallerSha256 ('a' * 64)
if ($result -ne 'ri-diagnostic:mismatch:unknown_error:present' -or $global:signatureCalls -ne 2) { throw 'independent checks failed' }
Write-Output 'Independent hash and signature checks PASS'
