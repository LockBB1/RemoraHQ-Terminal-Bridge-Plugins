param(
    [string]$Installer,
    [ValidatePattern('^[a-f0-9]{64}$')][string]$InstallerSha256
)
$hash = 'error'
$signature = 'error'
$signer = 'unknown'
try {
    if ((Get-FileHash -LiteralPath $Installer -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -ceq $InstallerSha256) { $hash = 'match' } else { $hash = 'mismatch' }
} catch { }
try {
    $result = Get-AuthenticodeSignature -LiteralPath $Installer -ErrorAction Stop
    $signer = if ($result.SignerCertificate) { 'present' } else { 'absent' }
    $signature = switch ([string]$result.Status) {
        'Valid' { 'valid' }
        'NotSigned' { 'not_signed' }
        'NotTrusted' { 'not_trusted' }
        'HashMismatch' { 'hash_mismatch' }
        'UnknownError' { 'unknown_error' }
        default { 'other' }
    }
} catch { }
Write-Output ('ri-diagnostic:' + $hash + ':' + $signature + ':' + $signer)
