# verify-signature.ps1 — release gate for the GitHub Actions pipeline.
#
# Asserts, for one signed exe, exactly what the in-app updater asserts
# before it applies a download (src/updater.js):
#   1. the file carries an Authenticode signature whose signer
#      certificate SHA-256 fingerprint equals the pinned fingerprint
#      (PINNED_SIGNER_FINGERPRINT256 in src/updater.js — extracted from
#      there when -Fingerprint is not passed), and
#   2. the signature carries an RFC 3161 timestamp.
# The signature Status may read Valid or NotTrusted: NotTrusted is the
# expected verdict for a self-signed cert on any machine where the
# public cert has not been installed, and is not a failure here. The
# fingerprint equality is the check that matters. Any other status
# (NotSigned, HashMismatch, ...) fails.
#
# Usage:
#   .\scripts\verify-signature.ps1 -File dist\Muse-Portable.exe
#   .\scripts\verify-signature.ps1 -File <exe> -Fingerprint "0E:C7:..."
param(
    [Parameter(Mandatory = $true)][string]$File,
    [string]$Fingerprint
)
$ErrorActionPreference = "Stop"

if (-not $Fingerprint) {
    $updater = Get-Content (Join-Path $PSScriptRoot "..\src\updater.js") -Raw
    if ($updater -notmatch "PINNED_SIGNER_FINGERPRINT256\s*=\s*'([0-9A-Fa-f:]+)'") {
        throw "Could not find PINNED_SIGNER_FINGERPRINT256 in src/updater.js"
    }
    $Fingerprint = $Matches[1]
}
$expected = ($Fingerprint -replace "[:\s]", "").ToUpper()

$sig = Get-AuthenticodeSignature $File
if ($sig.Status -notin @("Valid", "NotTrusted")) {
    throw "$File : signature status is $($sig.Status) ($($sig.StatusMessage))"
}
if (-not $sig.SignerCertificate) {
    throw "$File : no signer certificate in the signature"
}
if (-not $sig.TimeStamperCertificate) {
    throw "$File : signature has no RFC 3161 timestamp"
}
$sha = [System.Security.Cryptography.SHA256]::Create()
try {
    $actual = ([BitConverter]::ToString($sha.ComputeHash($sig.SignerCertificate.RawData)) -replace "-", "").ToUpper()
} finally {
    $sha.Dispose()
}
if ($actual -ne $expected) {
    throw "$File : signer fingerprint mismatch - got $actual, pinned is $expected"
}
Write-Host "[verify-signature] OK: $File (signer fingerprint matches the pinned Muse Desktop cert, timestamp present, status $($sig.Status))"
