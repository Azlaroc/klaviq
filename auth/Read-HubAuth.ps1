#requires -Version 7.0
<#
.SYNOPSIS
    Read the encrypted Hub auth blob and return the Devolutions
    Hub Application Identity values (key + secret + URL + vaultId).

.DESCRIPTION
    Runtime counterpart of Bootstrap-HubAuth.ps1. Cross-platform:

      Windows : DPAPI CurrentUser decrypt of %LOCALAPPDATA%\klaviq\auth.dat
      Linux   : age -d -i ~/.config/klaviq/auth.key  ~/.config/klaviq/auth.age

    Either way returns a PSCustomObject with four fields:

        key      → applicationKey    (GUID;GUID string)
        secret   → applicationSecret (base64 string, plaintext)
        url      → Hub URL
        vaultId  → Hub vault GUID (optional — default vault for bare-GUID deploy refs)

    Two consumption patterns:

      (a) Dot-source from a launcher, then call the function:

            . $PSScriptRoot\..\auth\Read-HubAuth.ps1
            $auth = Get-KlaviqAuth
            Connect-HubAccount -Url              $auth.url `
                               -ApplicationKey    $auth.key `
                               -ApplicationSecret $auth.secret

      (b) Run standalone (returns the object on the pipeline):

            $auth = pwsh -NoProfile -File .\Read-HubAuth.ps1

.PARAMETER BlobPath
    Path to the encrypted blob. Defaults:
      Windows : %LOCALAPPDATA%\klaviq\auth.dat
      Linux   : ~/.config/klaviq/auth.age

.PARAMETER KeyPath
    Linux only. Path to the age identity (private key) created by
    Bootstrap-HubAuth.ps1. Defaults to ~/.config/klaviq/auth.key.

.NOTES
    Output discipline: writes NOTHING to stdout except the returned
    object. All diagnostics go to stderr. This matters for MCP launcher
    use, where stdout is the JSON-RPC transport.

    The decrypted secret lives in the caller's process memory in the
    returned object's .secret field. Callers are responsible for
    scrubbing it after use (e.g., `$auth = $null` once env vars are set).

    Function signature `Get-KlaviqAuth` is identical across platforms —
    launchers don't need to know which platform produced the blob.
#>

[CmdletBinding()]
param(
    [string] $BlobPath,
    [string] $KeyPath
)

function Get-KlaviqAuth {
    [CmdletBinding()]
    param(
        [string] $BlobPath,
        [string] $KeyPath
    )

    # Resolve paths: explicit param > KLAVIQ_* env override > platform default.
    if (-not $BlobPath) {
        if ($env:KLAVIQ_BLOB_PATH) {
            $BlobPath = $env:KLAVIQ_BLOB_PATH
        } elseif ($IsLinux) {
            $BlobPath = Join-Path $HOME '.config/klaviq/auth.age'
        } else {
            $BlobPath = Join-Path $env:LOCALAPPDATA 'klaviq\auth.dat'
        }
    }
    if (-not $KeyPath -and $IsLinux) {
        if ($env:KLAVIQ_KEY_PATH) {
            $KeyPath = $env:KLAVIQ_KEY_PATH
        } else {
            $KeyPath = Join-Path $HOME '.config/klaviq/auth.key'
        }
    }

    if (-not (Test-Path -LiteralPath $BlobPath -PathType Leaf)) {
        Write-Error "Hub auth blob not found at $BlobPath. Run auth/Bootstrap-HubAuth.ps1 to seed it." -ErrorAction Stop
    }

    $json  = $null
    $plain = $null

    try {
        if ($IsLinux) {
            if (-not (Test-Path -LiteralPath $KeyPath -PathType Leaf)) {
                Write-Error "age identity key not found at $KeyPath. Re-run Bootstrap-HubAuth.ps1." -ErrorAction Stop
            }
            if (-not (Get-Command age -ErrorAction SilentlyContinue)) {
                Write-Error "age is not installed (apt install age)." -ErrorAction Stop
            }
            $json = & age -d -i $KeyPath $BlobPath 2>$null
            if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($json)) {
                Write-Error "Hub auth blob decrypt failed (age exit $LASTEXITCODE). Likely the wrong identity, or the blob is corrupt. Re-run Bootstrap-HubAuth.ps1." -ErrorAction Stop
            }
        } else {
            Add-Type -AssemblyName System.Security
            $cipher = [System.IO.File]::ReadAllBytes($BlobPath)
            $plain  = [System.Security.Cryptography.ProtectedData]::Unprotect(
                          $cipher, $null,
                          [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
            $json   = [System.Text.Encoding]::UTF8.GetString($plain)
        }
    } catch {
        if (-not $IsLinux) {
            Write-Error "Hub auth blob decrypt failed: $_. Likely a different user/machine, or the blob is corrupt. Re-run Bootstrap-HubAuth.ps1." -ErrorAction Stop
        } else {
            throw
        }
    }

    try {
        $obj = $json | ConvertFrom-Json
    } catch {
        Write-Error "Hub auth blob parse failed: $_. Blob may be corrupt; re-run Bootstrap-HubAuth.ps1." -ErrorAction Stop
    } finally {
        if ($plain) { [Array]::Clear($plain, 0, $plain.Length) }
        $json = $null
    }

    if (-not $obj.key -or -not $obj.secret -or -not $obj.url) {
        Write-Error "Hub auth blob is missing required fields (key, secret, url). Re-run Bootstrap-HubAuth.ps1." -ErrorAction Stop
    }
    # vaultId is optional — it's only the default vault for bare-GUID deploy refs.

    return $obj
}

# When invoked directly (not dot-sourced), emit the object on the pipeline.
# Dot-source idiom: InvocationName is '.' under dot-sourcing.
if ($MyInvocation.InvocationName -ne '.') {
    Get-KlaviqAuth -BlobPath $BlobPath -KeyPath $KeyPath
}
