#requires -Version 7.0
<#
.SYNOPSIS
    Bootstrap the encrypted Devolutions Hub auth blob for headless secret
    delivery.

.DESCRIPTION
    Captures a Devolutions Hub Application Identity (applicationKey +
    applicationSecret + hubUrl + vaultId), validates it against Hub via
    Connect-HubAccount, and writes an encrypted blob to disk under
    the current user's profile.

    Cross-platform — same pwsh script, platform-conditional storage:
      Windows : DPAPI CurrentUser scope, blob at %LOCALAPPDATA%\klaviq\auth.dat
      Linux   : age (X25519), blob at ~/.config/klaviq/auth.age plus
                recipient key at ~/.config/klaviq/auth.key (0400 owner-only)

    Three seeding paths, all cross-platform — RDM Desktop is NOT required:

      1. Manual-paste path: operator types/pastes the App Identity values
         from the Hub portal (browser). Read-Host -AsSecureString is used
         so input does not echo and does not land in shell history.

      2. JSON-file path (-FromJsonFile): seed from a JSON file containing
         { key, secret, url, vaultId }. Intended for automated/headless
         seeding where interactive Read-Host is unavailable.

      3. Stdin path (-FromStdin): read the same JSON from stdin (a pipe), so
         the seed never touches disk. Ideal for an API-broker that resolves
         the credentials via the Hub API and pipes them straight in.

    All paths produce the same JSON payload shape. Runtime consumers
    decrypt the blob, call Connect-HubAccount, and fetch the actual secret
    live from Hub — that secret is NEVER persisted to disk.

    Only key + secret + url are required. The vault is OPTIONAL: normal
    `secret://<vault>/<cred>` references carry their own vault, so the blob
    needs a default vault only for legacy bare-GUID deploy manifests. In
    interactive paste mode, klaviq lists your accessible vaults after
    connecting and lets you pick one BY NAME (it stores the GUID) — or skip.

.PARAMETER BlobPath
    Where to write the encrypted blob. Defaults:
      Windows : %LOCALAPPDATA%\klaviq\auth.dat
      Linux   : ~/.config/klaviq/auth.age

.PARAMETER KeyPath
    Linux only. Path to the age identity (private key). Auto-generated
    via age-keygen on first run if missing. Defaults to
    ~/.config/klaviq/auth.key (0400 owner-only).

.PARAMETER Url
    The Hub URL. If omitted, falls back to the KLAVIQ_HUB_URL environment
    variable, then (in paste mode) an interactive prompt. Set it once and you
    won't be asked again.

.PARAMETER ManualPaste
    If provided, skips path-selection and goes straight to manual-paste mode.

.PARAMETER FromJsonFile
    Path to a JSON file containing { key, secret, url, vaultId }. When
    provided, skips the interactive-paste path and seeds from this file
    directly. Intended for automated seeding (CI, provisioning) or tests
    where interactive Read-Host is unavailable.

    On Linux, the script warns if the file is on persistent storage
    (anything that's not tmpfs/ramfs). Recommended path: /run/shm/seed.json
    (always tmpfs on systemd systems). The script does NOT delete the
    source file by default — see -ShredSource.

.PARAMETER FromStdin
    Read the seed JSON ({ key, secret, url, vaultId }) from stdin instead of a
    file — the plaintext never touches disk. Pipe it in, e.g.
    `<produce-json> | Bootstrap-HubAuth.ps1 -FromStdin`. Ideal for an API-broker
    that resolves credentials via the Hub API. Mutually exclusive with
    -FromJsonFile / -ManualPaste.

.PARAMETER ShredSource
    When combined with -FromJsonFile, the source JSON file is securely
    deleted after Bootstrap completes — regardless of success or failure.
    The secret has been read into process memory by that point and the
    file's continued existence is pure liability.

    Linux: uses `shred -u` (overwrite + unlink).
    Windows: uses Remove-Item -Force (unlink only; NTFS provides no
    standard secure-delete primitive — for higher hygiene use sdelete
    from Sysinternals out-of-band).

    Requires -FromJsonFile; will Fail if specified without it.

.NOTES
    Plaintext exposure: PowerShell process memory only. Never disk,
    network, env, or logs. SecureString is converted briefly to a
    Marshal pointer for crypto, then cleared.

    Windows: DPAPI scope: CurrentUser. Blob decryptable only by the user
    who created it, on the same machine.

    Linux: age X25519 identity at ~/.config/klaviq/auth.key (0400). Blob
    decryptable only by the user holding that identity. The identity is
    portable across hosts in principle but in practice should stay on the
    host where Bootstrap-HubAuth was run.

    To bootstrap a new machine or a different user, run this script there.
#>

[CmdletBinding()]
param(
    [string] $BlobPath,
    [string] $KeyPath,
    [string] $Url,
    [switch] $ManualPaste,
    [string] $FromJsonFile,
    [switch] $FromStdin,
    [switch] $ShredSource
)

$ErrorActionPreference = 'Stop'

if ($ShredSource -and -not $FromJsonFile) {
    Write-Error "Bootstrap-HubAuth: -ShredSource requires -FromJsonFile." -ErrorAction Stop
}

# ─── Platform-aware default paths ───────────────────────────────────────────
# Windows: DPAPI blob at %LOCALAPPDATA%\klaviq\auth.dat
# Linux:   age blob at ~/.config/klaviq/auth.age, recipient key at ~/.config/klaviq/auth.key (0400)
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

# ─── Helpers ────────────────────────────────────────────────────────────────

function Fail([string]$msg) {
    Write-Error "Bootstrap-HubAuth: $msg" -ErrorAction Stop
}

function Test-DevolutionsPowerShellAvailable {
    if (Get-Module -ListAvailable -Name 'Devolutions.PowerShell') {
        Import-Module Devolutions.PowerShell -ErrorAction SilentlyContinue
        return $?
    }
    return $false
}

# ─── tmpfs / shred helpers (Linux + cross-platform) ────────────────────────

function Test-PathOnTmpfs {
    # Returns $true if $Path is on tmpfs/ramfs. Returns $null (unknown) if
    # detection fails. Linux only — Windows always returns $null.
    param([string] $Path)
    if (-not $IsLinux) { return $null }
    try {
        $fs = (& findmnt -n -o FSTYPE -T $Path 2>$null).Trim()
        if ([string]::IsNullOrWhiteSpace($fs)) { return $null }
        return ($fs -in @('tmpfs', 'ramfs'))
    } catch {
        return $null
    }
}

function Invoke-SecureFileDelete {
    # Best-effort secure delete. On Linux shred -u (overwrite + unlink).
    # On Windows Remove-Item -Force (unlink; NTFS has no standard secure delete).
    # Swallows errors — caller chose to clean up; we won't crash on cleanup failure.
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try {
        if ($IsLinux -and (Get-Command shred -ErrorAction SilentlyContinue)) {
            & shred -u $Path 2>$null
            if ($LASTEXITCODE -ne 0 -and (Test-Path -LiteralPath $Path)) {
                Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
            }
        } else {
            Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Warning "Bootstrap-HubAuth: failed to delete $Path after shredding attempt: $_"
    }
}

# ─── age encryption helpers (Linux) ─────────────────────────────────────────

function Test-AgeAvailable {
    return ((Get-Command age          -ErrorAction SilentlyContinue) -and
            (Get-Command age-keygen   -ErrorAction SilentlyContinue))
}

function Initialize-AgeKey {
    param([string] $KeyPath)

    $dir = Split-Path -Parent $KeyPath
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        & chmod 700 $dir
    }

    if (-not (Test-Path -LiteralPath $KeyPath -PathType Leaf)) {
        Write-Host "  Generating new age keypair at $KeyPath" -ForegroundColor Cyan
        & age-keygen -o $KeyPath 2>$null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $KeyPath -PathType Leaf)) {
            Fail "age-keygen failed to write $KeyPath"
        }
        & chmod 400 $KeyPath
    }

    $recipient = (& age-keygen -y $KeyPath 2>$null).Trim()
    if ([string]::IsNullOrWhiteSpace($recipient)) {
        Fail "could not derive age recipient public key from $KeyPath"
    }
    return $recipient
}

function ConvertFrom-SecureStringPlain {
    param([System.Security.SecureString] $s)
    if (-not $s) { return '' }
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
    try   { [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}

# ─── Capture: stdin path (pipe — no plaintext to disk) ──────────────────────

function Get-AppIdentityFromStdin {
    $raw = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($raw)) {
        Fail "-FromStdin: no JSON received on stdin (pipe the seed in, e.g. '<produce-json> | … -FromStdin')."
    }
    try {
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Fail "-FromStdin: stdin could not be parsed as JSON: $_"
    }
    foreach ($f in 'key','secret') {
        if ([string]::IsNullOrWhiteSpace($obj.$f)) {
            Fail "-FromStdin: missing required field '$f'"
        }
    }
    # url optional here (may come from -Url / KLAVIQ_HUB_URL); vaultId optional too.
    return @{ key = $obj.key; secret = $obj.secret; url = $obj.url; vaultId = $obj.vaultId }
}

# ─── Capture: JSON-file path (automation / tests) ───────────────────────────

function Get-AppIdentityFromJsonFile {
    param([string] $Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Fail "FromJsonFile not found: $Path"
    }
    try {
        $obj = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Fail "FromJsonFile could not be parsed as JSON: $_"
    }
    foreach ($f in 'key','secret') {
        if ([string]::IsNullOrWhiteSpace($obj.$f)) {
            Fail "FromJsonFile missing required field '$f'"
        }
    }
    # url optional here (may come from -Url / KLAVIQ_HUB_URL); vaultId optional too.
    return @{ key = $obj.key; secret = $obj.secret; url = $obj.url; vaultId = $obj.vaultId }
}

# ─── Capture: Manual-paste path ─────────────────────────────────────────────

function Get-AppIdentityFromPaste {
    param([string] $DefaultUrl)
    Write-Host ''
    Write-Host 'Paste the values from the App Identity page. Input for key/secret is hidden.' -ForegroundColor Cyan
    Write-Host ''

    $keySecure    = Read-Host 'applicationKey    (format: GUID;GUID)'  -AsSecureString
    $secretSecure = Read-Host 'applicationSecret (base64 string)'      -AsSecureString
    if ([string]::IsNullOrWhiteSpace($DefaultUrl)) {
        $url = Read-Host 'Hub URL           (e.g., https://<tenant>.devolutions.app)'
    } else {
        $url = $DefaultUrl
        Write-Host "  Hub URL (from default): $url" -ForegroundColor Green
    }

    $key    = ConvertFrom-SecureStringPlain $keySecure
    $secret = ConvertFrom-SecureStringPlain $secretSecure

    # vaultId is NOT prompted — it's optional and (in paste mode) chosen
    # interactively from the accessible-vault list after Connect succeeds.
    return @{ key = $key; secret = $secret; url = $url; vaultId = $null }
}

function Select-DefaultVault {
    # Called while connected to Hub (paste mode). Lists accessible vaults and lets
    # the operator pick one BY NAME; returns its GUID, or $null if skipped.
    try {
        $vaults = @(Get-HubVault -ErrorAction Stop | Sort-Object Name)
    } catch {
        Write-Host '  (could not list vaults — skipping default-vault selection)' -ForegroundColor Yellow
        return $null
    }
    if (-not $vaults -or $vaults.Count -eq 0) { return $null }
    Write-Host ''
    Write-Host 'Pick a default vault (optional — only used for bare-GUID deploy manifests;' -ForegroundColor Cyan
    Write-Host 'secret://<vault>/<cred> references carry their own vault):'               -ForegroundColor Cyan
    for ($i = 0; $i -lt $vaults.Count; $i++) {
        Write-Host ("  [{0}] {1}" -f ($i + 1), $vaults[$i].Name)
    }
    $sel = Read-Host 'Choice (number, or Enter to skip)'
    if ([string]::IsNullOrWhiteSpace($sel)) {
        Write-Host '  (no default vault set)' -ForegroundColor Yellow
        return $null
    }
    if ($sel -match '^\d+$' -and [int]$sel -ge 1 -and [int]$sel -le $vaults.Count) {
        $v = $vaults[[int]$sel - 1]
        Write-Host ("  default vault: {0}" -f $v.Name) -ForegroundColor Green
        return $v.Id
    }
    Write-Host '  invalid choice — no default vault set.' -ForegroundColor Yellow
    return $null
}

# ─── Path selection ─────────────────────────────────────────────────────────

if (-not (Test-DevolutionsPowerShellAvailable)) {
    Fail "Devolutions.PowerShell module not installed. Run: Install-Module Devolutions.PowerShell"
}

$path = $null

if ($FromStdin) {
    if ($FromJsonFile -or $ManualPaste) {
        Fail "-FromStdin is mutually exclusive with -FromJsonFile / -ManualPaste."
    }
    if ($IsLinux -and -not (Test-AgeAvailable)) {
        Fail "age and age-keygen must be installed (e.g., 'sudo apt install age')."
    }
    $path = 'stdin'
} elseif ($FromJsonFile) {
    if ($ManualPaste) {
        Fail "-FromJsonFile is mutually exclusive with -ManualPaste."
    }
    if ($IsLinux -and -not (Test-AgeAvailable)) {
        Fail "age and age-keygen must be installed (e.g., 'sudo apt install age')."
    }
    # Warn if the seed file is on persistent storage. Plaintext credentials
    # in a non-tmpfs file survive reboots until manually deleted (or until
    # -ShredSource runs at the end of Bootstrap).
    $onTmpfs = Test-PathOnTmpfs -Path $FromJsonFile
    if ($onTmpfs -eq $false) {
        $fsType = ''
        try { $fsType = (& findmnt -n -o FSTYPE -T $FromJsonFile 2>$null).Trim() } catch {}
        Write-Warning ("FromJsonFile is on '{0}', not tmpfs. Plaintext credentials in {1} will persist on disk across reboots. Recommended path: /run/shm/seed.json. Use -ShredSource to auto-clean after Bootstrap." -f $fsType, $FromJsonFile)
    }
    if ($ShredSource) {
        Write-Host ("  -ShredSource: {0} will be securely deleted after Bootstrap" -f $FromJsonFile) -ForegroundColor Cyan
    }
    $path = 'json'
} else {
    if ($IsLinux -and -not (Test-AgeAvailable)) {
        Fail "age and age-keygen must be installed (e.g., 'sudo apt install age')."
    }
    $path = 'paste'
}

# Body wrapped in try/finally so -ShredSource runs even if Bootstrap fails
# partway through. The secret is in memory by the time we reach Capture, so
# the source file is equally exposed on success and failure — clean either way.
try {

# ─── Capture ────────────────────────────────────────────────────────────────

$urlDefault = if (-not [string]::IsNullOrWhiteSpace($Url)) { $Url }
              elseif (-not [string]::IsNullOrWhiteSpace($env:KLAVIQ_HUB_URL)) { $env:KLAVIQ_HUB_URL }
              else { $null }

$ai = switch ($path) {
    'stdin' { Get-AppIdentityFromStdin }
    'json'  { Get-AppIdentityFromJsonFile -Path $FromJsonFile }
    default { Get-AppIdentityFromPaste -DefaultUrl $urlDefault }
}

# url may come from -Url / KLAVIQ_HUB_URL even on the json/stdin paths
if ([string]::IsNullOrWhiteSpace($ai.url) -and $urlDefault) { $ai.url = $urlDefault }

if ([string]::IsNullOrWhiteSpace($ai.key)    -or
    [string]::IsNullOrWhiteSpace($ai.secret) -or
    [string]::IsNullOrWhiteSpace($ai.url)) {
    Fail 'key, secret, and url are required (supply url via -Url / KLAVIQ_HUB_URL if not in the seed). Aborting before any disk write.'
}

# ─── Validate by attempting Connect-HubAccount ──────────────────────────────

Write-Host ''
Write-Host 'Validating credentials against Hub…' -ForegroundColor Cyan

try {
    Connect-HubAccount -Url              $ai.url `
                       -ApplicationKey    $ai.key `
                       -ApplicationSecret $ai.secret `
                       -ErrorAction Stop | Out-Null
    Write-Host '  Connect-HubAccount succeeded.' -ForegroundColor Green

    # Interactive paste with no default vault yet: let the operator pick one BY
    # NAME from the accessible list (klaviq stores the GUID). Optional — only
    # needed for bare-GUID deploy manifests; secret://vault/cred refs don't use it.
    if ($path -eq 'paste' -and [string]::IsNullOrWhiteSpace($ai.vaultId)) {
        $ai.vaultId = Select-DefaultVault
    }
} catch {
    Fail "Connect-HubAccount failed: $_. No blob written."
} finally {
    try { Disconnect-HubAccount -ErrorAction SilentlyContinue | Out-Null } catch {}
}

# ─── Serialize + encrypt + write (platform-specific cipher) ────────────────

$payload = $ai | ConvertTo-Json -Compress
$bytes   = $null
$cipher  = $null

$blobDir = Split-Path -Parent $BlobPath
if (-not (Test-Path -LiteralPath $blobDir)) {
    New-Item -ItemType Directory -Path $blobDir -Force | Out-Null
    if ($IsLinux) { & chmod 700 $blobDir }
}

if ($IsLinux) {
    # age (X25519). Recipient public key is derived from the keypair at $KeyPath.
    $recipient = Initialize-AgeKey -KeyPath $KeyPath
    # Pipe payload to `age -r <recipient> -o $BlobPath`. No plaintext on disk.
    $payload | & age -r $recipient -o $BlobPath
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $BlobPath -PathType Leaf)) {
        Fail "age encrypt failed for $BlobPath"
    }
    & chmod 600 $BlobPath
} else {
    # DPAPI CurrentUser scope (Windows).
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
    Add-Type -AssemblyName System.Security
    $cipher = [System.Security.Cryptography.ProtectedData]::Protect(
                  $bytes, $null,
                  [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [System.IO.File]::WriteAllBytes($BlobPath, $cipher)
}

# ─── Round-trip verify (no plaintext printed) ───────────────────────────────

try {
    if ($IsLinux) {
        $rtJson = & age -d -i $KeyPath $BlobPath 2>$null
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($rtJson)) {
            throw "age decrypt failed (exit $LASTEXITCODE)"
        }
        $rt    = $rtJson | ConvertFrom-Json
        $rtJson = $null
    } else {
        $check = [System.IO.File]::ReadAllBytes($BlobPath)
        $plain = [System.Security.Cryptography.ProtectedData]::Unprotect(
                     $check, $null,
                     [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        $rt    = [System.Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json
        [Array]::Clear($plain, 0, $plain.Length)
    }
    if (-not $rt.key -or -not $rt.secret -or -not $rt.url) {
        throw 'round-trip parse missing fields'
    }
} catch {
    Fail "round-trip verification failed: $_. Blob at $BlobPath may be corrupt."
}

# ─── Scrub plaintext from memory ────────────────────────────────────────────

$ai.key    = $null
$ai.secret = $null
$payload   = $null
if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }

# ─── Done ───────────────────────────────────────────────────────────────────

Write-Host ''
Write-Host "✓ Hub auth blob written: $BlobPath" -ForegroundColor Green
if ($IsLinux) {
    Write-Host "  age recipient key:    $KeyPath (0400, owner-only)"
    Write-Host '  Decryptable only by the user holding the matching age identity (this user on this machine).'
} else {
    Write-Host '  DPAPI scope: CurrentUser (decryptable only by this user on this machine)'
}
Write-Host '  Runtime consumers can now read this blob.'
Write-Host ''

}  # end try
finally {
    if ($ShredSource -and $FromJsonFile -and (Test-Path -LiteralPath $FromJsonFile)) {
        Invoke-SecureFileDelete -Path $FromJsonFile
        if (-not (Test-Path -LiteralPath $FromJsonFile)) {
            Write-Host "  -ShredSource: deleted $FromJsonFile" -ForegroundColor Cyan
        }
    }
}
