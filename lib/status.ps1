#requires -Version 7.0
<#
.SYNOPSIS
    `klaviq status` verb implementation.

.DESCRIPTION
    Diagnostic snapshot for operators triaging a sick host or onboarding a new one.
    Returns key:value lines on stdout — parseable by `cut -d:` / `awk` etc.

    Always succeeds-on-execution (exit 0) when the auth blob is present and the
    cmd ran to completion, even if Hub is unreachable. Operator parses the
    `hub-reachable:` and other keys to diagnose. The one exception: missing or
    undecryptable auth blob returns EXIT_BOOTSTRAP (5) per spec — that's the
    spec's one "this verb should fail loudly" case.

    Keys emitted on stdout:
      auth-blob-present       true | false
      auth-blob-path          full path
      auth-blob-mtime         ISO-8601 UTC
      hub-url                 from the auth blob
      hub-reachable           true | false
      identity-key            App Identity key from blob (GUID;GUID format, first
                              GUID is the identity's tenant-unique ID; can be
                              correlated with the Hub portal's App Identity list)
      vaults-accessible-count integer (only if hub-reachable=true)
      vaults-accessible       comma-separated names (only if hub-reachable=true)
#>

function Invoke-Status {
    param([string[]] $VerbArgs)

    if ($VerbArgs -and $VerbArgs.Count -gt 0) {
        Write-Diag "klaviq status: takes no arguments (got: $($VerbArgs -join ' '))"
        Exit-Klaviq $EXIT_GENERIC
    }

    # Determine auth blob path: KLAVIQ_BLOB_PATH env override > platform default
    if ($env:KLAVIQ_BLOB_PATH) {
        $authBlobPath = $env:KLAVIQ_BLOB_PATH
    } elseif ($IsLinux) {
        $authBlobPath = Join-Path $HOME '.config/klaviq/auth.age'
    } else {
        $authBlobPath = Join-Path $env:LOCALAPPDATA 'klaviq\auth.dat'
    }

    # Check blob presence; if absent, this is the spec's "exit 5 + message" case
    if (-not (Test-Path -LiteralPath $authBlobPath -PathType Leaf)) {
        Write-Diag (Get-BootstrapMissingMessage $authBlobPath)
        Exit-Klaviq $EXIT_BOOTSTRAP
    }

    # Blob exists — collect mtime
    $blobMtime = (Get-Item -LiteralPath $authBlobPath).LastWriteTimeUtc.ToString('o')

    # Try to load auth blob via Get-KlaviqAuth (from auth/Read-HubAuth.ps1)
    # Use the same Read-HubAuth path-resolution logic from resolver.ps1
    $readHubAuth = Join-Path $PSScriptRoot '..\auth\Read-HubAuth.ps1'
    if (-not (Test-Path -LiteralPath $readHubAuth -PathType Leaf)) {
        $readHubAuth = Join-Path $HOME '.local/share/klaviq/Read-HubAuth.ps1'
        if (-not $IsLinux) {
            $readHubAuth = Join-Path $env:LOCALAPPDATA 'klaviq\bin\Read-HubAuth.ps1'
        }
    }
    if (-not (Test-Path -LiteralPath $readHubAuth -PathType Leaf)) {
        Write-Diag "klaviq status: Read-HubAuth.ps1 not found at $readHubAuth (foundation script missing)"
        Exit-Klaviq $EXIT_GENERIC
    }
    . $readHubAuth

    try {
        $auth = Get-KlaviqAuth -BlobPath $authBlobPath
    } catch {
        Write-Diag (Get-BootstrapMissingMessage $authBlobPath)
        Write-Diag "  detail: $($_.Exception.Message)"
        Exit-Klaviq $EXIT_BOOTSTRAP
    }

    # Extract App Identity key prefix (first GUID before ';') for identity-key output
    $identityKey = if ($auth.key -match '^([0-9a-fA-F-]+);') { $matches[1] } else { '<unknown>' }

    # Probe Hub reachability via Connect-HubAccount (any network failure → hub-reachable=false)
    if (-not (Get-Module -ListAvailable -Name 'Devolutions.PowerShell')) {
        Write-Diag "klaviq status: Devolutions.PowerShell module not installed. Run: Install-Module Devolutions.PowerShell -Scope CurrentUser"
        Exit-Klaviq $EXIT_GENERIC
    }
    Import-Module Devolutions.PowerShell -ErrorAction Stop | Out-Null

    $hubReachable = $false
    $vaults = @()
    try {
        Connect-HubAccount -Url $auth.url `
                           -ApplicationKey $auth.key `
                           -ApplicationSecret $auth.secret `
                           -ErrorAction Stop | Out-Null
        $hubReachable = $true
        try {
            $vaults = @(Get-HubVault -ErrorAction Stop | Sort-Object Name)
        } catch {
            # connected but vault enumeration failed — leave list empty, note in stderr
            Write-Diag "klaviq status: warning — connected but Get-HubVault failed: $($_.Exception.Message)"
        }
    } catch {
        # Could be network OR auth failure. Stderr diagnostic; hub-reachable=false either way.
        Write-Diag "klaviq status: Connect-HubAccount failed: $($_.Exception.Message)"
    } finally {
        try { Disconnect-HubAccount -ErrorAction SilentlyContinue | Out-Null } catch {}
    }

    # Emit key:value lines on stdout (no trailing-newline-discipline concern for status —
    # multi-line output IS the contract here; use Write-Value for each line plus newlines)
    $out = New-Object System.Text.StringBuilder
    [void]$out.AppendLine("auth-blob-present: true")
    [void]$out.AppendLine("auth-blob-path: $authBlobPath")
    [void]$out.AppendLine("auth-blob-mtime: $blobMtime")
    [void]$out.AppendLine("hub-url: $($auth.url)")
    [void]$out.AppendLine("hub-reachable: $($hubReachable.ToString().ToLower())")
    [void]$out.AppendLine("identity-key: $identityKey")
    if ($hubReachable) {
        [void]$out.AppendLine("vaults-accessible-count: $($vaults.Count)")
        $vaultNames = ($vaults | ForEach-Object { $_.Name }) -join ','
        [void]$out.AppendLine("vaults-accessible: $vaultNames")
    } else {
        [void]$out.AppendLine("vaults-accessible-count: 0")
        [void]$out.AppendLine("vaults-accessible: ")
    }

    Write-Value ($out.ToString())
    Exit-Klaviq $EXIT_OK
}
