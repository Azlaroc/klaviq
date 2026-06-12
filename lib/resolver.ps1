#requires -Version 7.0
<#
.SYNOPSIS
    Vault + entry lookup and value extraction for klaviq.

.DESCRIPTION
    Three functions, dot-sourced by klaviq.ps1:

    - Connect-KlaviqSession : open ONE Devolutions Hub session for the
      lifetime of a single klaviq invocation. Loads the auth blob via
      Get-KlaviqAuth (from auth/Read-HubAuth.ps1) and calls Connect-HubAccount.
      Returns the auth object for downstream use of $auth.url etc.

    - Resolve-EntryByRef : given a parsed reference (from parser.ps1), look up
      the vault by name OR GUID, then the entry by name OR GUID within that
      vault, and call Get-HubEntryResolved with -ResolveSensitives. Returns
      the resolved entry object.

    - Get-KlaviqValue : extract the secret value bytes from a resolved entry.
      Branches on CredentialType:
          AccessCode → .Connection.Credentials.Password   (Secret, v1 canonical)
          Default    → .Connection.Credentials.Password   (legacy)
          ApiKey     → .Connection.Credentials.APIKey     (legacy)
          Custom     → .Connection.Credentials.CustomScript (legacy blob)
      Unknown types throw — fail loudly per spec.

    All three functions throw [System.Exception]-derived types that klaviq.ps1
    converts to the appropriate EXIT_NOT_FOUND / EXIT_DENIED / EXIT_UNREACHABLE / etc.
#>

# Custom exception types for clean dispatch in klaviq.ps1
class KlaviqNotFoundException : System.Exception {
    KlaviqNotFoundException([string]$message) : base($message) {}
}
class KlaviqDeniedException : System.Exception {
    KlaviqDeniedException([string]$message) : base($message) {}
}
class KlaviqUnreachableException : System.Exception {
    KlaviqUnreachableException([string]$message) : base($message) {}
}
class KlaviqBootstrapException : System.Exception {
    KlaviqBootstrapException([string]$message) : base($message) {}
}

function Connect-KlaviqSession {
    # Loads auth and opens a Hub session. Returns the auth object so callers
    # can pass auth.vaultId / auth.url where needed.
    # Throws KlaviqBootstrapException if the auth blob is missing.
    # Throws KlaviqUnreachableException if Connect-HubAccount fails for network reasons.

    # The auth helper lives in auth/Read-HubAuth.ps1 — dot-source it.
    # PSScriptRoot for THIS file is .../klaviq/lib, so the relative path is ../../auth/Read-HubAuth.ps1.
    $readHubAuth = Join-Path $PSScriptRoot '..\auth\Read-HubAuth.ps1'
    if (-not (Test-Path -LiteralPath $readHubAuth -PathType Leaf)) {
        # Fall back to the installed location on the host (deploy layout).
        $readHubAuth = Join-Path $HOME '.local/share/klaviq/Read-HubAuth.ps1'
        if (-not $IsLinux) {
            $readHubAuth = Join-Path $env:LOCALAPPDATA 'klaviq\bin\Read-HubAuth.ps1'
        }
    }
    if (-not (Test-Path -LiteralPath $readHubAuth -PathType Leaf)) {
        throw [KlaviqBootstrapException]::new("klaviq: Read-HubAuth.ps1 not found at $readHubAuth (foundation script missing)")
    }
    . $readHubAuth

    try {
        $auth = Get-KlaviqAuth
    } catch {
        # Get-KlaviqAuth throws if the blob is missing or undecryptable.
        # Both surface to operator as EXIT_BOOTSTRAP — they're cured by re-running Bootstrap.
        throw [KlaviqBootstrapException]::new($_.Exception.Message)
    }

    if (-not (Get-Module -ListAvailable -Name 'Devolutions.PowerShell')) {
        throw [System.InvalidOperationException]::new('klaviq: Devolutions.PowerShell module not installed. Run: Install-Module Devolutions.PowerShell -Scope CurrentUser')
    }
    Import-Module Devolutions.PowerShell -ErrorAction Stop | Out-Null

    try {
        Connect-HubAccount -Url $auth.url `
                           -ApplicationKey $auth.key `
                           -ApplicationSecret $auth.secret `
                           -ErrorAction Stop | Out-Null
    } catch {
        # Crude classification: network errors → Unreachable; everything else → re-throw as-is
        # (likely auth-blob staleness, surfaces as generic exit 1 to the operator with the
        # Hub-side error message on stderr).
        $msg = $_.Exception.Message
        if ($msg -match '(timed? out|unreachable|connection|resolve|no such host|name or service|dns|network|socket)') {
            throw [KlaviqUnreachableException]::new("Connect-HubAccount failed: $msg")
        }
        throw
    }

    return $auth
}

function Resolve-EntryByRef {
    # Returns the resolved Hub entry object (output of Get-HubEntryResolved).
    # Throws KlaviqNotFoundException / KlaviqDeniedException as appropriate.
    param(
        [Parameter(Mandatory)] $Auth,
        [Parameter(Mandatory)] [hashtable] $ParsedRef
    )

    # ─── Vault lookup ──────────────────────────────────────────────────
    $vaultId = $null
    if ($ParsedRef.VaultIsGuid) {
        # Trust the GUID. We don't pre-validate accessibility — the Get-HubEntryResolved
        # call below surfaces the access error if the identity can't see this vault.
        $vaultId = $ParsedRef.Vault
    } else {
        # Name lookup — enumerate vaults the identity can see, match on Name.
        try {
            $vaults = Get-HubVault -ErrorAction Stop
        } catch {
            throw [KlaviqUnreachableException]::new("Get-HubVault failed: $($_.Exception.Message)")
        }
        $match = $vaults | Where-Object { $_.Name -eq $ParsedRef.Vault }
        if (-not $match) {
            # Could be denied (not in identity's ACL) or genuinely not-found.
            # Spec semantics: silently absent from list = denied/invisible — but from the
            # operator's POV "I asked for X and it's not there" is most useful as NotFound.
            # An explicit denied test would require admin-level visibility we don't have.
            throw [KlaviqNotFoundException]::new("vault '$($ParsedRef.Vault)' not found among accessible vaults")
        }
        if (@($match).Count -gt 1) {
            throw [System.InvalidOperationException]::new("vault name '$($ParsedRef.Vault)' is ambiguous (multiple matches); use the GUID form")
        }
        $vaultId = (@($match)[0]).Id
    }

    # ─── Entry lookup ──────────────────────────────────────────────────
    $entryId = $null
    if ($ParsedRef.NameIsGuid) {
        $entryId = $ParsedRef.Name
    } else {
        # Enumerate entries in the vault, match on Name. The Devolutions cmdlet for
        # this is Get-HubEntry; it returns lightweight metadata (id + name + type) so
        # we can find the GUID without resolving secrets yet.
        try {
            $entries = Get-HubEntry -VaultId $vaultId -ErrorAction Stop
        } catch {
            $msg = $_.Exception.Message
            if ($msg -match 'access|denied|permission|forbidden|401|403') {
                throw [KlaviqDeniedException]::new("Get-HubEntry on vault $vaultId failed: $msg")
            }
            throw [KlaviqUnreachableException]::new("Get-HubEntry failed: $msg")
        }
        # Get-HubEntry returns PSDecryptedEntry objects where the entry name lives at
        # .PsMetadata.Name (NOT .Name) and the entry GUID lives at .Entry.Id (NOT .Id
        # nor .PsMetadata.Id, which is empty).
        # Get-HubVault, by contrast, returns vault objects with .Name and .Id directly —
        # the Devolutions API is inconsistent across the two cmdlets.
        $match = $entries | Where-Object { $_.PsMetadata.Name -eq $ParsedRef.Name }
        if (-not $match) {
            throw [KlaviqNotFoundException]::new("entry '$($ParsedRef.Name)' not found in vault $vaultId")
        }
        if (@($match).Count -gt 1) {
            throw [System.InvalidOperationException]::new("entry name '$($ParsedRef.Name)' is ambiguous in vault $vaultId (multiple matches); use the GUID form")
        }
        $entryId = (@($match)[0]).Entry.Id
    }

    # ─── Resolve (fetch secret values) ─────────────────────────────────
    try {
        $resolved = Get-HubEntryResolved -VaultId $vaultId `
                                         -EntryId $entryId `
                                         -ResolveSensitives `
                                         -ResolvePasswords `
                                         -ErrorAction Stop
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match 'access|denied|permission|forbidden|401|403') {
            throw [KlaviqDeniedException]::new("Get-HubEntryResolved on $entryId failed: $msg")
        }
        if ($msg -match 'not found|404') {
            throw [KlaviqNotFoundException]::new("entry $entryId not found in vault $vaultId")
        }
        throw [KlaviqUnreachableException]::new("Get-HubEntryResolved failed: $msg")
    }

    if (-not $resolved) {
        throw [KlaviqNotFoundException]::new("entry $entryId returned no data from Get-HubEntryResolved")
    }

    return $resolved
}

function Get-KlaviqValue {
    # Extracts the secret value string from a resolved entry, branching on CredentialType.
    # Fails loudly on unknown types.
    param([Parameter(Mandatory)] $Resolved)

    $creds = $Resolved.Connection.Credentials
    if (-not $creds) {
        throw [System.InvalidOperationException]::new("resolved entry has no .Connection.Credentials")
    }
    $credType = "$($creds.CredentialType)"  # stringify enum

    switch ($credType) {
        'AccessCode' { return $creds.Password }     # Secret, v1 canonical
        'Default'    { return $creds.Password }     # legacy
        'ApiKey'     { return $creds.APIKey }       # legacy
        'Custom'     { return $creds.CustomScript } # legacy blob
        default {
            throw [System.InvalidOperationException]::new("unknown CredentialType '$credType' — extend resolver.ps1 (Get-KlaviqValue) for this type")
        }
    }
}
