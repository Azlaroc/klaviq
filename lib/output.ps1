#requires -Version 7.0
<#
.SYNOPSIS
    Output discipline + exit code constants for klaviq.

.DESCRIPTION
    Dot-sourced by klaviq.ps1. Provides:

    - Exit-code constants matching the spec (architecture/klaviq.md):
        0 ok / 1 generic / 2 not-found / 3 denied / 4 hub-unreachable / 5 bootstrap-missing
    - Write-Value : stdout = value bytes only, NO trailing newline. Bypasses pwsh's
      Write-Output / Write-Host so consumers piping into xxd / jq / openssl get
      exactly the bytes Hub returned, nothing more.
    - Write-Diag  : stderr = diagnostics. Never contains secret values.
    - Exit-Klaviq : forces process exit with the given code (works from inside
      functions in dot-sourced scripts, where `exit` would only return from
      the function).
    - Operator-facing error strings, centralized so message phrasing stays consistent
      with the spec.
#>

# Exit codes — frozen per spec, do not renumber.
$script:EXIT_OK           = 0
$script:EXIT_GENERIC      = 1
$script:EXIT_NOT_FOUND    = 2
$script:EXIT_DENIED       = 3
$script:EXIT_UNREACHABLE  = 4
$script:EXIT_BOOTSTRAP    = 5

# Force UTF-8 on stdout so non-ASCII secret bytes round-trip cleanly.
$OutputEncoding = [System.Text.Encoding]::UTF8

function Write-Value {
    # Writes value bytes to stdout with NO trailing newline.
    # Bypasses pwsh's Write-Output/Write-Host pipeline so the bytes hit the
    # process's stdout stream verbatim — pipeable into xxd / jq / openssl / file.
    param([Parameter(Mandatory)] [string] $Value)
    [Console]::Out.Write($Value)
    [Console]::Out.Flush()
}

function Write-Diag {
    # Writes a diagnostic line to stderr. Never include secret values here.
    param([Parameter(Mandatory)] [string] $Message)
    [Console]::Error.WriteLine($Message)
}

function Exit-Klaviq {
    # Force-exits the process with a specific code. Use this rather than `exit $code`
    # from inside dot-sourced functions, where `exit` only returns from the function.
    param([Parameter(Mandatory)] [int] $Code)
    [Environment]::Exit($Code)
}

# ─── Operator-facing error strings ──────────────────────────────────────────

function Get-BootstrapMissingMessage {
    # Returned on EXIT_BOOTSTRAP (5). The exact wording is part of the operator
    # experience — keep aligned with the spec's failure-modes table.
    param([string] $BlobPath)
    if (-not $BlobPath) {
        if ($IsLinux) { $BlobPath = Join-Path $HOME '.config/klaviq/auth.age' }
        else          { $BlobPath = Join-Path $env:LOCALAPPDATA 'klaviq\auth.dat' }
    }
    return "klaviq: no auth blob found at $BlobPath — run 'klaviq bootstrap' to seed it"
}

function Get-NotFoundMessage {
    param([string] $Ref)
    return "klaviq: reference not found: $Ref (verify vault and entry name; identity may not see the entry — try ``klaviq list``)"
}

function Get-DeniedMessage {
    param([string] $Ref)
    return "klaviq: access denied: $Ref (identity lacks read permission on this vault or entry)"
}

function Get-UnreachableMessage {
    param([string] $Url)
    return "klaviq: Hub unreachable at $Url (network outage, Hub-side outage, or firewall blocking 443)"
}
