#!/usr/bin/env pwsh
#requires -Version 7.0
<#
.SYNOPSIS
    klaviq — universal CLI for resolving Devolutions Hub-stored secrets.

.DESCRIPTION
    Verb dispatcher. v1 verbs:

        klaviq bootstrap [-ManualPaste | -FromStdin | -FromJsonFile <file>] [-Url <url>]
            One-time setup: capture a Hub Application Identity into the local
            OS-encrypted auth blob (forwards to auth/Bootstrap-HubAuth.ps1).

        klaviq get <secret://vault/name>
            Print resolved value bytes to stdout (no trailing newline).

        klaviq run KEY=secret://vault/name [KEY=...] -- <cmd> [args]
            Resolve refs, inject as env vars, exec cmd, pass through child exit.

        klaviq deploy <service-dir> [-NoRecreate]
            Read <service-dir>/.klaviq.yml, materialize secrets to /run/klaviq/
            (Linux) or %LOCALAPPDATA%\klaviq\runtime\ (Windows), recycle the
            compose service. -NoRecreate refreshes files without recycle.

        klaviq list [--vault <name>]
            Enumerate vaults the identity can see, or entries within a named vault.

        klaviq status
            Diagnostic snapshot: auth-blob, hub-reachable, vaults-accessible.

    Spec: README.md
    ADR : README.md

    Exit codes (frozen per spec):
        0 ok / 1 generic / 2 not-found / 3 denied / 4 hub-unreachable / 5 bootstrap-missing

.NOTES
    Output discipline: stdout = value bytes only (no decoration), stderr = diagnostics.
    Never logs secret values. Never caches resolved values between fetches.
#>

# No [CmdletBinding()] + no declared verb-args param. Both are intentional:
# pwsh's parameter binder (when invoked via `pwsh -File`) tries to interpret
# `--` as a parameter-name marker, and CmdletBinding's common parameters (-Verbose,
# -Debug, -ErrorAction, etc.) make `--` ambiguous against an empty suffix. Dropping
# CmdletBinding + ValueFromRemainingArguments and reading $args directly lets `--`
# (a required separator for `klaviq run`) flow through as a normal positional arg.
param()
# Read everything from $args (auto-variable). With empty param(), pwsh has nothing
# to bind positional args to, so all args land in $args verbatim — including the
# `--` separator that pwsh's parameter binder otherwise tries to interpret as a
# parameter-name marker.
$Verb = if ($args.Count -gt 0) { $args[0] } else { $null }
$VerbArgs = if ($args.Count -gt 1) { @($args[1..($args.Count - 1)]) } else { @() }

$ErrorActionPreference = 'Stop'

# ─── Load libs ──────────────────────────────────────────────────────────────
$libDir = Join-Path $PSScriptRoot 'lib'
. (Join-Path $libDir 'output.ps1')
. (Join-Path $libDir 'parser.ps1')
. (Join-Path $libDir 'resolver.ps1')
. (Join-Path $libDir 'status.ps1')
. (Join-Path $libDir 'list.ps1')
. (Join-Path $libDir 'run.ps1')
. (Join-Path $libDir 'deploy.ps1')

# ─── Verb dispatch ──────────────────────────────────────────────────────────

function Invoke-Get {
    param([string[]] $VerbArgs)

    if ($null -eq $VerbArgs -or $VerbArgs.Count -ne 1) {
        Write-Diag 'klaviq get: expected exactly one argument: <secret://vault/name>'
        Exit-Klaviq $EXIT_GENERIC
    }
    $ref = $VerbArgs[0]

    # Parse
    try {
        $parsed = Parse-KlaviqRef -Reference $ref
    } catch [System.ArgumentException] {
        Write-Diag "klaviq get: $($_.Exception.Message)"
        Exit-Klaviq $EXIT_GENERIC
    }

    # Connect + resolve + extract — single dispatch tree for all known failure modes
    $auth = $null
    try {
        $auth     = Connect-KlaviqSession
        $resolved = Resolve-EntryByRef -Auth $auth -ParsedRef $parsed
        $value    = Get-KlaviqValue -Resolved $resolved
    }
    catch [KlaviqBootstrapException] {
        Write-Diag (Get-BootstrapMissingMessage)
        Exit-Klaviq $EXIT_BOOTSTRAP
    }
    catch [KlaviqNotFoundException] {
        Write-Diag (Get-NotFoundMessage $ref)
        Write-Diag "  detail: $($_.Exception.Message)"
        Exit-Klaviq $EXIT_NOT_FOUND
    }
    catch [KlaviqDeniedException] {
        Write-Diag (Get-DeniedMessage $ref)
        Write-Diag "  detail: $($_.Exception.Message)"
        Exit-Klaviq $EXIT_DENIED
    }
    catch [KlaviqUnreachableException] {
        $url = if ($auth) { $auth.url } else { '<unknown>' }
        Write-Diag (Get-UnreachableMessage $url)
        Write-Diag "  detail: $($_.Exception.Message)"
        Exit-Klaviq $EXIT_UNREACHABLE
    }
    catch {
        Write-Diag "klaviq get: $($_.Exception.Message)"
        Exit-Klaviq $EXIT_GENERIC
    }
    finally {
        # Always disconnect, regardless of success/failure.
        try { Disconnect-HubAccount -ErrorAction SilentlyContinue | Out-Null } catch {}
    }

    if ([string]::IsNullOrEmpty($value)) {
        Write-Diag "klaviq get: resolved entry has empty value (check Hub entry contents)"
        Exit-Klaviq $EXIT_GENERIC
    }

    Write-Value $value
    Exit-Klaviq $EXIT_OK
}

function Invoke-Bootstrap {
    param([string[]] $VerbArgs)

    # Thin forwarder to auth/Bootstrap-HubAuth.ps1 — keeps bootstrap a first-class,
    # discoverable verb while the script stays usable standalone.
    #
    # Forwarded as a CHILD `pwsh -File` (NOT an in-process `& script @args`): array
    # splatting into an in-process call binds POSITIONALLY and mangles named flags,
    # whereas `pwsh -File` re-parses the trailing args as named command-line tokens.
    # The child inherits stdin, so both the hidden paste prompts and the -FromStdin
    # pipe keep working.
    $bootstrap = Join-Path $PSScriptRoot 'auth' 'Bootstrap-HubAuth.ps1'
    if (-not (Test-Path -LiteralPath $bootstrap -PathType Leaf)) {
        Write-Diag "klaviq bootstrap: Bootstrap-HubAuth.ps1 not found at $bootstrap"
        Exit-Klaviq $EXIT_GENERIC
    }
    try {
        & pwsh -NoProfile -File $bootstrap @VerbArgs
        Exit-Klaviq ([int]$LASTEXITCODE)
    } catch {
        # pwsh 7.4+ throws on a native non-zero exit under ErrorActionPreference=Stop;
        # the child already printed its own diagnostic — just surface its exit code.
        Exit-Klaviq ([int]$(if ($LASTEXITCODE) { $LASTEXITCODE } else { $EXIT_GENERIC }))
    }
}

function Show-Usage {
    [Console]::Error.WriteLine(@'
klaviq — universal CLI for resolving Devolutions Hub-stored secrets

USAGE:
    klaviq <verb> [args]

VERBS:
    bootstrap [-ManualPaste|-FromStdin|-FromJsonFile <f>] [-Url <u>]   seed the auth blob (one-time setup)
    get <secret://vault/name>                 resolve one reference to stdout
    run KEY=<secret://...> -- <cmd> [args]    inject refs as env vars, exec cmd, pass through exit
    deploy <service-dir> [-NoRecreate]        materialize manifest secrets + recycle compose service
    list [--vault <name>]                     enumerate vaults or entries (tab-separated)
    status                                    diagnostic snapshot (key:value on stdout)

EXIT CODES:
    0  ok
    1  generic failure
    2  reference not found
    3  access denied
    4  Hub unreachable
    5  bootstrap blob missing — run 'klaviq bootstrap'

SPEC:
    README.md
'@)
}

# ─── Main ───────────────────────────────────────────────────────────────────

if (-not $Verb -or $Verb -in @('-h', '--help', 'help')) {
    Show-Usage
    Exit-Klaviq $EXIT_OK
}

switch ($Verb) {
    'bootstrap' { Invoke-Bootstrap -VerbArgs $VerbArgs }
    'get'    { Invoke-Get -VerbArgs $VerbArgs }
    'run'    { Invoke-Run    -VerbArgs $VerbArgs }
    'deploy' { Invoke-Deploy -VerbArgs $VerbArgs }
    'list'   { Invoke-List   -VerbArgs $VerbArgs }
    'status' { Invoke-Status -VerbArgs $VerbArgs }
    default {
        Write-Diag "klaviq: unknown verb '$Verb'"
        Show-Usage
        Exit-Klaviq $EXIT_GENERIC
    }
}
