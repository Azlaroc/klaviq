#requires -Version 7.0
<#
.SYNOPSIS
    `klaviq run` verb implementation.

.DESCRIPTION
    Subshell launcher with secret:// references injected as env vars.

      klaviq run KEY=secret://vault/name [KEY=secret://...] -- <cmd> [args]

    Workflow per spec:
      1. Parse all KEY=ref pairs before `--`
      2. Resolve every reference via the existing resolver pipeline
      3. If ANY resolve fails → exit with appropriate code (1/2/3/4/5), cmd NEVER runs
      4. All succeeded → set env vars, exec cmd, pass through child exit code

    Use case: MCP launchers, ad-hoc scripts, any consumer that wants secrets
    as env vars without exposing them in compose files or argv. Replaces the
    pattern of "per-launcher pwsh boilerplate that fetches secrets + sets env".

    NOTE on docker-compose: secrets injected this way are visible in
    `docker inspect`. For docker-compose services where that exposure matters,
    use `klaviq deploy` (file-mount pattern) instead. `klaviq run` is the
    right fit for standalone processes, MCP launchers, and scripts.
#>

function Invoke-Run {
    param([string[]] $VerbArgs)

    if (-not $VerbArgs -or $VerbArgs.Count -eq 0) {
        Write-Diag "klaviq run: usage: klaviq run KEY=secret://vault/name [KEY=...] -- <cmd> [args]"
        Exit-Klaviq $EXIT_GENERIC
    }

    # ─── Find the '--' separator ──────────────────────────────────────
    $sepIdx = -1
    for ($i = 0; $i -lt $VerbArgs.Count; $i++) {
        if ($VerbArgs[$i] -eq '--') { $sepIdx = $i; break }
    }
    if ($sepIdx -lt 0) {
        Write-Diag "klaviq run: missing '--' separator. Usage: klaviq run KEY=secret://... -- <cmd> [args]"
        Exit-Klaviq $EXIT_GENERIC
    }
    if ($sepIdx -eq 0) {
        Write-Diag "klaviq run: at least one KEY=secret://... pair required before '--'"
        Exit-Klaviq $EXIT_GENERIC
    }
    if ($sepIdx -ge $VerbArgs.Count - 1) {
        Write-Diag "klaviq run: no command after '--'"
        Exit-Klaviq $EXIT_GENERIC
    }

    # Pre-declare with @() and assign via separate statements (NOT via if-expression
    # return). PowerShell unwraps single-element arrays at if-expression boundaries
    # back to scalars even with the @() cast inside the branch; separate-statement
    # assignment preserves array shape. Without this, single-arg cmds like
    # `-- github-mcp-server.exe stdio` would splat 'stdio' character-by-character
    # via `& $cmd @cmdArgs` → child sees args=['s','t','d','i','o'].
    $envPairs = @()
    if ($sepIdx -gt 0) {
        $envPairs = @($VerbArgs[0..($sepIdx - 1)])
    }
    $cmd = $VerbArgs[$sepIdx + 1]
    $cmdArgs = @()
    if ($sepIdx + 2 -le $VerbArgs.Count - 1) {
        $cmdArgs = @($VerbArgs[($sepIdx + 2)..($VerbArgs.Count - 1)])
    }

    # ─── Parse KEY=ref pairs (validate shape; defer resolution) ──────
    $assignments = [ordered]@{}
    foreach ($pair in $envPairs) {
        $eqIdx = $pair.IndexOf('=')
        if ($eqIdx -le 0) {
            Write-Diag "klaviq run: malformed env-var assignment '$pair' (expected KEY=secret://...)"
            Exit-Klaviq $EXIT_GENERIC
        }
        $key = $pair.Substring(0, $eqIdx)
        $ref = $pair.Substring($eqIdx + 1)
        if ([string]::IsNullOrWhiteSpace($key)) {
            Write-Diag "klaviq run: empty KEY in '$pair'"
            Exit-Klaviq $EXIT_GENERIC
        }
        if (-not $ref.StartsWith('secret://', [System.StringComparison]::Ordinal)) {
            Write-Diag "klaviq run: KEY '$key' value must be a secret:// reference (got: $ref)"
            Exit-Klaviq $EXIT_GENERIC
        }
        if ($assignments.Contains($key)) {
            Write-Diag "klaviq run: KEY '$key' specified multiple times"
            Exit-Klaviq $EXIT_GENERIC
        }
        $assignments[$key] = $ref
    }

    # ─── Resolve ALL refs BEFORE exec (any failure = cmd never runs) ─
    $auth = $null
    $resolved = [ordered]@{}
    $currentKey = '<connect>'
    $currentRef = '<connect>'
    try {
        $auth = Connect-KlaviqSession
        foreach ($key in $assignments.Keys) {
            $currentKey = $key
            $currentRef = $assignments[$key]
            $parsed = Parse-KlaviqRef -Reference $currentRef
            $entry = Resolve-EntryByRef -Auth $auth -ParsedRef $parsed
            $value = Get-KlaviqValue -Resolved $entry
            if ([string]::IsNullOrEmpty($value)) {
                throw [System.InvalidOperationException]::new("entry '$currentRef' (KEY=$currentKey) resolved to an empty value")
            }
            $resolved[$key] = $value
        }
    }
    catch [System.ArgumentException] {
        Write-Diag "klaviq run: KEY=$currentKey ref parse failed: $($_.Exception.Message)"
        Exit-Klaviq $EXIT_GENERIC
    }
    catch [KlaviqBootstrapException] {
        Write-Diag (Get-BootstrapMissingMessage)
        Exit-Klaviq $EXIT_BOOTSTRAP
    }
    catch [KlaviqNotFoundException] {
        Write-Diag (Get-NotFoundMessage $currentRef)
        Write-Diag "  KEY=$currentKey detail: $($_.Exception.Message)"
        Exit-Klaviq $EXIT_NOT_FOUND
    }
    catch [KlaviqDeniedException] {
        Write-Diag (Get-DeniedMessage $currentRef)
        Write-Diag "  KEY=$currentKey detail: $($_.Exception.Message)"
        Exit-Klaviq $EXIT_DENIED
    }
    catch [KlaviqUnreachableException] {
        $url = if ($auth) { $auth.url } else { '<unknown>' }
        Write-Diag (Get-UnreachableMessage $url)
        Write-Diag "  KEY=$currentKey detail: $($_.Exception.Message)"
        Exit-Klaviq $EXIT_UNREACHABLE
    }
    catch {
        Write-Diag "klaviq run: KEY=${currentKey}: $($_.Exception.Message)"
        Exit-Klaviq $EXIT_GENERIC
    }
    finally {
        try { Disconnect-HubAccount -ErrorAction SilentlyContinue | Out-Null } catch {}
    }

    # ─── All resolved. Set env vars on THIS process, exec child ──────
    # Set on Process scope so the child inherits via the & call operator.
    foreach ($key in $resolved.Keys) {
        [Environment]::SetEnvironmentVariable($key, $resolved[$key], 'Process')
    }
    # Drop the hashtable references — env vars own the secret lifetime now.
    # Parent pwsh terminates after Exit-Klaviq; env block is destroyed with the process.
    $resolved.Clear()

    # Exec child. PowerShell's & operator propagates env vars to the child
    # (process-scoped env vars are part of the launched-process environment).
    & $cmd @cmdArgs
    Exit-Klaviq $LASTEXITCODE
}
