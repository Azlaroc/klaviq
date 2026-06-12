#requires -Version 7.0
<#
.SYNOPSIS
    `klaviq list` verb implementation.

.DESCRIPTION
    Enumeration verb. Two modes:

      klaviq list                  — list vaults the current identity can see
                                       Output: <vault-name>\t<vault-guid> per line

      klaviq list --vault <name>   — list entries in the named vault
                                       Output: <vault-name>\t<entry-name>\t<entry-guid> per line

    Identity scoping is enforced: vaults the identity can't see are silently
    absent from the no-arg listing (no enumeration leak of denied space).
    Explicit `--vault <denied-name>` returns exit 2 (not-found) since we can't
    distinguish "doesn't exist" from "you can't see it" via the API. If Get-HubEntry
    fails with a permission error (vault visible but entry access denied — rare),
    exit 3.

    Output is tab-separated, parseable by `cut -f1` / `awk` etc.
#>

function Invoke-List {
    param([string[]] $VerbArgs)

    # ─── Parse args ──────────────────────────────────────────────────
    $vaultName = $null
    if ($VerbArgs -and $VerbArgs.Count -gt 0) {
        if ($VerbArgs.Count -eq 2 -and $VerbArgs[0] -eq '--vault') {
            $vaultName = $VerbArgs[1]
            if ([string]::IsNullOrWhiteSpace($vaultName)) {
                Write-Diag "klaviq list: --vault requires a vault name"
                Exit-Klaviq $EXIT_GENERIC
            }
        } else {
            Write-Diag "klaviq list: invalid arguments. Usage: klaviq list [--vault <name>]"
            Exit-Klaviq $EXIT_GENERIC
        }
    }

    # ─── Connect + enumerate ─────────────────────────────────────────
    $auth = $null
    try {
        $auth = Connect-KlaviqSession

        if (-not $vaultName) {
            # Mode 1: list vaults the identity can see
            $vaults = @(Get-HubVault -ErrorAction Stop | Sort-Object Name)
            $out = New-Object System.Text.StringBuilder
            foreach ($v in $vaults) {
                [void]$out.AppendLine("$($v.Name)`t$($v.Id)")
            }
            if ($out.Length -gt 0) {
                Write-Value ($out.ToString())
            }
            # If zero vaults visible (shouldn't happen for any real identity),
            # we still exit 0 with empty stdout — that's a valid "list returned nothing" result.
        } else {
            # Mode 2: list entries in a named vault
            $vaults = @(Get-HubVault -ErrorAction Stop)
            $match = @($vaults | Where-Object { $_.Name -eq $vaultName })
            if (-not $match -or $match.Count -eq 0) {
                throw [KlaviqNotFoundException]::new("vault '$vaultName' not found among accessible vaults")
            }
            if ($match.Count -gt 1) {
                Write-Diag "klaviq list: vault name '$vaultName' is ambiguous (multiple matches in identity's listing); use the GUID form via klaviq get if disambiguation needed"
                Exit-Klaviq $EXIT_GENERIC
            }
            $vaultId = $match[0].Id

            try {
                $entries = @(Get-HubEntry -VaultId ([guid]$vaultId) -ErrorAction Stop)
            } catch {
                $msg = $_.Exception.Message
                if ($msg -match 'access|denied|permission|forbidden|401|403') {
                    throw [KlaviqDeniedException]::new("Get-HubEntry on vault '$vaultName' failed: $msg")
                }
                throw [KlaviqUnreachableException]::new("Get-HubEntry failed: $msg")
            }

            # Entries returned by Get-HubEntry use .PsMetadata.Name and .Entry.Id
            # (NOT .Name and .Id — see resolver.ps1 comment). Sort by name.
            $sorted = $entries | Sort-Object { $_.PsMetadata.Name }
            $out = New-Object System.Text.StringBuilder
            foreach ($e in $sorted) {
                [void]$out.AppendLine("$vaultName`t$($e.PsMetadata.Name)`t$($e.Entry.Id)")
            }
            if ($out.Length -gt 0) {
                Write-Value ($out.ToString())
            }
            # Empty vault → empty stdout, exit 0. (The default [Root] placeholder
            # in fresh vaults is itself an entry and will appear in the listing.)
        }
    }
    catch [KlaviqBootstrapException] {
        Write-Diag (Get-BootstrapMissingMessage)
        Exit-Klaviq $EXIT_BOOTSTRAP
    }
    catch [KlaviqNotFoundException] {
        Write-Diag "klaviq list: $($_.Exception.Message)"
        Exit-Klaviq $EXIT_NOT_FOUND
    }
    catch [KlaviqDeniedException] {
        Write-Diag "klaviq list: access denied"
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
        Write-Diag "klaviq list: $($_.Exception.Message)"
        Exit-Klaviq $EXIT_GENERIC
    }
    finally {
        try { Disconnect-HubAccount -ErrorAction SilentlyContinue | Out-Null } catch {}
    }

    Exit-Klaviq $EXIT_OK
}
