#requires -Version 7.0
<#
.SYNOPSIS
    `klaviq deploy` verb implementation.

.DESCRIPTION
    Docker-compose secret materialization with container recycle.

      klaviq deploy <service-dir> [-NoRecreate]

    Workflow per spec:
      1. Read <service-dir>/.klaviq.yml manifest (YAML)
      2. Open ONE Hub session for all secrets in the manifest
      3. For each ref, resolve + atomic-write to materialization root
            Linux  : /run/klaviq/<entry-name>   (0400, owned by current user)
            Windows: $env:LOCALAPPDATA\klaviq\runtime\<entry-name>  (current user ACL)
         File name = entry's PsMetadata.Name (matches docker-compose secrets: name)
      4. Unless -NoRecreate, run `docker compose up -d --force-recreate` in <service-dir>

    Manifest format (YAML — both forms accepted, may be mixed):
        secrets:
          - secret://prod/token-grafana-db     # NEW: full reference
          - secret://prod/api-cloudflare-zone
          - 00000000-0000-0000-0000-000000000000              # LEGACY: bare GUID
                                                              # uses auth blob's vault
                                                              # (legacy bare-GUID form;
                                                              #  prefer secret:// refs)

    Single Hub session: no per-secret Connect/Disconnect overhead.
    Atomic write: <name>.tmp.<rnd> → chmod/ACL → mv -f. Never partial-state.

    `-NoRecreate`: useful for rotation testing — refresh secret files without
    recycling the container. Operator runs the container's reload mechanism
    (or accepts staleness until next natural recycle) separately.
#>

# ─── CredentialType extractor (mirrors resolver.ps1, with extra context) ─────
# We don't call Get-KlaviqValue from resolver.ps1 here because the bare-GUID
# code path needs per-entry context (vault-id default from auth blob) that
# Resolve-EntryByRef doesn't expose. Both code paths funnel through this
# extractor for uniformity.
function Get-DeployValue {
    param([Parameter(Mandatory)] $Resolved, [Parameter(Mandatory)] [string] $RefDescription)
    $creds = $Resolved.Connection.Credentials
    if (-not $creds) {
        throw [System.InvalidOperationException]::new("resolved entry has no .Connection.Credentials (ref: $RefDescription)")
    }
    $credType = "$($creds.CredentialType)"
    switch ($credType) {
        'AccessCode' { return $creds.Password }
        'Default'    { return $creds.Password }
        'ApiKey'     { return $creds.APIKey }
        'Custom'     { return $creds.CustomScript }
        default {
            throw [System.InvalidOperationException]::new("unknown CredentialType '$credType' on $RefDescription — extend deploy.ps1 (Get-DeployValue) for this type")
        }
    }
}

function Invoke-Deploy {
    param([string[]] $VerbArgs)

    # ─── Parse args ──────────────────────────────────────────────────
    $serviceDir = $null
    $noRecreate = $false
    foreach ($a in $VerbArgs) {
        switch -Exact ($a) {
            '-NoRecreate'   { $noRecreate = $true }
            '--no-recreate' { $noRecreate = $true }
            default {
                if ($serviceDir) {
                    Write-Diag "klaviq deploy: multiple service-dir args; got '$serviceDir' and '$a'"
                    Exit-Klaviq $EXIT_GENERIC
                }
                $serviceDir = $a
            }
        }
    }
    if (-not $serviceDir) {
        Write-Diag "klaviq deploy: usage: klaviq deploy <service-dir> [-NoRecreate]"
        Exit-Klaviq $EXIT_GENERIC
    }

    $resolved = $null
    try {
        $resolved = (Resolve-Path -LiteralPath $serviceDir -ErrorAction Stop).Path
    } catch {
        Write-Diag "klaviq deploy: service directory not found: $serviceDir"
        Exit-Klaviq $EXIT_GENERIC
    }
    $serviceDir = $resolved
    if (-not (Test-Path -LiteralPath $serviceDir -PathType Container)) {
        Write-Diag "klaviq deploy: not a directory: $serviceDir"
        Exit-Klaviq $EXIT_GENERIC
    }

    $manifestPath = Join-Path $serviceDir '.klaviq.yml'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        Write-Diag "klaviq deploy: manifest not found at $manifestPath (create a .klaviq.yml with a 'secrets:' list)"
        Exit-Klaviq $EXIT_GENERIC
    }

    # ─── YAML parser availability ────────────────────────────────────
    if (-not (Get-Module -ListAvailable -Name 'powershell-yaml')) {
        Write-Diag "klaviq deploy: installing powershell-yaml module (one-time, CurrentUser scope) ..."
        try {
            Install-Module -Name 'powershell-yaml' -Force -Scope CurrentUser -Repository PSGallery -AcceptLicense -ErrorAction Stop | Out-Null
        } catch {
            Write-Diag "klaviq deploy: powershell-yaml install failed: $($_.Exception.Message)"
            Exit-Klaviq $EXIT_GENERIC
        }
    }
    Import-Module 'powershell-yaml' -ErrorAction Stop | Out-Null

    # ─── Parse manifest ──────────────────────────────────────────────
    $manifest = $null
    try {
        $manifest = (Get-Content -LiteralPath $manifestPath -Raw) | ConvertFrom-Yaml
    } catch {
        Write-Diag "klaviq deploy: failed to parse $manifestPath as YAML: $($_.Exception.Message)"
        Exit-Klaviq $EXIT_GENERIC
    }
    if (-not $manifest -or -not $manifest.secrets -or $manifest.secrets.Count -eq 0) {
        Write-Diag "klaviq deploy: $manifestPath has no 'secrets' list (or it is empty)"
        Exit-Klaviq $EXIT_GENERIC
    }
    $secretRefs = @($manifest.secrets | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { "$_" })
    if ($secretRefs.Count -eq 0) {
        Write-Diag "klaviq deploy: $manifestPath has no valid (non-empty) secret refs"
        Exit-Klaviq $EXIT_GENERIC
    }
    Write-Diag "klaviq deploy: manifest: $($secretRefs.Count) secret(s) in $manifestPath"

    # ─── Materialization root ────────────────────────────────────────
    if ($env:KLAVIQ_SECRET_DIR) {
        $secretRoot = $env:KLAVIQ_SECRET_DIR
    } elseif ($IsLinux) {
        $secretRoot = '/run/klaviq'
    } else {
        $secretRoot = Join-Path $env:LOCALAPPDATA 'klaviq\runtime'
    }

    if (-not (Test-Path -LiteralPath $secretRoot)) {
        if ($IsLinux) {
            Write-Diag "klaviq deploy: creating $secretRoot (sudo install -d 700) ..."
            $userName  = (& id -un).Trim()
            $groupName = (& id -gn).Trim()
            & sudo install -d -m 700 -o $userName -g $groupName $secretRoot
            if ($LASTEXITCODE -ne 0) {
                Write-Diag "klaviq deploy: failed to create $secretRoot (sudo install exit $LASTEXITCODE; passwordless sudo required for /run/klaviq)"
                Exit-Klaviq $EXIT_GENERIC
            }
        } else {
            try {
                New-Item -ItemType Directory -Path $secretRoot -Force -ErrorAction Stop | Out-Null
            } catch {
                Write-Diag "klaviq deploy: failed to create $secretRoot : $($_.Exception.Message)"
                Exit-Klaviq $EXIT_GENERIC
            }
        }
    }

    # ─── Hub session: ONE Connect for all secrets ────────────────────
    $auth = $null
    $writtenFiles = @()
    $currentRef = '<connect>'
    try {
        $auth = Connect-KlaviqSession

        foreach ($secretRef in $secretRefs) {
            $currentRef = $secretRef

            # Resolve via the appropriate path:
            #   secret://… → full parser + Resolve-EntryByRef pipeline
            #   bare GUID  → direct Get-HubEntryResolved using auth.vaultId (legacy compat)
            if ($secretRef.StartsWith('secret://', [System.StringComparison]::Ordinal)) {
                $parsed = Parse-KlaviqRef -Reference $secretRef
                $entry  = Resolve-EntryByRef -Auth $auth -ParsedRef $parsed
            } else {
                # Bare GUID assumed. Reject anything else with a clear message.
                if (-not (Test-IsGuid $secretRef)) {
                    throw [System.ArgumentException]::new("manifest entry '$secretRef' is neither a secret:// reference nor a bare GUID")
                }
                if ([string]::IsNullOrWhiteSpace($auth.vaultId)) {
                    throw [System.ArgumentException]::new("manifest entry '$secretRef' is a bare GUID but this auth blob has no default vault — re-bootstrap selecting a default vault, or use a full secret://<vault>/<cred> reference")
                }
                try {
                    $entry = Get-HubEntryResolved -VaultId $auth.vaultId `
                                                  -EntryId ([guid]$secretRef) `
                                                  -ResolveSensitives `
                                                  -ResolvePasswords `
                                                  -ErrorAction Stop
                } catch {
                    $msg = $_.Exception.Message
                    if ($msg -match 'access|denied|permission|forbidden|401|403') {
                        throw [KlaviqDeniedException]::new("Get-HubEntryResolved on $secretRef failed: $msg")
                    }
                    if ($msg -match 'not found|404') {
                        throw [KlaviqNotFoundException]::new("entry $secretRef not found in vault $($auth.vaultId)")
                    }
                    throw [KlaviqUnreachableException]::new("Get-HubEntryResolved failed: $msg")
                }
            }

            $entryName = $entry.PsMetadata.Name
            if ([string]::IsNullOrWhiteSpace($entryName)) {
                throw [System.InvalidOperationException]::new("entry '$secretRef' returned empty PsMetadata.Name")
            }

            $value = Get-DeployValue -Resolved $entry -RefDescription $secretRef
            if ([string]::IsNullOrEmpty($value)) {
                throw [System.InvalidOperationException]::new("entry '$entryName' ($secretRef) resolved to an empty value")
            }

            # Atomic write: tmp → chmod/ACL → mv -f
            $outFile = Join-Path $secretRoot $entryName
            $tmpFile = "{0}.tmp.{1}" -f $outFile, ([Guid]::NewGuid().ToString('N').Substring(0,8))

            try {
                # Write content WITHOUT a trailing newline (consumers like telegraf
                # treat the file as a raw token; a stray \n breaks header signing).
                [System.IO.File]::WriteAllText($tmpFile, $value)

                if ($IsLinux) {
                    & chmod 400 $tmpFile
                    if ($LASTEXITCODE -ne 0) { throw "chmod 400 failed on $tmpFile" }
                    & mv -f $tmpFile $outFile
                    if ($LASTEXITCODE -ne 0) { throw "mv $tmpFile $outFile failed (exit $LASTEXITCODE)" }
                } else {
                    # Windows: set ACL to current user only, then atomic rename.
                    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                    $acl = Get-Acl -LiteralPath $tmpFile
                    $acl.SetAccessRuleProtection($true, $false)
                    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
                    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                        $currentUser,
                        [System.Security.AccessControl.FileSystemRights]::Read,
                        [System.Security.AccessControl.AccessControlType]::Allow)
                    $acl.SetAccessRule($rule)
                    Set-Acl -LiteralPath $tmpFile -AclObject $acl
                    Move-Item -LiteralPath $tmpFile -Destination $outFile -Force -ErrorAction Stop
                }

                $writtenFiles += $outFile
                $credType = "$($entry.Connection.Credentials.CredentialType)"
                Write-Diag ("  -> {0}  ({1}, {2} chars)" -f $outFile, $credType, $value.Length)
            } catch {
                if (Test-Path -LiteralPath $tmpFile) {
                    if ($IsLinux) {
                        & shred -u $tmpFile 2>$null
                        if ($LASTEXITCODE -ne 0) { Remove-Item -LiteralPath $tmpFile -Force -ErrorAction SilentlyContinue }
                    } else {
                        Remove-Item -LiteralPath $tmpFile -Force -ErrorAction SilentlyContinue
                    }
                }
                throw
            } finally {
                $value = $null
            }
            $entry = $null
        }
    }
    catch [System.ArgumentException] {
        Write-Diag "klaviq deploy: $($_.Exception.Message)"
        Exit-Klaviq $EXIT_GENERIC
    }
    catch [KlaviqBootstrapException] {
        Write-Diag (Get-BootstrapMissingMessage)
        Exit-Klaviq $EXIT_BOOTSTRAP
    }
    catch [KlaviqNotFoundException] {
        Write-Diag (Get-NotFoundMessage $currentRef)
        Write-Diag "  detail: $($_.Exception.Message)"
        Exit-Klaviq $EXIT_NOT_FOUND
    }
    catch [KlaviqDeniedException] {
        Write-Diag (Get-DeniedMessage $currentRef)
        Write-Diag "  detail: $($_.Exception.Message)"
        Exit-Klaviq $EXIT_DENIED
    }
    catch [KlaviqUnreachableException] {
        $url = if ($auth) { $auth.url } else { '<unknown>' }
        Write-Diag (Get-UnreachableMessage $url)
        Write-Diag "  ref: $currentRef"
        Write-Diag "  detail: $($_.Exception.Message)"
        Exit-Klaviq $EXIT_UNREACHABLE
    }
    catch {
        Write-Diag "klaviq deploy: ${currentRef}: $($_.Exception.Message)"
        Exit-Klaviq $EXIT_GENERIC
    }
    finally {
        try { Disconnect-HubAccount -ErrorAction SilentlyContinue | Out-Null } catch {}
    }

    Write-Diag "klaviq deploy: $($writtenFiles.Count) secret(s) installed under $secretRoot/"

    # ─── Container recycle ───────────────────────────────────────────
    if ($noRecreate) {
        Write-Diag "klaviq deploy: -NoRecreate: skipping docker compose recreate"
        Exit-Klaviq $EXIT_OK
    }

    Write-Diag "klaviq deploy: docker compose up -d --force-recreate ..."
    Push-Location $serviceDir
    try {
        & docker compose up -d --force-recreate
        if ($LASTEXITCODE -ne 0) {
            Write-Diag "klaviq deploy: docker compose returned exit $LASTEXITCODE"
            Exit-Klaviq $EXIT_GENERIC
        }
    } finally {
        Pop-Location
    }

    Write-Diag "klaviq deploy: done. Check 'docker logs' for service status."
    Exit-Klaviq $EXIT_OK
}
