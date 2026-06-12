#requires -Version 7.0
<#
.SYNOPSIS
    secret:// reference parser.

.DESCRIPTION
    Single function: Parse-KlaviqRef. Validates the strict full form and
    auto-detects GUID vs human-name shape for each of vault and entry.

    Reference grammar (spec architecture/klaviq.md):
        secret://<vault>/<name>
    where <vault> and <name> are each either a 36-char hyphenated GUID or
    a human-readable string. Both forms may be mixed within one reference.

    GUID detection: ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$
#>

$script:GuidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

function Test-IsGuid {
    param([string] $Value)
    return $Value -match $script:GuidPattern
}

function Parse-KlaviqRef {
    # Returns a hashtable: @{ Raw; Vault; Name; VaultIsGuid; NameIsGuid }
    # Throws a [System.ArgumentException] on any malformed input — caller
    # converts to EXIT_GENERIC (1) with a clear stderr message.
    param([Parameter(Mandatory)] [string] $Reference)

    if ([string]::IsNullOrWhiteSpace($Reference)) {
        throw [System.ArgumentException]::new('reference is empty')
    }

    if (-not $Reference.StartsWith('secret://', [System.StringComparison]::Ordinal)) {
        throw [System.ArgumentException]::new("reference must start with 'secret://' (got: $Reference)")
    }

    $rest = $Reference.Substring('secret://'.Length)
    if ([string]::IsNullOrWhiteSpace($rest)) {
        throw [System.ArgumentException]::new("reference is missing vault and name: $Reference")
    }

    $slash = $rest.IndexOf('/')
    if ($slash -lt 0) {
        throw [System.ArgumentException]::new("reference is missing the '/' between vault and name: $Reference")
    }

    $vault = $rest.Substring(0, $slash)
    $name  = $rest.Substring($slash + 1)

    if ([string]::IsNullOrWhiteSpace($vault)) {
        throw [System.ArgumentException]::new("reference has empty vault segment: $Reference")
    }
    if ([string]::IsNullOrWhiteSpace($name)) {
        throw [System.ArgumentException]::new("reference has empty name segment: $Reference")
    }
    # No nested slashes — vault and name are single segments each.
    if ($name.Contains('/')) {
        throw [System.ArgumentException]::new("reference has too many '/' segments (vault and name only): $Reference")
    }

    return @{
        Raw         = $Reference
        Vault       = $vault
        Name        = $name
        VaultIsGuid = (Test-IsGuid $vault)
        NameIsGuid  = (Test-IsGuid $name)
    }
}
