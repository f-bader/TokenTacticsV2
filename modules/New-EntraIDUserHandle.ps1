<#
.SYNOPSIS
    Generates the FIDO2 user handle for an Entra ID user.

.DESCRIPTION
    Calculates the user handle used in FIDO2/WebAuthn assertions for Entra ID from the
    tenant ID and the user's object ID. The handle is constructed as the byte sequence
    "ON:" + tenant ID (little-endian) + SHA256(user ID little-endian).

    This is a public helper, e.g. to determine the userHandle value required by
    Invoke-EntraIDPasskeyLogin when using a software-based passkey.

.PARAMETER TenantId
    The Entra ID tenant ID (GUID).

.PARAMETER UserId
    The Entra ID object ID (GUID) of the user.

.EXAMPLE
    New-EntraIDUserHandle -TenantId "00000000-0000-0000-0000-000000000001" -UserId "00000000-0000-0000-0000-000000000002"
    Returns the user handle as Base64 and hex encoded strings.

.NOTES
    Part of TokenTacticsV2
    https://github.com/f-bader/TokenTacticsV2

    Based on Generate-UserHandle: https://gist.github.com/f-bader/501aaeb9a79f58359e0a5c2892763a52
#>
function New-EntraIDUserHandle {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [string]$UserId
    )

    # 1. Parse the strings into GUID objects
    try {
        $tenantGuid = [guid]::Parse($TenantId)
        $userGuid = [guid]::Parse($UserId)
    } catch {
        throw "TenantId and UserId must be valid GUIDs. $($_.Exception.Message)"
    }

    # 2. Get the "ON:" static string as a byte array (ASCII)
    $onBytes = [System.Text.Encoding]::ASCII.GetBytes("ON:")

    # 3. Get Tenant ID in little-endian binary presentation
    # (.NET natively exports the first 3 components of a GUID as little-endian)
    $tenantBytes = $tenantGuid.ToByteArray()

    # 4. Get User ID in the same binary presentation and calculate its SHA256 Hash
    $userBytes = $userGuid.ToByteArray()
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $userHashBytes = $sha256.ComputeHash($userBytes)
    $sha256.Dispose()

    # 5. Concatenate the three byte arrays: [ "ON:" + TenantBytes + UserHashBytes ]
    $totalLength = $onBytes.Length + $tenantBytes.Length + $userHashBytes.Length
    $userHandleBytes = [byte[]]::new($totalLength)

    [System.Buffer]::BlockCopy($onBytes, 0, $userHandleBytes, 0, $onBytes.Length)
    [System.Buffer]::BlockCopy($tenantBytes, 0, $userHandleBytes, $onBytes.Length, $tenantBytes.Length)
    [System.Buffer]::BlockCopy($userHashBytes, 0, $userHandleBytes, ($onBytes.Length + $tenantBytes.Length), $userHashBytes.Length)

    # 6. Encode the final output (Base64 is standard for JSON/Auth tokens, Hex provided as backup)
    $userHandleBase64 = [Convert]::ToBase64String($userHandleBytes)
    $userHandleHex = [System.BitConverter]::ToString($userHandleBytes).Replace("-", "").ToLower()

    # Output the results
    [PSCustomObject]@{
        TenantId         = $TenantId
        UserId           = $UserId
        UserHandleBase64 = $userHandleBase64
        UserHandleHex    = $userHandleHex
    }
}
