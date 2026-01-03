<#
.SYNOPSIS
    Creates FIDO2 Authenticator Data structure.

.DESCRIPTION
    This function generates the Authenticator Data structure used in FIDO2 authentication.
    It includes the RP ID hash, flags, and signature counter.

.PARAMETER RpId
    The relying party identifier (RP ID) for which the authenticator data is being generated.

.PARAMETER SignCount
    The signature counter value.
    Defaults to 0.

.PARAMETER Flags
    The flags byte indicating user presence and user verification status.
    Defaults to 0x05 (user present and user verified).

.EXAMPLE
    $authData = New-FidoAuthenticatorData -RpId "example.com" -SignCount 1 -Flags 0x05
    This command creates the authenticator data for the RP ID "example.com" with a signature count of 1 and flags set to indicate user presence and verification.

.NOTES
    Part of TokenTacticsV2
    https://github.com/f-bader/TokenTacticsV2
#>
function New-FidoAuthenticatorData {
    param(
        [Parameter(Mandatory)]
        [string]$RpId,

        [Parameter(Mandatory = $false)]
        [int]$SignCount = 0,

        [Parameter(Mandatory = $false)]
        [ValidateSet(0x01, 0x04, 0x05)]
        [byte]$Flags = 0x05
    )

    # 1. RP ID Hash (32 bytes)
    $rpIdBytes = [System.Text.Encoding]::UTF8.GetBytes($RpId)
    $rpIdHash = [System.Security.Cryptography.SHA256]::HashData($rpIdBytes)

    # 2. Flags (1 byte)

    # 3. Counter (Big Endian)
    $cntBytes = [BitConverter]::GetBytes([int]$SignCount)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($cntBytes) }

    # Combine
    $authData = [byte[]]::new(37)
    [Array]::Copy($rpIdHash, 0, $authData, 0, 32)
    $authData[32] = $Flags
    [Array]::Copy($cntBytes, 0, $authData, 33, 4)

    return $authData
}