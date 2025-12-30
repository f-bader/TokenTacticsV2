<#
.SYNOPSIS
    Creates FIDO2 Signature for authentication assertion.

.DESCRIPTION
    This function generates a FIDO2 signature for authentication assertions using the provided challenge, origin,
    authenticator data, and private key in PEM format. It constructs the ClientDataJSON, hashes it, and signs the
    combined Authenticator Data and Client Data Hash using ECDSA with SHA-256.

.PARAMETER Challenge
    The base64url-encoded challenge string received from the server.

.PARAMETER Origin
    The origin (usually the URL) associated with the authentication request.

.PARAMETER AuthDataBytes
    The byte array representing the Authenticator Data structure.

.PARAMETER PrivateKeyPem
    The private key in PEM format used for signing the data.

.EXAMPLE
    $origin = "https://login.microsoft.com"
    $challenge = "randomlyGeneratedChallengeString"
    $authData = New-FidoAuthenticatorData -RpId "login.microsoft.com"
    $privateKeyPem = Get-Content -Raw -Path "C:\path\to\privatekey.pem"
    $signatureData = New-FidoSignature -Challenge $challenge -Origin $origin -AuthDataBytes $authData -PrivateKeyPem $privateKeyPem
    This command generates the FIDO2 signature and client data for the given challenge, origin, authenticator data, and private key.

.NOTES
    Part of TokenTacticsV2
    https://github.com/f-bader/TokenTacticsV2
#>
function New-FidoSignature {
    param(
        [Parameter(Mandatory)]
        [string]$Challenge,
        [Parameter(Mandatory)]
        [string]$Origin,
        [Parameter(Mandatory)]
        [byte[]]$AuthDataBytes,
        [Parameter(Mandatory)]
        [string]$PrivateKeyPem
    )

    # 1. ClientDataJSON
    $clientData = [ordered]@{
        challenge   = $Challenge
        crossOrigin = $false
        origin      = $Origin
        type        = "webauthn.get"
    }
    # Compress JSON to remove whitespace (Standard Requirement)
    $clientJson = $clientData | ConvertTo-Json -Compress -Depth 10
    $clientBytes = [System.Text.Encoding]::UTF8.GetBytes($clientJson)
    $clientHash = [System.Security.Cryptography.SHA256]::HashData($clientBytes)

    # 2. Sign (AuthData + ClientDataHash)
    $dataToSign = $AuthDataBytes + $clientHash

    $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
    $ecdsa.ImportFromPem($PrivateKeyPem)

    # 3. Generate Signature (DER Sequence)
    $sigBytes = $ecdsa.SignData(
        $dataToSign, 
        [System.Security.Cryptography.HashAlgorithmName]::SHA256, 
        [System.Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence
    )

    return @{
        Signature  = $sigBytes
        ClientData = $clientBytes
    }
}