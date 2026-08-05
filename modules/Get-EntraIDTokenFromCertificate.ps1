function Get-EntraIDTokenFromCertificate {
    <#
    .SYNOPSIS
        Acquires an Entra ID application token with a certificate client assertion.

    .DESCRIPTION
        Resolves an RSA certificate from a Windows personal certificate store, signs
        an RS256 client assertion with its private key, and exchanges that assertion
        through the OAuth 2.0 client credentials flow. TPM-backed certificates sign
        through the Microsoft Platform Crypto Provider without exporting their key.

    .PARAMETER TenantId
        The Microsoft Entra tenant ID or domain.

    .PARAMETER ClientId
        The application (client) ID registered in Microsoft Entra ID.

    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate registered on the application.

    .PARAMETER Scope
        The application permission scope to request. This must use the .default suffix.

    .PARAMETER CertStoreLocation
        The personal certificate store containing the certificate.

    .EXAMPLE
        Get-EntraIDTokenFromCertificate `
            -TenantId 'contoso.onmicrosoft.com' `
            -ClientId '00000000-0000-0000-0000-000000000000' `
            -CertificateThumbprint '0123456789ABCDEF0123456789ABCDEF01234567'

    .NOTES
        Upload the corresponding public .cer file to the Entra ID App Registration
        before requesting a token.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateThumbprint,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Scope = 'https://graph.microsoft.com/.default',

        [Parameter()]
        [ValidateSet('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')]
        [string]$CertStoreLocation = 'Cert:\CurrentUser\My'
    )

    if ($env:OS -ne 'Windows_NT') {
        throw 'Get-EntraIDTokenFromCertificate requires a Windows certificate store.'
    }

    $normalizedThumbprint = ($CertificateThumbprint -replace '\s', '').ToUpperInvariant()
    if ($normalizedThumbprint.Length % 2 -ne 0 -or $normalizedThumbprint -notmatch '^[0-9A-F]+$') {
        throw "Certificate thumbprint '$CertificateThumbprint' is not valid hexadecimal."
    }

    $certificatePath = "$CertStoreLocation\$normalizedThumbprint"
    try {
        $certificate = Get-Item -Path $certificatePath -ErrorAction Stop
    } catch {
        throw "Certificate '$normalizedThumbprint' was not found at '$CertStoreLocation'. $($_.Exception.Message)"
    }

    $now = [DateTimeOffset]::UtcNow
    if ($certificate.NotBefore.ToUniversalTime() -gt $now.UtcDateTime -or $certificate.NotAfter.ToUniversalTime() -lt $now.UtcDateTime) {
        throw "Certificate '$normalizedThumbprint' is not currently valid."
    }
    if (-not $certificate.HasPrivateKey) {
        throw "Certificate '$normalizedThumbprint' does not have an accessible private key."
    }

    try {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
    } catch {
        throw "Certificate '$normalizedThumbprint' does not expose an RSA private key. $($_.Exception.Message)"
    }

    if ($null -eq $rsa) {
        throw "Certificate '$normalizedThumbprint' does not expose an RSA private key."
    }

    try {
        $thumbprintBytes = [byte[]]::new($normalizedThumbprint.Length / 2)
        for ($index = 0; $index -lt $normalizedThumbprint.Length; $index += 2) {
            $thumbprintBytes[$index / 2] = [Convert]::ToByte($normalizedThumbprint.Substring($index, 2), 16)
        }

        $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        $header = [ordered]@{
            alg = 'RS256'
            typ = 'JWT'
            x5t = ConvertTo-Base64Url -Bytes $thumbprintBytes
        }
        $payload = [ordered]@{
            aud = $tokenEndpoint
            iss = $ClientId
            sub = $ClientId
            jti = [guid]::NewGuid().ToString()
            nbf = $now.ToUnixTimeSeconds()
            exp = $now.AddMinutes(10).ToUnixTimeSeconds()
        }

        $headerBytes = [System.Text.Encoding]::UTF8.GetBytes(($header | ConvertTo-Json -Compress))
        $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress))
        $unsignedAssertion = "$(ConvertTo-Base64Url -Bytes $headerBytes).$(ConvertTo-Base64Url -Bytes $payloadBytes)"
        $signature = $rsa.SignData(
            [System.Text.Encoding]::UTF8.GetBytes($unsignedAssertion),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $clientAssertion = "$unsignedAssertion.$(ConvertTo-Base64Url -Bytes $signature)"

        $body = @{
            client_id             = $ClientId
            scope                 = $Scope
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $clientAssertion
            grant_type            = 'client_credentials'
        }

        $global:response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri $tokenEndpoint -Body $body -ErrorAction Stop
        Write-Output $global:response
    } finally {
        $rsa.Dispose()
    }
}
