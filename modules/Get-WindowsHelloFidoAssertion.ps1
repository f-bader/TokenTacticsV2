<#
.SYNOPSIS
    Creates a signed WebAuthn (FIDO2) assertion using a Windows Hello for Business key.

.DESCRIPTION
    Generates a FIDO2 assertion for an Entra ID sign-in challenge using the Windows Hello
    for Business credential of the current user. The private key never leaves the TPM;
    signing is performed through the NCrypt API.

    The Windows Hello for Business certificate is located in the current user's certificate
    store (subject contains "login.windows.net"). The user handle is derived from the
    certificate subject (tenant ID) and the user's object ID. If no user ID is supplied, the
    object ID is derived from the user SID in the certificate subject. The credential ID is
    the Base64Url encoded SHA256 hash of the exported RSA public key blob.

    This command requires Windows and a Windows Hello for Business provisioned user.

    The assertion is returned as a compressed JSON string, so it can easily be transferred
    to the machine running Invoke-EntraIDPasskeyAssertionLogin (e.g. via clipboard).

.PARAMETER Challenge
    The server-issued FIDO2 challenge string, e.g. from Get-EntraIDFido2Challenge.

.PARAMETER UserId
    The Entra ID object ID (GUID) of the user that owns the Windows Hello credential.
    If omitted, the object ID is derived from the user SID in the certificate subject.

.PARAMETER RpId
    The relying party identifier. Defaults to "login.microsoft.com".

.PARAMETER Origin
    The origin of the authentication request. Defaults to "https://login.microsoft.com".

.PARAMETER SignCount
    The signature counter value. Defaults to 0.

.EXAMPLE
    $assertion = Get-WindowsHelloFidoAssertion -Challenge $challenge -UserId "00000000-0000-0000-0000-000000000002"
    Creates a signed assertion that can be passed to Invoke-EntraIDPasskeyAssertionLogin.

.EXAMPLE
    $assertion = Get-WindowsHelloFidoAssertion -Challenge $challenge
    Creates a signed assertion, deriving the object ID from the certificate's user SID.

.NOTES
    Part of TokenTacticsV2
    https://github.com/f-bader/TokenTacticsV2

    Based on fido_assertion.ps1 by Dirk-jan Mollema (@dirkjanm), part of ROADtools,
    released under the MIT license.
    https://github.com/dirkjanm/ROADtools/blob/master/winhello_assertion/fido_assertion.ps1
#>

function ConvertFrom-TTUserSid {
    <#
    .SYNOPSIS
        Converts an Entra ID user SID (S-1-12-1-...) to the user's object ID.
        Private helper for Get-WindowsHelloFidoAssertion.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Sid
    )

    # Entra ID user SIDs encode the object ID as four little-endian UInt32 sub-authorities
    $parts = $Sid.Split('-')
    if ($parts.Count -lt 8 -or $parts[0] -ne 'S' -or $parts[1] -ne '1' -or $parts[2] -ne '12') {
        throw "'$Sid' is not a valid Entra ID user SID (expected format S-1-12-1-...)."
    }

    $bytes = [byte[]]::new(16)
    for ($i = 0; $i -lt 4; $i++) {
        $subAuthority = [uint32]::Parse($parts[4 + $i])
        $subBytes = [BitConverter]::GetBytes($subAuthority)
        if (-not [BitConverter]::IsLittleEndian) { [Array]::Reverse($subBytes) }
        [Array]::Copy($subBytes, 0, $bytes, $i * 4, 4)
    }
    return [Guid]::new($bytes)
}

function Get-WindowsHelloFidoAssertion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Challenge,

        [Parameter(Mandatory = $false)]
        [ValidateScript({
            if ([guid]::TryParse($_, [ref]([guid]::Empty))) { $true }
            else { throw "UserId must be the Entra ID object ID (GUID) of the user, not a UPN. Omit -UserId to derive it from the certificate." }
        })]
        [string]$UserId,

        [Parameter(Mandatory = $false)]
        [string]$RpId = "login.microsoft.com",

        [Parameter(Mandatory = $false)]
        [string]$Origin = "https://login.microsoft.com",

        [Parameter(Mandatory = $false)]
        [int]$SignCount = 0
    )

    if ($env:OS -ne 'Windows_NT') {
        throw 'Get-WindowsHelloFidoAssertion is supported only on Windows.'
    }

    # NCrypt Native API definitions
    if (-not ([System.Management.Automation.PSTypeName]'NCrypt').Type) {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class NCrypt {
    [DllImport("Crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool CertGetCertificateContextProperty(
        IntPtr pCertContext,
        uint dwPropId,
        IntPtr pvData,
        ref uint pcbData
    );

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct CRYPT_KEY_PROV_INFO {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszContainerName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszProvName;
        public uint dwProvType;
        public uint dwFlags;
        public uint cProvParam;
        public IntPtr rgProvParam;
        public uint dwKeySpec;
    }

    [DllImport("ncrypt.dll", SetLastError = true)]
    public static extern int NCryptOpenStorageProvider(
        ref IntPtr phProvider,
        [MarshalAs(UnmanagedType.LPWStr)]
        string pszProviderName,
        uint dwFlags
    );

    [DllImport("ncrypt.dll", SetLastError = true)]
    public static extern int NCryptOpenKey(
        IntPtr hProvider,
        ref IntPtr phKey,
        [MarshalAs(UnmanagedType.LPWStr)]
        string pszKeyName,
        uint dwLegacyKeySpec,
        uint dwFlags
    );

    [DllImport("ncrypt.dll", SetLastError = true)]
    public static extern int NCryptSignHash(
        IntPtr hKey,
        IntPtr pPaddingInfo,
        byte[] pbHashValue,
        int cbHashValue,
        byte[] pbSignature,
        int cbSignature,
        ref int pcbResult,
        int dwFlags
    );

    [DllImport("ncrypt.dll", SetLastError = true)]
    public static extern int NCryptExportKey(
        IntPtr hKey,
        IntPtr hExportKey,
        [MarshalAs(UnmanagedType.LPWStr)]
        string pszBlobType,
        IntPtr pParameterList,
        [MarshalAs(UnmanagedType.LPArray)]
        byte[] pbOutput,
        int cbOutput,
        ref int pcbResult,
        int dwFlags
    );

    [StructLayout(LayoutKind.Sequential)]
    public struct BCRYPT_PKCS1_PADDING_INFO {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pszAlgId;
    }
}
"@
    }

    function Get-Base64UrlEncode {
        param([byte[]]$Bytes)
        $base64 = [Convert]::ToBase64String($Bytes)
        return $base64.Replace('+', '-').Replace('/', '_').Replace('=', '')
    }

    function Convert-GuidToLittleEndian {
        param([Guid]$Guid)
        $bytes = $Guid.ToByteArray()
        return $bytes
    }

    function Get-UserHandleFromCert {
        param($Certificate, $userId)

        # Parse certificate subject
        # Format is typically: CN={sid}/{unknown}/login.windows.net/{tenantId}/{upn}
        $subject = $Certificate.Subject
        Write-Verbose "Certificate Subject: $subject"

        $parts = $subject -split '/'

        if ($parts.Length -lt 3) {
            throw "Cannot parse certificate subject. Expected format: CN={sid}/.../login.windows.net/{tenantId}/{upn}"
        }

        # The tenant ID is the second to last part of the subject
        $tenantId = $parts[-2]
        try {
            $tenantGuid = [Guid]$tenantId
        } catch {
            throw "Failed to parse the tenant ID '$tenantId' from the certificate subject as a GUID."
        }

        if ([string]::IsNullOrWhiteSpace($userId)) {
            # Derive the object ID from the user SID in the certificate subject (first part)
            $sid = $parts[0] -replace '^CN=', ''
            Write-Verbose "Deriving object ID from certificate user SID: $sid"
            $userGuid = ConvertFrom-TTUserSid -Sid $sid
            $userId = $userGuid.ToString()
            Write-Host "$([char]0x2714) Derived object ID from certificate: $userId" -ForegroundColor Green
        } else {
            $userGuid = [Guid]$userId
        }

        Write-Verbose "Tenant ID: $tenantId"
        Write-Verbose "User ID: $userId"

        $tenantBytes = Convert-GuidToLittleEndian -Guid $tenantGuid
        $userBytes = Convert-GuidToLittleEndian -Guid $userGuid

        # Calculate userHandle: "ON:" + tenantId (LE) + SHA256(userId LE)
        $userHandleBytes = [System.Collections.ArrayList]::new()
        [void]$userHandleBytes.AddRange([byte[]][char[]]"ON:")
        [void]$userHandleBytes.AddRange($tenantBytes)

        # Calculate SHA256 of user ID bytes
        $sha256 = [Security.Cryptography.SHA256]::Create()
        $userHash = $sha256.ComputeHash($userBytes)
        [void]$userHandleBytes.AddRange($userHash)
        $sha256.Dispose()

        $userHandle = Get-Base64UrlEncode -Bytes $userHandleBytes.ToArray()

        Write-Verbose "User Handle: $userHandle"

        return @{
            TenantId   = $tenantId
            UserId     = $userId
            UserHandle = $userHandle
        }
    }

    # Main execution
    Write-Host "$([char]0x2718) Looking for Windows Hello certificate..." -ForegroundColor Cyan
    $certs = Get-ChildItem Cert:\CurrentUser\My\ | Where-Object { $_.Subject -like "*login.windows.net*" }

    if ($certs.Count -eq 0) {
        throw "No Windows Hello certificate found"
    }

    $cert = $certs[0]
    Write-Host "$([char]0x2714) Found certificate: $($cert.Subject)" -ForegroundColor Green

    # Extract user info from certificate
    $userInfo = Get-UserHandleFromCert -Certificate $cert -userId $UserId

    # Get key provider info
    $certHandle = $cert.Handle
    $propSize = 0
    $propId = 2  # CERT_KEY_PROV_INFO_PROP_ID

    [void][NCrypt]::CertGetCertificateContextProperty($certHandle, $propId, [IntPtr]::Zero, [ref]$propSize)
    $propBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($propSize)
    [void][NCrypt]::CertGetCertificateContextProperty($certHandle, $propId, $propBuffer, [ref]$propSize)

    $keyProv = [Runtime.InteropServices.Marshal]::PtrToStructure($propBuffer, [Type][NCrypt+CRYPT_KEY_PROV_INFO])
    [Runtime.InteropServices.Marshal]::FreeHGlobal($propBuffer)

    Write-Verbose "Key Container: $($keyProv.pwszContainerName)"
    Write-Verbose "Key Provider: $($keyProv.pwszProvName)"

    # Open NCrypt storage provider and key
    $phProvider = [IntPtr]::Zero
    [void][NCrypt]::NCryptOpenStorageProvider([ref]$phProvider, $keyProv.pwszProvName, 0)

    $phKey = [IntPtr]::Zero
    [void][NCrypt]::NCryptOpenKey($phProvider, [ref]$phKey, $keyProv.pwszContainerName, 0, 0)

    # Export public key for credential ID calculation
    $pcbResult = 0
    [void][NCrypt]::NCryptExportKey($phKey, [IntPtr]::Zero, "RSAPUBLICBLOB", [IntPtr]::Zero, $null, 0, [ref]$pcbResult, 0)
    $pubkey = New-Object byte[] -ArgumentList $pcbResult
    [void][NCrypt]::NCryptExportKey($phKey, [IntPtr]::Zero, "RSAPUBLICBLOB", [IntPtr]::Zero, $pubkey, $pubkey.Length, [ref]$pcbResult, 0)

    # Calculate credential ID (SHA256 of public key)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    $credIdHash = $sha256.ComputeHash($pubkey)
    $sha256.Dispose()
    $credentialId = Get-Base64UrlEncode -Bytes $credIdHash

    Write-Host "$([char]0x2714) Credential ID: $credentialId" -ForegroundColor Green

    # Base64 encode challenge
    $challengebytes = [System.Text.Encoding]::UTF8.GetBytes($Challenge)
    $challengeb64 = Get-Base64UrlEncode -Bytes $challengebytes

    # Create clientDataJSON
    $clientData = @{
        type        = "webauthn.get"
        challenge   = $challengeb64
        origin      = $Origin
        crossOrigin = $false
    } | ConvertTo-Json -Compress

    $clientDataBytes = [System.Text.Encoding]::UTF8.GetBytes($clientData)
    $clientDataB64 = Get-Base64UrlEncode -Bytes $clientDataBytes

    # Hash clientDataJSON
    $sha256 = [Security.Cryptography.SHA256]::Create()
    $clientDataHash = $sha256.ComputeHash($clientDataBytes)
    $sha256.Dispose()

    # Create authenticatorData
    # RP ID hash (32 bytes) + flags (1 byte) + sign count (4 bytes) = 37 bytes
    $rpIdBytes = [System.Text.Encoding]::UTF8.GetBytes($RpId)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    $rpIdHash = $sha256.ComputeHash($rpIdBytes)
    $sha256.Dispose()

    $flags = 0x05  # UP (0x01) + UV (0x04)
    $signCountBytes = [BitConverter]::GetBytes([int]$SignCount)
    [Array]::Reverse($signCountBytes)  # Big-endian

    $authenticatorData = [byte[]]::new(37)
    [Array]::Copy($rpIdHash, 0, $authenticatorData, 0, 32)
    $authenticatorData[32] = $flags
    [Array]::Copy($signCountBytes, 0, $authenticatorData, 33, 4)

    $authenticatorDataB64 = Get-Base64UrlEncode -Bytes $authenticatorData

    # Create data to sign: authenticatorData || hash(clientDataJSON)
    $toSign = [byte[]]::new($authenticatorData.Length + $clientDataHash.Length)
    [Array]::Copy($authenticatorData, 0, $toSign, 0, $authenticatorData.Length)
    [Array]::Copy($clientDataHash, 0, $toSign, $authenticatorData.Length, $clientDataHash.Length)

    # Hash the data to sign
    $sha256 = [Security.Cryptography.SHA256]::Create()
    $hashToSign = $sha256.ComputeHash($toSign)
    $sha256.Dispose()

    Write-Host "$([char]0x2718) Signing assertion with Windows Hello key..." -ForegroundColor Cyan

    # Sign with NCrypt
    $paddingInfo = New-Object -TypeName 'NCrypt+BCRYPT_PKCS1_PADDING_INFO'
    $paddingInfo.pszAlgId = "SHA256"
    $pPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf($paddingInfo))
    [Runtime.InteropServices.Marshal]::StructureToPtr($paddingInfo, $pPtr, $false)

    $sigSize = 0
    [void][NCrypt]::NCryptSignHash($phKey, $pPtr, $hashToSign, $hashToSign.Length, $null, 0, [ref]$sigSize, 2)

    $signature = New-Object byte[] -ArgumentList $sigSize
    [void][NCrypt]::NCryptSignHash($phKey, $pPtr, $hashToSign, $hashToSign.Length, $signature, $signature.Length, [ref]$sigSize, 2)

    [Runtime.InteropServices.Marshal]::FreeHGlobal($pPtr)

    $signatureB64 = Get-Base64UrlEncode -Bytes $signature

    Write-Host "$([char]0x2714) Signature created" -ForegroundColor Green

    # Construct the WebAuthn assertion response and return it as a compressed JSON string,
    # so it can easily be transferred to the machine running Invoke-EntraIDPasskeyAssertionLogin
    $assertion = [ordered]@{
        id                = $credentialId
        clientDataJSON    = $clientDataB64
        authenticatorData = $authenticatorDataB64
        signature         = $signatureB64
        userHandle        = $userInfo.UserHandle
    }

    return ($assertion | ConvertTo-Json -Compress)
}
