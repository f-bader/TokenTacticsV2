function New-TPMCertificate {
    <#
    .SYNOPSIS
        Creates a non-exportable RSA certificate backed by the Windows TPM.

    .DESCRIPTION
        Creates a self-signed certificate in a personal certificate store using the
        Microsoft Platform Crypto Provider. The private key remains non-exportable
        and can be used to authenticate an Entra ID application with a certificate.

    .PARAMETER Subject
        The subject distinguished name for the certificate.

    .PARAMETER CertStoreLocation
        The personal certificate store in which to create the certificate.

    .PARAMETER PublicKeyPath
        Optional path to write the public certificate as a DER-encoded .cer file.

    .EXAMPLE
        New-TPMCertificate -Subject 'CN=EntraID-TPM-Auth' -PublicKeyPath C:\Temp\EntraID-TPM-Auth.cer

    .EXAMPLE
        New-TPMCertificate -Subject 'CN=Service-Auth' -CertStoreLocation Cert:\LocalMachine\My

    .NOTES
        This command requires Windows, a provisioned TPM, and the Microsoft Platform
        Crypto Provider. A LocalMachine certificate store generally requires elevation.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Subject,

        [Parameter()]
        [ValidateSet('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')]
        [string]$CertStoreLocation = 'Cert:\CurrentUser\My',

        [Parameter()]
        [ValidateSet(2048, 3072, 4096)]
        [int]$KeyLength = 2048,

        [Parameter()]
        [ValidateScript({ $_ -gt (Get-Date) })]
        [datetime]$NotAfter = (Get-Date).AddYears(2),

        [Parameter()]
        [ValidatePattern('(?i)\.cer$')]
        [string]$PublicKeyPath
    )

    if ($env:OS -ne 'Windows_NT') {
        throw 'New-TPMCertificate is supported only on Windows.'
    }

    if (-not (Get-Command -Name New-SelfSignedCertificate -ErrorAction SilentlyContinue)) {
        throw 'The Windows PKI New-SelfSignedCertificate cmdlet is unavailable.'
    }

    if (-not $PSCmdlet.ShouldProcess($CertStoreLocation, "Create TPM-backed certificate '$Subject'")) {
        return
    }

    $certificateParameters = @{
        Subject           = $Subject
        CertStoreLocation = $CertStoreLocation
        Provider          = 'Microsoft Platform Crypto Provider'
        KeyAlgorithm      = 'RSA'
        KeyLength         = $KeyLength
        KeyUsage          = 'DigitalSignature'
        KeyExportPolicy   = 'NonExportable'
        NotAfter          = $NotAfter
        ErrorAction       = 'Stop'
    }

    $certificate = New-SelfSignedCertificate @certificateParameters

    if ($PublicKeyPath) {
        Export-TTPublicCertificate -Certificate $certificate -Path $PublicKeyPath
    }

    Write-Output $certificate
}

function Export-TTPublicCertificate {
    param(
        [Parameter(Mandatory = $true)]
        $Certificate,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    Export-Certificate -Cert $Certificate -FilePath $Path -Type CERT -ErrorAction Stop | Out-Null
}
