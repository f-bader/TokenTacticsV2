BeforeAll {
    . "$PSScriptRoot/fixtures/TestData.ps1"
    Import-Module $script:ModulePath -Force

    $script:FakeCertificate = [PSCustomObject]@{
        Thumbprint = '0123456789ABCDEF0123456789ABCDEF01234567'
        Subject    = 'CN=EntraID-TPM-Auth'
    }
}

Describe 'New-TPMCertificate on Windows' -Skip:(-not $IsWindows) {
    BeforeEach {
        $script:NewCertificateParameters = $null
        $script:ExportParameters = $null
        Mock -ModuleName TokenTactics Get-Command {
            [PSCustomObject]@{ Name = 'New-SelfSignedCertificate' }
        } -ParameterFilter { $Name -eq 'New-SelfSignedCertificate' }
        Mock -ModuleName TokenTactics New-SelfSignedCertificate {
            param(
                $Subject,
                $CertStoreLocation,
                $Provider,
                $KeyAlgorithm,
                $KeyLength,
                $KeyUsage,
                $KeyExportPolicy,
                $NotAfter
            )
            $script:NewCertificateParameters = @{
                Subject           = $Subject
                CertStoreLocation = $CertStoreLocation
                Provider          = $Provider
                KeyAlgorithm      = $KeyAlgorithm
                KeyLength         = $KeyLength
                KeyUsage          = $KeyUsage
                KeyExportPolicy   = $KeyExportPolicy
                NotAfter          = $NotAfter
            }
            $script:FakeCertificate
        }
        Mock -ModuleName TokenTactics Export-TTPublicCertificate {
            param($Certificate, $Path)
            $script:ExportParameters = @{
                Certificate = $Certificate
                Path        = $Path
            }
        }
    }

    It 'creates a non-exportable RSA certificate with the TPM provider' {
        $result = New-TPMCertificate -Subject 'CN=EntraID-TPM-Auth'

        $result | Should -Be $script:FakeCertificate
        $script:NewCertificateParameters['Subject'] | Should -Be 'CN=EntraID-TPM-Auth'
        $script:NewCertificateParameters['CertStoreLocation'] | Should -Be 'Cert:\CurrentUser\My'
        $script:NewCertificateParameters['Provider'] | Should -Be 'Microsoft Platform Crypto Provider'
        $script:NewCertificateParameters['KeyAlgorithm'] | Should -Be 'RSA'
        $script:NewCertificateParameters['KeyLength'] | Should -Be 2048
        $script:NewCertificateParameters['KeyUsage'] | Should -Be 'DigitalSignature'
        $script:NewCertificateParameters['KeyExportPolicy'] | Should -Be 'NonExportable'
    }

    It 'exports only the public certificate when PublicKeyPath is supplied' {
        New-TPMCertificate -Subject 'CN=EntraID-TPM-Auth' -PublicKeyPath 'C:\Temp\EntraID-TPM-Auth.cer' | Should -Be $script:FakeCertificate

        $script:ExportParameters['Certificate'] | Should -Be $script:FakeCertificate
        $script:ExportParameters['Path'] | Should -Be 'C:\Temp\EntraID-TPM-Auth.cer'
    }

    It 'rejects a non-CER public key path' {
        { New-TPMCertificate -Subject 'CN=EntraID-TPM-Auth' -PublicKeyPath 'C:\Temp\certificate.pem' } |
            Should -Throw
    }

    It 'reports an unavailable PKI cmdlet before creation' {
        Mock -ModuleName TokenTactics Get-Command { $null } -ParameterFilter { $Name -eq 'New-SelfSignedCertificate' }

        { New-TPMCertificate -Subject 'CN=EntraID-TPM-Auth' } |
            Should -Throw '*New-SelfSignedCertificate cmdlet is unavailable*'
    }

}

Describe 'New-TPMCertificate on non-Windows systems' -Skip:$IsWindows {
    It 'rejects non-Windows systems' {
        { New-TPMCertificate -Subject 'CN=EntraID-TPM-Auth' } |
            Should -Throw '*supported only on Windows*'
    }
}
