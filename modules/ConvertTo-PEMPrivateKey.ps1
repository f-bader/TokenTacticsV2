function ConvertTo-PEMPrivateKey {
    <#
    .SYNOPSIS
        Converts a raw Base64 private key string to PEM format.

    .DESCRIPTION
        This function takes a raw Base64 encoded private key string and converts it to the PEM format
        by adding the appropriate headers and footers, and wrapping the content at 64 characters.
        If the input is already in PEM format, it returns the original value.

    .PARAMETER PrivateKey
        The private key string to convert.

    .EXAMPLE
        ConvertTo-PEMPrivateKey -PrivateKey "MIGHAg...Zqj0391"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$PrivateKey
    )

    process {
        # Check if it's already in PEM format
        if ($PrivateKey.Trim() -match "^-----BEGIN PRIVATE KEY-----") {
            return $PrivateKey
        }

        # Remove any whitespace
        $cleanKey = $PrivateKey.Trim() -replace "`r|`n|\s", ""

        # Replace invalid characters (if any)
        $cleanKey = $cleanKey -replace "-", "+" -replace "_", "/"

        # Wrap at 64 characters
        $wrappedKey = ""
        for ($i = 0; $i -lt $cleanKey.Length; $i += 64) {
            if ($i + 64 -lt $cleanKey.Length) {
                $wrappedKey += $cleanKey.Substring($i, 64) + "`n"
            } else {
                $wrappedKey += $cleanKey.Substring($i)
            }
        }

        $pemKey = "-----BEGIN PRIVATE KEY-----`n$wrappedKey`n-----END PRIVATE KEY-----"
        return $pemKey
    }
}
