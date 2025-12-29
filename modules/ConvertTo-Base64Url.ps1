<#
.SYNOPSIS
    Converts a byte array to a Base64Url encoded string.

.DESCRIPTION
    This function takes a byte array as input and returns its Base64Url encoded representation.
    Base64Url encoding is similar to standard Base64 encoding but replaces '+' with '-', '/' with '_',
    and removes padding '=' characters, making it safe for URL transmission.

.PARAMETER Bytes
    A byte array to be converted to Base64Url format.

.EXAMPLE
    $byteArray = [byte[]](0..255)
    $base64UrlString = ConvertTo-Base64Url -Bytes $byteArray
    Write-Output $base64UrlString

.NOTES
    Part of TokenTacticsV2
    https://github.com/f-bader/TokenTacticsV2
#>
function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')
}