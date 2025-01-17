function ConvertFrom-JWTtoken {
    <#
    .DESCRIPTION
        Parse JWTtoken code from https://www.michev.info/Blog/Post/2140/decode-jwt-access-and-id-tokens-via-powershell
    .EXAMPLE
        ConvertFrom-JWTtoken -Token ey....
    #>
    [cmdletbinding()]
    param(
        [Alias("access_token", "id_token")]
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$token
    )

    if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }

    $TokenHeader = $token.Split(".")[0].Replace('-', '+').Replace('_', '/')

    while ($TokenHeader.Length % 4) {
        $TokenHeader += "="
    }
    $TokenHeaderObject = [System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($TokenHeader)) | ConvertFrom-Json
    Write-Verbose ( $TokenHeaderObject  | Out-String -Width 100 )

    $TokenPayload = $token.Split(".")[1].Replace('-', '+').Replace('_', '/')

    while ($TokenPayload.Length % 4) {
        $TokenPayload += "="
    }

    $tokenArray = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($TokenPayload))

    $TokenObject = $tokenArray | ConvertFrom-Json
    if (-not [string]::IsNullOrWhiteSpace($TokenObject.iat)) {
        $TokenObject | Add-Member -NotePropertyName "IssuedAt" -NotePropertyValue (Get-Date "01.01.1970").AddSeconds($TokenObject.iat)
    }
    if (-not [string]::IsNullOrWhiteSpace($TokenObject.nbf)) {
        $TokenObject | Add-Member -NotePropertyName "NotBefore" -NotePropertyValue (Get-Date "01.01.1970").AddSeconds($TokenObject.nbf)
    }
    if (-not [string]::IsNullOrWhiteSpace($TokenObject.exp)) {
        $TokenObject | Add-Member -NotePropertyName "ExpirationDate" -NotePropertyValue (Get-Date "01.01.1970").AddSeconds($TokenObject.exp)
    }
    if (-not [string]::IsNullOrWhiteSpace($TokenObject.IssuedAt)) {
        $TokenObject | Add-Member -NotePropertyName "ValidForHours" -NotePropertyValue (New-TimeSpan -Start $TokenObject.IssuedAt -End $TokenObject.ExpirationDate | Select-Object -ExpandProperty TotalHours)
    }
    return $TokenObject
}
