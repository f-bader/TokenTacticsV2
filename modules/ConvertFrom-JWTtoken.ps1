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

    $segments = $token.Split('.')
    if ($segments.Count -ne 3 -or !$token.StartsWith("eyJ")) {
        Write-Error "Invalid token" -ErrorAction Stop
    }

    $TokenHeader = $segments[0].Replace('-', '+').Replace('_', '/')

    while ($TokenHeader.Length % 4) {
        $TokenHeader += "="
    }
    $TokenHeaderObject = [System.Text.Encoding]::UTF8.GetString([system.convert]::FromBase64String($TokenHeader)) | ConvertFrom-Json
    Write-Verbose ( $TokenHeaderObject  | Out-String -Width 100 )

    $TokenPayload = $segments[1].Replace('-', '+').Replace('_', '/')

    while ($TokenPayload.Length % 4) {
        $TokenPayload += "="
    }

    $tokenArray = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($TokenPayload))

    $TokenObject = $tokenArray | ConvertFrom-Json
    if ($null -ne $TokenObject.iat) {
        $TokenObject | Add-Member -NotePropertyName "IssuedAt" -NotePropertyValue ([DateTimeOffset]::FromUnixTimeSeconds($TokenObject.iat).UtcDateTime)
    }
    if ($null -ne $TokenObject.nbf) {
        $TokenObject | Add-Member -NotePropertyName "NotBefore" -NotePropertyValue ([DateTimeOffset]::FromUnixTimeSeconds($TokenObject.nbf).UtcDateTime)
    }
    if ($null -ne $TokenObject.exp) {
        $TokenObject | Add-Member -NotePropertyName "ExpirationDate" -NotePropertyValue ([DateTimeOffset]::FromUnixTimeSeconds($TokenObject.exp).UtcDateTime)
    }
    if ($null -ne $TokenObject.IssuedAt -and $null -ne $TokenObject.ExpirationDate) {
        $TokenObject | Add-Member -NotePropertyName "ValidForHours" -NotePropertyValue (New-TimeSpan -Start $TokenObject.IssuedAt -End $TokenObject.ExpirationDate | Select-Object -ExpandProperty TotalHours)
    }
    return $TokenObject
}
