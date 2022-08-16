# Helper Functions
function Get-TenantID {
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName = 'Domain', Mandatory = $True)]
        [String]$domain
    )
    Process {
        $openIdConfig = Invoke-RestMethod "https://login.microsoftonline.com/$domain/.well-known/openid-configuration"
        $TenantId = $OpenIdConfig.authorization_endpoint.Split("/")[3]
        return $TenantId
    }
}

function Parse-JWTtoken {
    <#
    .DESCRIPTION
        Parse JWTtoken code from https://www.michev.info/Blog/Post/2140/decode-jwt-access-and-id-tokens-via-powershell
    .EXAMPLE
        Parse-JWTtoken -Token ey....
    #>
    [cmdletbinding()]
    param([Parameter(Mandatory = $true)][string]$token)

    if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }

    $tokenheader = $token.Split(".")[0].Replace('-', '+').Replace('_', '/')

    while ($tokenheader.Length % 4) {
        $tokenheader += "="
    }
    $TokenHeaderObject = [System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($tokenheader)) | ConvertFrom-Json
    Write-Verbose ( $TokenHeaderObject  | Out-String -Width 100 )

    $tokenPayload = $token.Split(".")[1].Replace('-', '+').Replace('_', '/')

    while ($tokenPayload.Length % 4) {
        $tokenPayload += "="
    }

    $tokenArray = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($tokenPayload))

    $tokobj = $tokenArray | ConvertFrom-Json
    $tokobj | Add-Member -NotePropertyName "IssuedAt" -NotePropertyValue (Get-Date "01.01.1970").AddSeconds($tokobj.iat)
    $tokobj | Add-Member -NotePropertyName "NotBefore" -NotePropertyValue (Get-Date "01.01.1970").AddSeconds($tokobj.nbf)
    $tokobj | Add-Member -NotePropertyName "ExpirationDate" -NotePropertyValue (Get-Date "01.01.1970").AddSeconds($tokobj.exp)
    $tokobj | Add-Member -NotePropertyName "ValidForHours" -NotePropertyValue (New-TimeSpan -Start $tokobj.IssuedAt -End $tokobj.ExpirationDate | Select-Object -ExpandProperty TotalHours)
    return $tokobj
}
