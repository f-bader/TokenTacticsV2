# Token and session utility command reference

## Clear-Token

Removes the module's known global token variables. Use `-Token All` or a specific
token family accepted by the implementation.

```powershell
Clear-Token -Token All
```

`-Token All` includes `$global:response`. It does not clear `$global:TokenDomain`,
`$global:TokenUpn`, `$global:ESTSAUTH`, `$global:webSession`,
`$global:Fido2FlowState`, or `$global:Fido2WebSession`; remove those and any
caller-created variables separately when the test ends.

## ConvertFrom-JWTtoken

Decodes a three-segment JWT payload and returns its claims. `-Token` accepts pipeline
input and has `access_token` and `id_token` aliases.

```powershell
$claims = ConvertFrom-JWTtoken -Token $accessToken
$claims | Select-Object aud, tid, scp, roles, IssuedAt, ExpirationDate, ValidForHours
```

This command does not verify the JWT signature or trust the claims.

## ConvertTo-PEMPrivateKey

Converts raw Base64 or Base64URL PKCS#8 key material to a PEM block. `-PrivateKey`
accepts pipeline input and returns an existing PEM value unchanged.

```powershell
$pem = ConvertTo-PEMPrivateKey -PrivateKey $base64Key
```

The result is sensitive private key material.

## Get-ForgedUserAgent

Returns a selected or custom HTTP user-agent string. Parameters are `-Device`,
`-Browser`, and `-CustomUserAgent`. Supported device values are `Mac`, `Windows`,
`Linux`, `AndroidMobile`, `iPhone`, and `OS/2`; browser values are `Android`,
`IE`, `Chrome`, `Firefox`, `Edge`, and `Safari`.

```powershell
Get-ForgedUserAgent -Device Windows -Browser Edge
```

The output is request metadata and is not a device identity or compliance claim.

## Get-TenantID

Reads the OpenID configuration for `-domain` and extracts the GUID tenant ID from
the authorization endpoint.

```powershell
Get-TenantID -domain 'contoso.onmicrosoft.com'
```

The command requires access to the tenant metadata endpoint.

## New-EntraIDUserHandle

Calculates an Entra FIDO2 user handle from `-TenantId` and `-UserId`, both GUIDs.
It returns URL-safe, padded Base64, and hexadecimal representations.

```powershell
New-EntraIDUserHandle -TenantId $tenantId -UserId $userObjectId
```

## Compatibility aliases

The module exports `Parse-JWTtoken` for `ConvertFrom-JWTtoken` and
`Forge-UserAgent` for `Get-ForgedUserAgent`. Prefer the canonical names in new
scripts.
