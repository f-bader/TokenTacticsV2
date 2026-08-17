# Inspect tokens and clean up local session state

These commands are local support utilities. They do not validate a token's
signature or grant access. Use them to inspect test fixtures, verify audiences and
claims, format key material, select request metadata, resolve tenant IDs, and
remove token variables after a test.

## Decode a JWT payload

```powershell
$claims = ConvertFrom-JWTtoken -Token $accessToken
$claims | Select-Object tid, aud, iss, scp, roles, ExpirationDate, ValidForHours
```

The command accepts pipeline input and the `access_token` and `id_token` property
aliases:

```powershell
$response | ConvertFrom-JWTtoken
```

The result includes the decoded payload plus `IssuedAt`, `NotBefore`,
`ExpirationDate`, and `ValidForHours` when the corresponding timestamp claims are
present. It is a decoder, not a signature verifier. Do not treat decoded claims as
trusted until the token has been validated by the intended resource provider.

## Clear module token variables

```powershell
Clear-Token -Token All
```

`Clear-Token` removes the module's known global token variables. Use the specific
token selection when the test needs to retain other values. `-Token All` includes
`$global:response`, but it intentionally does not remove session metadata, cookies,
or passkey state. Clear those separately when they are no longer needed:

```powershell
Remove-Variable -Scope Global -Name `
    TokenDomain, TokenUpn, ESTSAUTH, webSession, Fido2FlowState, Fido2WebSession `
    -ErrorAction SilentlyContinue
```

Also remove any variables created by the caller.

## Convert a private key to PEM

```powershell
$pem = ConvertTo-PEMPrivateKey -PrivateKey $base64Key
```

The command accepts raw Base64 or Base64URL PKCS#8 material and returns a
`BEGIN PRIVATE KEY` PEM block. If the input is already PEM, it is returned as-is.
This is a format conversion, not encryption. Protect the resulting string.

## User-agent profiles

```powershell
$userAgent = Get-ForgedUserAgent -Device Windows -Browser Edge
$custom = Get-ForgedUserAgent -CustomUserAgent 'Authorized-Test-Agent/1.0'
```

Supported device values are `Mac`, `Windows`, `Linux`, `AndroidMobile`, `iPhone`,
and `OS/2`. Supported browser values are `Android`, `IE`, `Chrome`, `Firefox`,
`Edge`, and `Safari`. This changes the HTTP `User-Agent` header only; it is not a
device identity, compliance signal, or security boundary.

## Resolve a tenant ID

```powershell
$tenantId = Get-TenantID -domain 'contoso.onmicrosoft.com'
```

The command reads the tenant's OpenID configuration and extracts the GUID from the
authorization endpoint. It requires network access to the tenant metadata endpoint
and fails if that endpoint does not contain a GUID tenant segment.

## Security checklist

- Do not print decoded tokens, key material, cookies, or full verbose request bodies
  in shared logs.
- Treat global variables as process-local secret storage only; they are not a vault.
- Use test fixtures with synthetic or redacted claims whenever possible.
- Clear variables and revoke test sessions at the end of the exercise.

See the [utility command reference](../commands/token-and-session-utilities.md).
