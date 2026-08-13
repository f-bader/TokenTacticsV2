# Build a custom certificate-backed OIDC provider

Use this workflow when a workload needs Entra federation but does not have a
pre-integrated provider such as GitHub. The issuer URL is part of the trust
relationship, so it must be chosen before the signing certificate and metadata
are created.

The workflow has two separate planes:

- Private plane: PowerShell holds the PFX/private key and signs short-lived assertions.
- Public plane: a stable HTTPS host serves only OIDC discovery and JWKS metadata.

Never publish the PFX, private key, or a signing endpoint.

## 0. Set the variables

Run these commands in the PowerShell session that will perform the workflow. The
values are usable examples; replace the tenant, subscription, application, and
hostname values with values from your environment. The storage account name must
be globally unique, lowercase, and 3–24 characters long.

    $subscriptionId        = '00000000-0000-0000-0000-000000000000'
    $tenantId              = 'contoso.onmicrosoft.com'
    $clientId              = '11111111-1111-1111-1111-111111111111'
    $appObjectId           = '22222222-2222-2222-2222-222222222222'
    $credentialName        = 'custom-oidc-workload'

    $resourceGroupName     = 'rg-tokentactics-oidc'
    $location              = 'westeurope'
    $storageAccountName    = 'ttoidcissuer12345'
    $deploymentName        = 'oidc-static-website'

    $issuerHost            = 'oidc.example.com'
    $issuer                = "https://$issuerHost"
    $cloudflareTunnelName  = 'tokentactics-oidc'
    $port                  = 8080

    $metadataPath          = './oidc-public'
    $pfxPath               = './issuer-signing.pfx'
    $publicCertificatePath = './issuer-signing.cer'

    $subject               = 'build-workload'
    $audience              = 'api://AzureADTokenExchange'
    $scope                 = 'https://graph.microsoft.com/.default'

The sample `$issuer` is for the Cloudflare option. If Azure Storage is selected,
step 1 replaces `$issuer` with the deployment's static website URL. Do not put a
PFX password in this block; the password is collected as a `SecureString` in step 2.

Install or make available only the tools for the hosting path you choose: Azure
CLI for the CLI branch, `Az.Accounts`, `Az.Resources`, and `Az.Storage` for the
Az PowerShell branch, and `cloudflared` for the tunnel branch.

## 1. Choose and prepare the hosting option

The final value of `$issuer` must be stable, publicly reachable over HTTPS, and
identical in all three places: the Entra federated credential, the discovery
document's `issuer`, and every assertion's `iss` claim.

Choose one hosting option. Do not run both deployment branches for the same issuer.

### Option A: local static host through a Cloudflare named tunnel

This option keeps the metadata files on the assertion-issuing machine and exposes
only the loopback static host through a stable Cloudflare hostname. Create the
tunnel once, then configure its ingress to forward `$issuerHost` to
`http://127.0.0.1:$port`.

    cloudflared tunnel create $cloudflareTunnelName
    cloudflared tunnel route dns $cloudflareTunnelName $issuerHost

The tunnel is started in step 4, after the metadata files exist. Do not use a
Quick Tunnel because its generated hostname is not stable enough for an Entra
trust relationship.

### Option B: Azure Storage static website

The included Bicep template creates the StorageV2 account and enables static
website hosting. It does not upload metadata or contain private key material.

Azure CLI from the same PowerShell session:

    az login
    az account set --subscription $subscriptionId
    az group create --name $resourceGroupName --location $location
    $issuer = az deployment group create --name $deploymentName --resource-group $resourceGroupName --template-file ./infra/oidc-static-website.bicep --parameters storageAccountName=$storageAccountName --query properties.outputs.staticWebsiteUrl.value -o tsv
    $issuer = $issuer.TrimEnd('/')

Az PowerShell alternative:

    Connect-AzAccount
    Set-AzContext -Subscription $subscriptionId
    New-AzResourceGroup -Name $resourceGroupName -Location $location
    $deployment = New-AzResourceGroupDeployment -Name $deploymentName -ResourceGroupName $resourceGroupName -TemplateFile ./infra/oidc-static-website.bicep -storageAccountName $storageAccountName
    $issuer = ([string]$deployment.Outputs.staticWebsiteUrl.Value).TrimEnd('/')

If the storage deployment already exists, retrieve its output instead of creating
it again:

    $deployment = Get-AzResourceGroupDeployment -ResourceGroupName $resourceGroupName -Name $deploymentName
    $issuer = ([string]$deployment.Outputs.staticWebsiteUrl.Value).TrimEnd('/')

If Azure reports `InvalidRequestParameters` for
`properties.staticWebsiteEnabled`, use the checked-in template unchanged. The
Blob service resource must use Storage Resource Provider API `2025-08-01` or later;
do not add a `staticWebsiteEnabled` property manually.

At the end of this step, confirm that `$issuer` contains the selected stable HTTPS
URL before continuing.

## 2. Create the signing certificate

Create the certificate only after `$issuer` is final. The PFX stays outside the
public metadata directory.

    $password = Read-Host 'PFX password' -AsSecureString
    $certificate = New-EntraIDFederatedSigningCertificate -PfxPath $pfxPath -PfxPasswordSecureString $password -PublicCertificatePath $publicCertificatePath
    $certificate | Format-List Thumbprint, PfxPath, PublicCertificatePath, NotAfter

On macOS and Linux, OpenSSL is used when the native .NET certificate provider
cannot create or load the PFX. Certificate-store thumbprint input remains
Windows-only; PFX input is cross-platform.

## 3. Generate the public OIDC metadata

Generate metadata using the exact issuer selected in step 1:

    $metadata = New-EntraIDFederatedIssuerMetadata -Issuer $issuer -Subject $subject -OutputPath $metadataPath -PfxPath $pfxPath -PfxPasswordSecureString $password -Audience $audience
    $metadata.GeneratedFiles

The command creates the two public OIDC endpoint files:

- `$metadataPath/.well-known/openid-configuration`
- `$metadataPath/keys.json`

With `-IncludeLocalConfig` it also writes `$metadataPath/issuer-config.json`, a
local convenience record of the issuer, subject, audience, and key ID that the web
host does not need. Keep it local if you create it. The `.well-known` directory is
hidden in normal PowerShell listings, so use `Get-ChildItem -Force -Recurse` or the
returned `GeneratedFiles` property when checking the result.

## 4. Publish the public metadata

Publish only the discovery document and JWKS. Never publish the PFX.

### Cloudflare named tunnel

Start the static host in one terminal:

    ./infra/Start-TTFederatedIssuerStaticHost.ps1 -Path $metadataPath -Port $port

Start the named tunnel in a second terminal:

    cloudflared tunnel run $cloudflareTunnelName

The tunnel must route `$issuerHost` to `http://127.0.0.1:$port`.

### Azure Storage static website

Az PowerShell:

    $storage = Get-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $storageAccountName
    $root = (Resolve-Path $metadataPath).Path
    Get-ChildItem -LiteralPath $root -File -Recurse -Force | Where-Object Name -ne 'issuer-config.json' | ForEach-Object {
        $blob = $_.FullName.Substring($root.Length).TrimStart('\', '/') -replace '\\', '/'
        $contentType = if ($_.Extension -eq '.json') { 'application/json' } else { 'application/octet-stream' }
        Set-AzStorageBlobContent -File $_.FullName -Container '$web' -Blob $blob -Context $storage.Context -Properties @{ ContentType = $contentType } -Force | Out-Null
    }

Azure CLI:

    az storage blob upload --account-name $storageAccountName --container-name '$web' --name 'keys.json' --file "$metadataPath/keys.json" --content-type application/json --auth-mode login --overwrite true
    az storage blob upload --account-name $storageAccountName --container-name '$web' --name '.well-known/openid-configuration' --file "$metadataPath/.well-known/openid-configuration" --content-type application/json --auth-mode login --overwrite true

## 5. Verify the public endpoints

Verify publication before creating the Entra trust relationship:

    $discoveryUrl = "$issuer/.well-known/openid-configuration"
    $jwksUrl = "$issuer/keys.json"
    $discovery = Invoke-RestMethod -Method Get -Uri $discoveryUrl
    $jwks = Invoke-RestMethod -Method Get -Uri $jwksUrl

    if ($discovery.issuer -ne $issuer) { throw "Discovery issuer '$($discovery.issuer)' does not match '$issuer'." }
    if ($discovery.jwks_uri -ne $jwksUrl) { throw "Discovery JWKS URI '$($discovery.jwks_uri)' does not match '$jwksUrl'." }
    if (@($jwks.keys).Count -lt 1) { throw 'The JWKS does not contain a signing key.' }
    $discovery | ConvertTo-Json -Depth 8
    $jwks | ConvertTo-Json -Depth 8

The discovery document must identify the issuer and JWKS URL, advertise `id_token`
responses, and advertise RS256 signing. The JWKS must contain the RSA key whose
`kid` is used in assertions.

## 6. Configure the Entra federated credential

Create or select the app registration identified by `$clientId` and
`$appObjectId`. Grant its required application permissions and admin consent.

In **App registrations > Certificates & secrets > Federated credentials**, add an
**Other issuer** credential with:

- Name: `$credentialName`
- Issuer: `$issuer`
- Subject: `$subject`
- Audience: `$audience`

The same values must appear in the external assertion. If using Az PowerShell to
create the credential, run this after the app registration exists:

    New-AzADAppFederatedCredential -ApplicationObjectId $appObjectId -Audience $audience -Issuer $issuer -Name $credentialName -Subject $subject

## 7. Sign and exchange an assertion

Create the assertion only after the public endpoints and federated credential are
ready:

    $assertion = New-EntraIDFederatedClientAssertion -Issuer $issuer -Subject $subject -Audience $audience -PfxPath $pfxPath -PfxPasswordSecureString $password
    $token = Get-EntraIDTokenFromFederatedCredential -TenantId $tenantId -ClientId $clientId -FederatedToken $assertion -Scope $scope
    $token

Decode the assertion locally and verify `iss`, `sub`, `aud`, `iat`, `nbf`, `exp`,
`jti`, `kid`, and the RS256 signature against `$jwks`.

## 8. Rotate the signing key

For rotation, create a new PFX and publish its public key before signing with it.
Keep the old and new keys in the public JWKS during the overlap period, then remove
the old key after all callers have migrated. `New-EntraIDFederatedIssuerMetadata` emits
one key for one certificate; preserving an overlap requires explicitly merging the
old and new JWK entries before publishing the JWKS.

Test wrong issuer, subject, audience, signature, expired assertions, unavailable
discovery, unavailable JWKS, and a removed old key before completing the rotation.

See the [certificate](../commands/New-EntraIDFederatedSigningCertificate.md),
[metadata](../commands/New-EntraIDFederatedIssuerMetadata.md),
[assertion](../commands/New-EntraIDFederatedClientAssertion.md), and
[exchange](../commands/Get-EntraIDTokenFromFederatedCredential.md) references.
