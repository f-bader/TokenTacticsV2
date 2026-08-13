```
  ______      __                 __             __  _                     ___ 
 /_  __/___  / /_____  ____     / /_____ ______/ /_(_)_________   _   __ |__ \
  / / / __ \/ //_/ _ \/ __ \   / __/ __ `/ ___/ __/ / ___/ ___/  | | / / __/ /
 / / / /_/ / ,< /  __/ / / /  / /_/ /_/ / /__/ /_/ / /__(__  )   | |/ / / __/ 
/_/  \____/_/|_|\___/_/ /_/   \__/\__,_/\___/\__/_/\___/____/    |___(_)____/     
```

# TokenTactics v2

TokenTactics v2 is a PowerShell toolkit for authorized Microsoft Entra ID security
research, red-team validation, and defensive engineering. It obtains, exchanges,
refreshes, inspects, and clears tokens across interactive, delegated, application,
workload, passkey, cookie, and brokered authentication flows.

The canonical documentation covers the complete exported command surface and
scenario-based procedures:

- [Documentation and scenario guides](./docs/README.md)
- [Exported command reference](./docs/commands/README.md)
- [Custom OIDC provider guide](./docs/use-cases/custom-oidc-provider.md)
- [Continuous Access Evaluation guide](./docs/use-cases/continuous-access-evaluation.md)

Use the toolkit only against tenants, accounts, applications, workloads, and
sessions for which you have explicit authorization. Treat tokens, cookies,
passkey key material, certificates, and client credentials as secrets.

## Installation and quick start

```powershell
Import-Module ./TokenTactics.psd1
Get-Help Get-EntraIDTokenFromDeviceCode
Get-EntraIDTokenFromDeviceCode -Client MSGraph
```

After the authorized user completes sign-in, the OAuth response is available in
`$response`:

```powershell
$response.access_token
$response.refresh_token
```

For an overview of the supported flows, start with the
[interactive authentication guide](./docs/use-cases/interactive-user-authentication.md).

## Testing

The test suite requires PowerShell 7 and Pester 5.7.1. It uses mocked HTTP
responses and does not require Entra ID credentials or network access.

```powershell
Install-Module Pester -RequiredVersion 5.7.1 -Scope CurrentUser
pwsh ./tests/Invoke-Tests.ps1
```

The suite runs on Linux, macOS, and Windows for every pull request.

## Project history

TokenTactics v2 is an updated version of [TokenTactics](https://github.com/rvrsh3ll/TokenTactics),
originally written by Stephan Borosh [@rvrsh3ll](https://github.com/rvrsh3ll) and
Bobby Cooke [@0xBoku](https://github.com/boku7). Current work includes Microsoft
Entra ID OAuth v2 flows, CAE, certificates and TPM-backed authentication, passkeys,
FIDO2 split flows, workload identity federation, nested app authentication, and
custom OIDC tooling.

## Authors and contributors

- [@rvrsh3ll](https://github.com/rvrsh3ll) — original TokenTactics author
- [@0xBoku](https://github.com/boku7) — original co-author and researcher
- [@f-bader](https://github.com/f-bader) — TokenTacticsV2 maintainer
- [@Pri3st](https://github.com/Pri3st) — Storage, Key Vault, and user-agent contributions

TokenTactics' methods are influenced by the research of Dr. Nestori Syynimaa at
[o365blog.com](https://o365blog.com/).
