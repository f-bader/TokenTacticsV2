# TokenTactics OAuth and workload guides

Start with the scenario that matches the workload. Each guide explains the Entra
registration, credential choice, command sequence, verification, and failure cases.

## Choose a scenario

- [Run a daemon or scheduled job as an application](./use-cases/app-only-daemon.md)
- [Call a downstream API on behalf of a signed-in user](./use-cases/delegated-api-obo.md)
- [Authenticate a GitHub Actions or external workload](./use-cases/ci-and-external-workloads.md)
- [Use an Azure Arc-enabled machine identity](./use-cases/azure-arc-machine.md)
- [Build a custom certificate-backed OIDC provider](./use-cases/custom-oidc-provider.md)
- [Support an existing implicit-flow browser application](./use-cases/implicit-browser-compatibility.md)
- [Use a certificate-backed application identity](./use-cases/certificate-application-identity.md)

The [cmdlet reference](./commands/README.md) documents individual parameters and
the [validation plan](./TESTING-OAUTH-WORKLOAD-FLOWS.md) provides the complete
test-tenant and negative-test procedure.
