# TokenTactics Pester Tests

This directory contains Pester tests for the core user-facing functions of TokenTactics.

## Overview

The tests validate the following functions without requiring actual connections to Azure/Entra ID by mocking external calls:

- **ConvertFrom-JWTtoken** - JWT token parsing and validation
- **Get-ForgedUserAgent** - User agent string generation for different devices and browsers
- **Get-TenantID** - Tenant ID retrieval (with mocked REST calls)
- **Get-TTCodeVerifier / Get-TTCodeChallenge** - PKCE code verifier and challenge generation
- **Clear-Token** - Token variable cleanup

## Running Tests

### Run all tests

```powershell
Invoke-Pester -Path ./Tests/*.Tests.ps1
```

### Run specific test file

```powershell
Invoke-Pester -Path ./Tests/ConvertFrom-JWTtoken.Tests.ps1
```

### Run with detailed output

```powershell
Invoke-Pester -Path ./Tests/*.Tests.ps1 -Output Detailed
```

## Test Structure

Each test file follows the Pester 5 structure:

- `BeforeAll` - Dot-sources the function file being tested
- `Describe` - Main test suite for the function
- `Context` - Groups related tests
- `It` - Individual test cases

## Test Coverage

| Function | Test Count | Coverage |
|----------|------------|----------|
| ConvertFrom-JWTtoken | 11 | JWT parsing, parameter aliases, error handling, pipeline support |
| Get-ForgedUserAgent | 26 | All device/browser combinations, custom user agents, defaults |
| Get-TenantID | 5 | Valid domains, error handling, mocked REST calls |
| CodeVerifier Functions | 13 | Code verifier generation, code challenge creation, validation |
| Clear-Token | 14 | Individual and bulk token clearing, idempotency |

**Total: 69 tests**

## Notes

- Tests use mocking (via Pester's `Mock` command) to avoid making actual REST API calls
- Tests dot-source individual function files for faster execution
- All tests are designed to run without requiring Azure/Entra ID credentials
