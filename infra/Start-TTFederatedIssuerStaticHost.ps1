<#
.SYNOPSIS
    Serves public OIDC discovery and JWKS files on loopback only.

.DESCRIPTION
    This helper deliberately serves static public metadata only. Keep the PFX and
    all assertion signing commands on the local machine. Use a named Cloudflare
    Tunnel or a reverse proxy to publish this listener through a stable HTTPS URL.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$Path,

    [ValidateRange(1, 65535)]
    [int]$Port = 8080
)

$root = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
$rootPrefix = $root.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
$listener = [Net.HttpListener]::new()
$listener.Prefixes.Add("http://127.0.0.1:$Port/")
$listener.Start()
Write-Host "Serving OIDC public metadata from $root at http://127.0.0.1:$Port/"
Write-Host 'Use Ctrl+C to stop. Do not place PFX files in this directory.'

try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        try {
            if ($context.Request.HttpMethod -notin @('GET', 'HEAD')) {
                $context.Response.StatusCode = 405
                continue
            }
            $requestPath = [Uri]::UnescapeDataString($context.Request.Url.AbsolutePath.TrimStart('/'))
            if ([string]::IsNullOrWhiteSpace($requestPath)) { $requestPath = 'index.html' }
            $candidate = [IO.Path]::GetFullPath((Join-Path $root $requestPath))
            if (-not $candidate.StartsWith($rootPrefix, [StringComparison]::Ordinal) -or -not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
                $context.Response.StatusCode = 404
            } else {
                $context.Response.StatusCode = 200
                $context.Response.ContentType = 'application/json'
                $bytes = [IO.File]::ReadAllBytes($candidate)
                $context.Response.ContentLength64 = $bytes.Length
                if ($context.Request.HttpMethod -eq 'GET') {
                    $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                }
            }
        } finally {
            $context.Response.Close()
        }
    }
} finally {
    $listener.Close()
}
