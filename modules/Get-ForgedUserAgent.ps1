function Get-ForgedUserAgent {
    <#
    .DESCRIPTION
        Forge the User-Agent when sending requests to Microsoft's APIs. Useful for bypassing device-specific Conditional Access Policies. Defaults to Windows Edge.
        Allows setting a fully custom User-Agent if provided.
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [String]$Device = "Windows",

        [Parameter(Mandatory = $false)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari', 'Samsung')]
        [String]$Browser = "Edge",

        [Parameter(Mandatory = $false)]
        [String]$CustomUserAgent
    )

    Process {
        if ($PSBoundParameters.ContainsKey('CustomUserAgent') -and $CustomUserAgent) {
            return $CustomUserAgent
        }

        $UserAgents = @{
            "Windows" = @{
                "Edge"    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.64"
                "Chrome"  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                "Firefox" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
                "IE"      = "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko"
            }
            "Mac" = @{
                "Safari"  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15"
                "Chrome"  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                "Firefox" = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0"
                "Edge"    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.64"
            }
            "Linux" = @{
                "Chrome"  = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                "Firefox" = "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
                "Edge"    = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.64"
            }
            "AndroidMobile" = @{
                "Chrome"  = "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36"
                "Firefox" = "Mozilla/5.0 (Android 10; Mobile; rv:89.0) Gecko/89.0 Firefox/89.0"
                "Edge"    = "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36 EdgA/46.03.4.5155"
                "Samsung" = "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/14.0 Chrome/91.0.4472.124 Mobile Safari/537.36"
            }
            "iPhone" = @{
                "Safari"  = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1"
                "Chrome"  = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) CriOS/91.0.4472.124 Mobile/15E148 Safari/537.36"
                "Firefox" = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/34.0 Mobile/15E148 Safari/605.1.15"
                "Edge"    = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) EdgiOS/46.3.24 Mobile/15E148 Safari/605.1.15"
            }
            "OS/2" = @{
                "Firefox" = "Mozilla/5.0 (OS/2; Warp 4.5; rv:45.0) Gecko/20100101 Firefox/45.0"
            }
        }

        if ($UserAgents.ContainsKey($Device) -and $UserAgents[$Device].ContainsKey($Browser)) {
            return $UserAgents[$Device][$Browser]
        } else {
            Write-Error "Invalid device or browser selection."
            return $null
        }
    }
}
