function Get-ForgedUserAgent {
    <#
    .DESCRIPTION
        Forge the User-Agent when sending requests to the Microsoft API's. Useful for bypassing device specific Conditional Access Policies. Defaults to Windows Edge.
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [string]$Device = "Windows",
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser = "Edge",
        [Parameter(Mandatory = $false)]
        [string]$CustomUserAgent
    )
    Process {
        if ($PSBoundParameters.ContainsKey('CustomUserAgent') -and $CustomUserAgent) {
            return $CustomUserAgent
        }
        if ($Device -eq 'Mac') {
            if ($Browser -eq 'Chrome') {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
            } elseif ($Browser -eq 'Firefox') {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:70.0) Gecko/20100101 Firefox/70.0'
            } elseif ($Browser -eq 'Edge') {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/604.1 Edg/91.0.100.0'
            } elseif ($Browser -eq 'Safari') {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15'
            } else {
                Write-Warning "Device platform not found, defaulting to macos/Safari"
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15'
            }
        } elseif ($Device -eq 'Windows') {
            if ($Browser -eq 'IE') {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'
            } elseif ($Browser -eq 'Chrome') {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
            } elseif ($Browser -eq 'Firefox') {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:70.0) Gecko/20100101 Firefox/70.0'
            } elseif ($Browser -eq 'Edge') {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042'
            } else {
                Write-Warning "Device platform not found, defaulting to Windows/Edge"
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042'
            }
        } elseif ($Device -eq 'AndroidMobile') {
            if ($Browser -eq 'Android') {
                $UserAgent = 'Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30'
            } elseif ($Browser -eq 'Chrome') {
                $UserAgent = 'Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Mobile Safari/537.36'
            } elseif ($Browser -eq 'Firefox') {
                $UserAgent = 'Mozilla/5.0 (Android 4.4; Mobile; rv:70.0) Gecko/70.0 Firefox/70.0'
            } elseif ($Browser -eq 'Edge') {
                $UserAgent = 'Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Mobile Safari/537.36 EdgA/103.0.1264.71'
            } else {
                Write-Warning "Device platform not found, defaulting to Android/Chrome"
                $UserAgent = 'Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30'
            }
        } elseif ($Device -eq 'iPhone') {
            if ($Browser -eq 'Chrome') {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/91.0.4472.114 Mobile/15E148 Safari/604.1'
            } elseif ($Browser -eq 'Firefox') {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) FxiOS/1.0 Mobile/12F69 Safari/600.1.4'
            } elseif ($Browser -eq 'Edge') {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 EdgiOS/44.5.0.10 Mobile/15E148 Safari/604.1'
            } elseif ($Browser -eq 'Safari') {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1'
            } else {
                Write-Warning "Device platform not found, defaulting to iPhone/Safari"
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1'
            }
        } elseif ($Device -eq 'Linux') {
            if ($Browser -eq 'Chrome') {
                $UserAgent = 'Mozilla/5.0 (M12; Linux X12-12) AppleWebKit/806.12 (KHTML, like Gecko) Ubuntu/23.04 Chrome/113.0.5672.63 Safari/16.4.1'
            } elseif ($Browser -eq 'Firefox') {
                $UserAgent = 'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.0.14) Gecko/2009090217 Ubuntu/9.04 (jaunty) Firefox/52.7.3'
            } elseif ($Browser -eq 'Edge') {
                $UserAgent = 'Mozilla/5.0 (Wayland; Linux x86_64; Surface) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Ubuntu/23.04 Edg/114.0.1823.43'
            } else {
                Write-Warning "Device platform not found, defaulting to Linux/Firefox"
                $UserAgent = 'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.0.14) Gecko/2009090217 Ubuntu/9.04 (jaunty) Firefox/52.7.3'
            }
        } elseif ($Device -eq 'OS/2') {
            if ($Browser -eq 'Firefox') {
                $UserAgent = 'Mozilla/5.0 (OS/2; U; Warp 4.5; en-US; rv:80.7.12) Gecko/20050922 Firefox/80.0.7'
            } else {
                Write-Warning "Device platform not found, defaulting to OS/2 Firefox"
                $UserAgent = 'Mozilla/5.0 (OS/2; U; Warp 4.5; en-US; rv:80.7.12) Gecko/20050922 Firefox/80.0.7'
            }
        } else {
            if ($Browser -eq 'Android') {
                Write-Warning "Device platform not found, defaulting to Android"
                $UserAgent = 'Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30'
            } elseif ($Browser -eq 'IE') {
                Write-Warning "Device platform not found, defaulting to Windows/IE"
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'
            } elseif ($Browser -eq 'Chrome') {
                Write-Warning "Device platform not found, defaulting to macos/Chrome"
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
            } elseif ($Browser -eq 'Firefox') {
                Write-Warning "Device platform not found, defaulting to Windows/Firefox"
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:70.0) Gecko/20100101 Firefox/70.0'
            } elseif ($Browser -eq 'Safari') {
                Write-Warning "Device platform not found, defaulting to Safari"
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15'
            } else {
                Write-Warning "Device platform not found, defaulting to Windows/Edge"
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042'
            }
        }
        return $UserAgent
    }
}
