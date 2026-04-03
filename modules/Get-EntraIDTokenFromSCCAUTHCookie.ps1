function Get-EntraIDTokenFromSCCAUTHCookie {
    <#
    .SYNOPSIS
        Retrieves authentication tokens for various Microsoft security services through the XDR portal.

    .DESCRIPTION
        Gets authentication tokens from Microsoft Defender XDR portal for accessing various Microsoft security services and resources.
        Authenticates using the sccauth cookie and optionally an XSRF token. If XSRF is not provided, it will be obtained automatically
        by making an initial request to security.microsoft.com.
        Supports both predefined resource names and manual resource specification.

    .PARAMETER SCCAuth
        The sccauth cookie value from an authenticated session to security.microsoft.com.

    .PARAMETER XSRF
        The XSRF-TOKEN cookie value from an authenticated session to security.microsoft.com.
        If not provided, XSRF-TOKEN is obtained automatically using the provided SCCAuth value.

    .PARAMETER ResourceName
        The name of the predefined resource to get a token for. Valid values are:
        - Azure: Azure Management API
        - LogAnalytics: Log Analytics API
        - MATP: Microsoft Defender for Endpoint
        - MCAS: Microsoft Defender for Cloud Apps
        - MicrosoftGraph: Microsoft Graph API
        - MicrosoftOffice: Microsoft Office API
        - Purview: Microsoft Purview API
        - PurviewACC: Microsoft Purview Compliance Center
        - ThreatIntelligencePortal: Threat Intelligence Portal

    .PARAMETER Resource
        The custom resource URL or ID to get a token for. Use this for resources not covered by ResourceName.

    .PARAMETER TenantId
        Optional. The Tenant ID to include in request headers (x-tid, tenant-id) and to use for PurviewACC resource construction.
        If not provided for PurviewACC, the Tenant ID will be retrieved automatically from the XDR portal.

    .PARAMETER ServiceType
        Optional. The service type for the custom resource.

    .EXAMPLE
        Get-EntraIDTokenFromSCCAUTHCookie -SCCAuth "your_sccauth_value" -ResourceName "MicrosoftGraph"
        Retrieves an authentication token for Microsoft Graph API.

    .EXAMPLE
        Get-EntraIDTokenFromSCCAUTHCookie -SCCAuth "your_sccauth_value" -XSRF "your_xsrf_value" -ResourceName "MATP"
        Retrieves an authentication token for Microsoft Defender for Endpoint.

    .EXAMPLE
        Get-EntraIDTokenFromSCCAUTHCookie -SCCAuth "your_sccauth_value" -Resource "https://management.core.windows.net/"
        Retrieves an authentication token for a custom resource URL.

    .OUTPUTS
        Object
        Returns the authentication token response object.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$SCCAuth,

        [Parameter()]
        [string]$XSRF,

        [Parameter(Mandatory, ParameterSetName = 'Automatic')]
        [ValidateSet('Azure', 'LogAnalytics', 'MATP', 'MCAS', 'MicrosoftGraph', 'MicrosoftOffice', 'Purview', 'PurviewACC', 'ThreatIntelligencePortal')]
        [string]$ResourceName,

        [Parameter(Mandatory, ParameterSetName = 'Manual')]
        [string]$Resource,

        [Parameter(ParameterSetName = 'Manual')]
        [string]$ServiceType,

        [Parameter()]
        [string]$TenantId
    )
    begin {
        Write-Verbose "Setting session cookies for XDR requests"
        $xdrSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $xdrSession.Cookies.Add((New-Object System.Net.Cookie("sccauth", $SCCAuth, "/", "security.microsoft.com")))

        if ($PSBoundParameters.ContainsKey('XSRF')) {
            $XsrfValue = $XSRF
        } else {
            Write-Verbose "Obtaining XSRF token from security.microsoft.com"
            $null = Invoke-WebRequest -UseBasicParsing -ErrorAction SilentlyContinue -WebSession $xdrSession -Method Get -Uri "https://security.microsoft.com/" -Verbose:$false
            $XsrfValue = $xdrSession.Cookies.GetCookies("https://security.microsoft.com")['xsrf-token'].Value
            if ([string]::IsNullOrWhiteSpace($XsrfValue)) {
                throw "Failed to obtain XSRF-TOKEN cookie from security.microsoft.com. Verify the provided SCCAuth value."
            }
        }
        $xdrSession.Cookies.Add((New-Object System.Net.Cookie("XSRF-TOKEN", $XsrfValue, "/", "security.microsoft.com")))

        [Hashtable]$xdrHeaders = @{}
        $xdrHeaders["X-XSRF-TOKEN"] = [System.Net.WebUtility]::UrlDecode($XsrfValue)
        if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
            $xdrHeaders["x-tid"] = $TenantId
            $xdrHeaders["tenant-id"] = $TenantId
        }
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Automatic') {
            switch ($ResourceName) {
                'Azure' {
                    $Resource = "https://management.core.windows.net/"
                    $ServiceType = $null
                }
                'LogAnalytics' {
                    $Resource = "ca7f3f0b-7d91-482c-8e09-c5d840d0eac5"
                }
                'MATP' {
                    # https://securitycenter.microsoft.com/mtp
                    $Resource = "MATP"
                }
                'MCAS' {
                    # Microsoft Defender for Cloud Apps
                    $Resource = "MCAS"
                }
                'MicrosoftGraph' {
                    $Resource = "https://graph.microsoft.com/"
                }
                'MicrosoftOffice' {
                    $Resource = "https://portal.office.com"
                }
                'Purview' {
                    $Resource = "https://api.purview-service.microsoft.com"
                    # 73c2949e-da2d-457a-9607-fcc665198967 = Azure Purview
                    $ServiceType = "73c2949e-da2d-457a-9607-fcc665198967"
                }
                'PurviewACC' {
                    if ([string]::IsNullOrWhiteSpace($TenantId)) {
                        $XdrTenantContext = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/sccManagement/mgmt/TenantContext?realTime=true" -ContentType "application/json" -WebSession $xdrSession -Headers $xdrHeaders
                        $TenantId = $XdrTenantContext.AuthInfo.TenantId
                    }
                    $Resource = "https://$($TenantId)-api.purview-service.microsoft.com"
                    # 73c2949e-da2d-457a-9607-fcc665198967 = Azure Purview
                    $ServiceType = "73c2949e-da2d-457a-9607-fcc665198967"
                }
                'ThreatIntelligencePortal' {
                    $Resource = "478d8d1a-326f-49da-a58e-8f576faa4b5e"
                }
                default {
                    throw "Unsupported ResourceName: $ResourceName"
                }
            }
        }
        Write-Verbose "Retrieving XDR token for service"
        $encodedResource = [System.Web.HttpUtility]::UrlEncode($Resource)
        if ( [string]::IsNullOrWhiteSpace($ServiceType) ) {
            $uri = "https://security.microsoft.com/api/Auth/getToken?resource=$encodedResource"
        } else {
            $uri = "https://security.microsoft.com/api/Auth/getToken?resource=$encodedResource&serviceType=$ServiceType"
        }
        Write-Verbose "Request URI: $uri"
        Invoke-RestMethod -Uri $uri -ContentType "application/json" -WebSession $xdrSession -Headers $xdrHeaders
    }

    end {

    }
}