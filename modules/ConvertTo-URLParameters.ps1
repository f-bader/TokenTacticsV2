function ConvertTo-URLParameters {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $RequestURL
    )
    $uri = [System.Uri]::new($RequestURL)
    # Get the parameters from the redirect URI and build a hashtable containing the different parameters
    $queryParams = @{}
    $query = $uri.Query.TrimStart('?')
    if ([string]::IsNullOrEmpty($query)) {
        return $queryParams
    }

    foreach ($pair in $query.Split('&')) {
        if ([string]::IsNullOrEmpty($pair)) {
            continue
        }

        $parts = $pair.Split('=', 2)
        $key = [System.Net.WebUtility]::UrlDecode($parts[0])
        $value = if ($parts.Count -eq 2) {
            [System.Net.WebUtility]::UrlDecode($parts[1])
        } else {
            ''
        }
        $queryParams[$key] = $value
    }
    return $queryParams
}
