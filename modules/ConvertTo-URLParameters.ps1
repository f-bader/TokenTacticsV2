function ConvertTo-URLParameters {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $RequestURL
    )
    $uri = [System.Uri]::new($RequestURL)
    # Get the parameters from the redirect URI and build a hashtable containing the different parameters
    $query = $uri.Query.TrimStart('?')
    $queryParams = @{}
    $paramPairs = $query.Split('&')

    foreach ($pair in $paramPairs) {
        $parts = $pair.Split('=')
        $key = $parts[0]
        $value = $parts[1]
        $queryParams[$key] = $value
    }
    return $queryParams
}