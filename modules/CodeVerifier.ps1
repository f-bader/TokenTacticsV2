function Get-TTCodeVerifier {
    # Generate a random string to be used as the code verifier. Expects a 43 character string
    $codeVerifier = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([System.Guid]::NewGuid().ToString("N"))).Replace("=", "").Replace("+", "-").Replace("/", "_")
    return $codeVerifier
}

function Get-TTCodeChallenge {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $codeVerifier
    )
    # Hash the code verifier using SHA-256 and then base64url encode it to generate the code challenge
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $codeChallengeBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($codeVerifier))
    $codeChallenge = [System.Convert]::ToBase64String($codeChallengeBytes).Replace("=", "").Replace("+", "-").Replace("/", "_")
    return $codeChallenge
}