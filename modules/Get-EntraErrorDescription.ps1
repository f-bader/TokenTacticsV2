function Get-EntraErrorDescription {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    if (-not [string]::IsNullOrWhiteSpace($ErrorRecord.ErrorDetails.Message)) {
        try {
            $details = $ErrorRecord.ErrorDetails.Message | ConvertFrom-Json -ErrorAction Stop
            if (-not [string]::IsNullOrWhiteSpace($details.error_description)) {
                return $details.error_description
            }
        } catch {
            return $ErrorRecord.ErrorDetails.Message
        }
    }

    return $ErrorRecord.Exception.Message
}
