function Invoke-EntraErrorHandling {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$AppConfig
    )

    #region Define variables
    $ErrorTitle = ( "Your account is blocked",
        "You cannot access this right now",
        "You can't get there from here",
        "Oops - You can't get to this yet",
        "You don't have access to this",
        "Help us keep your device secure",
        "Your sign-in was blocked",
        "You cannot proceed right now",
        "Set up your device to get access",
        "Get access to this resource",
        "Sorry, you can't get to this yet",
        "Try signing in another way",
        "Register or enroll your device",
        "Sorry, a security policy is preventing access",
        "Let's try something else",
        "Sign in with your work account",
        "Device must comply with your organization's compliance requirements",
        "We need to update your device registration",
        "Install or update Microsoft Authenticator to continue",
        "Install or update Microsoft Company Portal to continue"
    )
    $ErrorDescription = @(
        "We've detected suspicious activity on your account.",
        "It looks like you're trying to open this resource with an app that hasn't been approved by your IT department. Ask them for a list of approved applications.",
        "Your sign-in was successful but your admin requires your device to be managed by {0} to access this resource.",
        "Your sign-in was successful but does not meet the criteria to access this resource. For example, you might be signing in from a browser, app, or location that is restricted by your admin.",
        "Your sign-in was successful but you don't have permission to access this resource.",
        "Your IT department is ensuring that this device is up-to-date with all your organization's policies. It might take a few minutes.",
        "Your sign-in was successful but your admin requires the device requesting access to be managed by {0} to access this resource.",
        "You cannot access the resource from this browser on your device. You need to use Safari or Intune Managed Browser.",
        "You cannot access the resource from this browser on your device. You need to use Microsoft Edge.",
        "Your sign-in was successful, but you can't open this resource from this web browser. You might be able to access it from the Safari browser (ask your IT department for a list of approved mobile and desktop applications).",
        "You cannot access the resource from this browser on your device. You need to use Chrome or Intune Managed Browser.",
        "You cannot access the resource from this browser on your device. You need to use Chrome or Edge.",
        "You must use the Intune Managed Browser application before you can access this resource.",
        "You must use Microsoft Edge to access this resource.",
        "To access this resource, sign in or switch to your work or school account in Microsoft Edge.",
        "This application contains sensitive information and can only be accessed from:",
        "We've detected something unusual about this sign-in. For example, you might be signing in from a new location, device, or app. Before you can continue, we need to verify your identity. Please contact your admin.",
        "Your device isn't up to date with your organization\'s policies. Check its status and take action in your organization's device management portal",
        "Your sign-in was successful, but your device must be registered with {0} before you can use this site.",
        "It looks like you're trying to open this resource with a client app that is not available for use with app protection policies. Ask your IT department or see a list of applications that are protected here.",
        "It looks like you're trying to open this resource with a client app that is not available for use with app protection policies. Please try using the latest version of the client application or ask your IT department. You can see a list of applications that are protected here.",
        "We are currently unable to collect additional security information. Your organization requires this information to be set from specific locations or devices.",
        "Your sign-in was successful but does not meet the criteria to add an account to the Microsoft Authenticator app. For example, you might be signing in from a location or device that is restricted by your admin. You may add an account to the app by scanning a QR Code provided to you by your admin.",
        "{0} requires you to secure this device before you can access {0} email, files and data.",
        "This device does not meet your organization's compliance requirements. Open your organization's device management portal to take action.",
        "You can't complete this action because you're trying to access protected resources as an external user in this organization. Please contact the admin to allow you to access the protected resources.",
        "To access your service, app, or website, you may need to sign in to Microsoft Edge using {1}",
        "To access this app, website, or service, you'll need to register or enroll your device.",
        "An organization security policy requiring token protection is preventing this application from accessing the resource. You may be able to use a different application.",
        "Additional sign-in methods are required to access this resource. Contact your administrator to enable these methods.",
        "An authentication policy cannot be fulfilled. Please contact your administrator."
    )
    #endregion

    #region Output nice error messages
    if ($AppConfig.sErrorCode -eq "50058") {
        Write-Output "$([char]0x274C)  Error code $($AppConfig.sErrorCode) received from the authorize endpoint"
        Write-Output "    Session information is not sufficient for single-sign-on."
        Write-Output "    This means that a user is not signed in. This is a common error that's expected when a user is unauthenticated and"
        Write-Output "    has not yet signed in. If this error is encountered in an SSO context where the user has previously signed in,"
        Write-Output "    this means that the SSO session was either not found or invalid. This error may be returned to the application"
        Write-Output "    if prompt=none is specified."
        Write-Output "$([char]0x26A0)  TokenTactics does not support interactive logins. Please get a valid cookie from a signed-in session or use Get-AzureToken to get a token via the device code flow."
    } elseif ($AppConfig.sErrorCode -eq "53003") {
        Write-Output "$([char]0x274C)  Error code $($AppConfig.sErrorCode) received from the authorize endpoint"
        Write-Output "    Access has been blocked by Conditional Access policies. The access policy does not allow token issuance."
        Write-Output "    If this is unexpected, see the conditional access policy that applied to this request in the Azure Portal."
        if ( -not [string]::IsNullOrWhiteSpace($AppConfig.urlTokenBindingLearnMore)) {
            Write-Output "    Learn more about token binding - $($AppConfig.urlTokenBindingLearnMore)"
        }
    } elseif (-not [string]::IsNullOrWhiteSpace($AppConfig.sErrorCode)) {
        Write-Output "$([char]0x274C)  Error code $($AppConfig.sErrorCode) received from the authorize endpoint"
        Write-Output "    $($ErrorTitle[$AppConfig.iErrorTitle - 1])"
        Write-Output "    $($ErrorDescription[$AppConfig.iErrorDescription - 1])"
    } elseif ( -not [string]::IsNullOrWhiteSpace($AppConfig.strMainMessage) ) {
        Write-Output "$([char]0x274C)  $($AppConfig.strMainMessage)"
        Write-Output "    $($AppConfig.strServiceExceptionMessage)"
    } else {
        Write-Output "$([char]0x274C)  ENo error code received from the authorize endpoint"
    }
    if ( -not [string]::IsNullOrWhiteSpace($AppConfig.sDeviceId)) {
        Write-Output "$([char]0x2718)  Device Id:`t`t$($AppConfig.sDeviceId)"
    }
    if ( -not [string]::IsNullOrWhiteSpace($AppConfig.sDeviceState)) {
        Write-Output "$([char]0x2718)  Device state:`t$($AppConfig.sDeviceState)"
    }
    if ( -not [string]::IsNullOrWhiteSpace($AppConfig.correlationId)) {
        Write-Output "$([char]0x2718)  Correlation Id:`t$($AppConfig.correlationId)"
    }
    if ( -not [string]::IsNullOrWhiteSpace($AppConfig.sessionId)) {
        Write-Output "$([char]0x2718)  Session Id:`t`t$($AppConfig.sessionId)"
    }
    if ( -not [string]::IsNullOrWhiteSpace($AppConfig.sPOST_Username)) {
        Write-Output "$([char]0x2718)  Username:`t`t$($AppConfig.sPOST_Username)"
    }
    #endregion
}