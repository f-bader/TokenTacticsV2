BeforeAll {
    . "$PSScriptRoot/fixtures/TestData.ps1"
    Import-Module $script:ModulePath -Force
}

Describe "Get-ForgedUserAgent" {
    Context "Default (Windows/Edge)" {
        It "Returns a non-empty string" {
            $result = Get-ForgedUserAgent
            $result | Should -Not -BeNullOrEmpty
        }

        It "Returns Windows Edge UA by default" {
            $result = Get-ForgedUserAgent
            $result | Should -Match "Windows NT"
            $result | Should -Match "Edg"
        }
    }

    Context "Windows device" {
        It "Returns IE user agent for Windows/IE" {
            $result = Get-ForgedUserAgent -Device Windows -Browser IE
            $result | Should -Match "Trident"
        }

        It "Returns Chrome user agent for Windows/Chrome" {
            $result = Get-ForgedUserAgent -Device Windows -Browser Chrome
            $result | Should -Match "Chrome"
            $result | Should -Match "Windows NT"
        }

        It "Returns Firefox user agent for Windows/Firefox" {
            $result = Get-ForgedUserAgent -Device Windows -Browser Firefox
            $result | Should -Match "Firefox"
            $result | Should -Match "Windows NT"
        }
    }

    Context "Mac device" {
        It "Returns Safari user agent for Mac/Safari" {
            $result = Get-ForgedUserAgent -Device Mac -Browser Safari
            $result | Should -Match "Macintosh"
            $result | Should -Match "Safari"
        }

        It "Returns Chrome user agent for Mac/Chrome" {
            $result = Get-ForgedUserAgent -Device Mac -Browser Chrome
            $result | Should -Match "Macintosh"
            $result | Should -Match "Chrome"
        }

        It "Returns Edge user agent for Mac/Edge" {
            $result = Get-ForgedUserAgent -Device Mac -Browser Edge
            $result | Should -Match "Macintosh"
            $result | Should -Match "Edg"
        }

        It "Returns Firefox user agent for Mac/Firefox" {
            $result = Get-ForgedUserAgent -Device Mac -Browser Firefox
            $result | Should -Match "Macintosh"
            $result | Should -Match "Firefox"
        }
    }

    Context "iPhone device" {
        It "Returns Safari user agent for iPhone/Safari" {
            $result = Get-ForgedUserAgent -Device iPhone -Browser Safari
            $result | Should -Match "iPhone"
            $result | Should -Match "Safari"
        }

        It "Returns Chrome user agent for iPhone/Chrome" {
            $result = Get-ForgedUserAgent -Device iPhone -Browser Chrome
            $result | Should -Match "iPhone"
            $result | Should -Match "CriOS"
        }

        It "Returns Edge user agent for iPhone/Edge" {
            $result = Get-ForgedUserAgent -Device iPhone -Browser Edge
            $result | Should -Match "iPhone"
            $result | Should -Match "EdgiOS"
        }
    }

    Context "AndroidMobile device" {
        It "Returns Android user agent for AndroidMobile/Android" {
            $result = Get-ForgedUserAgent -Device AndroidMobile -Browser Android
            $result | Should -Match "Android"
        }

        It "Returns Chrome user agent for AndroidMobile/Chrome" {
            $result = Get-ForgedUserAgent -Device AndroidMobile -Browser Chrome
            $result | Should -Match "Android"
            $result | Should -Match "Chrome"
        }
    }

    Context "Linux device" {
        It "Returns Firefox user agent for Linux/Firefox" {
            $result = Get-ForgedUserAgent -Device Linux -Browser Firefox
            $result | Should -Match "Linux"
            $result | Should -Match "Firefox"
        }

        It "Returns Chrome user agent for Linux/Chrome" {
            $result = Get-ForgedUserAgent -Device Linux -Browser Chrome
            $result | Should -Match "Linux"
            $result | Should -Match "Chrome"
        }
    }

    Context "OS/2 device" {
        It "Returns Firefox user agent for OS/2" {
            $result = Get-ForgedUserAgent -Device "OS/2" -Browser Firefox
            $result | Should -Match "OS/2"
            $result | Should -Match "Firefox"
        }
    }

    Context "CustomUserAgent" {
        It "Returns the custom user agent string when provided" {
            $custom = "MyCustomAgent/1.0"
            $result = Get-ForgedUserAgent -CustomUserAgent $custom
            $result | Should -Be $custom
        }
    }

    Context "Invalid browser for device" {
        It "Falls back to a default and emits a warning for Windows with invalid browser" {
            $result = Get-ForgedUserAgent -Device Windows -Browser Safari -WarningVariable warning
            $result | Should -Not -BeNullOrEmpty
            $warning.Message | Should -Match 'not valid'
        }
    }
}
