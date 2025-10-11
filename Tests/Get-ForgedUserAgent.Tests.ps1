BeforeAll {
    # Dot-source the function file directly for faster test execution
    . "$PSScriptRoot/../modules/Get-ForgedUserAgent.ps1"
}

Describe "Get-ForgedUserAgent" {
    Context "Default Behavior" {
        It "Should return Windows Edge user agent by default" {
            $result = Get-ForgedUserAgent
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*Windows NT 10.0*"
            $result | Should -BeLike "*Edge*"
        }
    }

    Context "Custom User Agent" {
        It "Should return custom user agent when provided" {
            $customUA = "CustomUserAgent/1.0"
            
            $result = Get-ForgedUserAgent -CustomUserAgent $customUA
            
            $result | Should -Be $customUA
        }
    }

    Context "Windows Device" {
        It "Should return Windows IE user agent" {
            $result = Get-ForgedUserAgent -Device Windows -Browser IE
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*Windows NT 10.0*"
            $result | Should -BeLike "*Trident*"
        }

        It "Should return Windows Chrome user agent" {
            $result = Get-ForgedUserAgent -Device Windows -Browser Chrome
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*Windows NT 10.0*"
            $result | Should -BeLike "*Chrome*"
        }

        It "Should return Windows Firefox user agent" {
            $result = Get-ForgedUserAgent -Device Windows -Browser Firefox
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*Windows NT 10.0*"
            $result | Should -BeLike "*Firefox*"
        }

        It "Should return Windows Edge user agent" {
            $result = Get-ForgedUserAgent -Device Windows -Browser Edge
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*Windows NT 10.0*"
            $result | Should -BeLike "*Edge*"
        }
    }

    Context "Mac Device" {
        It "Should return Mac Chrome user agent" {
            $result = Get-ForgedUserAgent -Device Mac -Browser Chrome
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*Macintosh*"
            $result | Should -BeLike "*Chrome*"
        }

        It "Should return Mac Firefox user agent" {
            $result = Get-ForgedUserAgent -Device Mac -Browser Firefox
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*Macintosh*"
            $result | Should -BeLike "*Firefox*"
        }

        It "Should return Mac Edge user agent" {
            $result = Get-ForgedUserAgent -Device Mac -Browser Edge
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*Macintosh*"
            $result | Should -BeLike "*Edg*"
        }

        It "Should return Mac Safari user agent" {
            $result = Get-ForgedUserAgent -Device Mac -Browser Safari
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*Macintosh*"
            $result | Should -BeLike "*Safari*"
        }
    }

    Context "Linux Device" {
        It "Should return Linux Chrome user agent" {
            $result = Get-ForgedUserAgent -Device Linux -Browser Chrome
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*Linux*"
            $result | Should -BeLike "*Chrome*"
        }

        It "Should return Linux Firefox user agent" {
            $result = Get-ForgedUserAgent -Device Linux -Browser Firefox
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*Linux*"
            $result | Should -BeLike "*Firefox*"
        }

        It "Should return Linux Edge user agent" {
            $result = Get-ForgedUserAgent -Device Linux -Browser Edge
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*Linux*"
            $result | Should -BeLike "*Edg*"
        }
    }

    Context "AndroidMobile Device" {
        It "Should return Android user agent" {
            $result = Get-ForgedUserAgent -Device AndroidMobile -Browser Android
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*Android*"
        }

        It "Should return Android Chrome user agent" {
            $result = Get-ForgedUserAgent -Device AndroidMobile -Browser Chrome
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*Android*"
            $result | Should -BeLike "*Chrome*"
        }

        It "Should return Android Firefox user agent" {
            $result = Get-ForgedUserAgent -Device AndroidMobile -Browser Firefox
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*Android*"
            $result | Should -BeLike "*Firefox*"
        }

        It "Should return Android Edge user agent" {
            $result = Get-ForgedUserAgent -Device AndroidMobile -Browser Edge
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*Android*"
            $result | Should -BeLike "*Edg*"
        }
    }

    Context "iPhone Device" {
        It "Should return iPhone Chrome user agent" {
            $result = Get-ForgedUserAgent -Device iPhone -Browser Chrome
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*iPhone*"
            $result | Should -BeLike "*CriOS*"
        }

        It "Should return iPhone Firefox user agent" {
            $result = Get-ForgedUserAgent -Device iPhone -Browser Firefox
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*iPhone*"
            $result | Should -BeLike "*FxiOS*"
        }

        It "Should return iPhone Edge user agent" {
            $result = Get-ForgedUserAgent -Device iPhone -Browser Edge
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*iPhone*"
            $result | Should -BeLike "*EdgiOS*"
        }

        It "Should return iPhone Safari user agent" {
            $result = Get-ForgedUserAgent -Device iPhone -Browser Safari
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*iPhone*"
            $result | Should -BeLike "*Safari*"
        }
    }

    Context "OS/2 Device" {
        It "Should return OS/2 Firefox user agent" {
            $result = Get-ForgedUserAgent -Device 'OS/2' -Browser Firefox
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*OS/2*"
            $result | Should -BeLike "*Firefox*"
        }
    }

    Context "Browser Only Parameter" {
        It "Should return Edge user agent when only Browser is specified" {
            $result = Get-ForgedUserAgent -Browser Edge
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*Edge*"
        }

        It "Should return Chrome user agent when only Browser is specified" {
            $result = Get-ForgedUserAgent -Browser Chrome
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*Chrome*"
        }
    }

    Context "Device Only Parameter" {
        It "Should return Mac Edge user agent when only Device Mac is specified" {
            $result = Get-ForgedUserAgent -Device Mac
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*Macintosh*"
        }

        It "Should return Windows Edge user agent when only Device Windows is specified" {
            $result = Get-ForgedUserAgent -Device Windows
            
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeLike "*Windows*"
        }
    }
}
