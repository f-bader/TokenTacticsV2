@{
    Run          = @{
        Path     = './tests'
        PassThru = $true
    }
    Filter       = @{
        ExcludeTag = @('Integration')
    }
    Output       = @{
        Verbosity = 'Normal'
    }
    TestResult   = @{
        Enabled      = $true
        OutputFormat = 'NUnitXml'
        OutputPath   = './test-results.xml'
    }
    CodeCoverage = @{
        Enabled               = $true
        Path                  = @('./modules/*.ps1', './TokenTactics.psm1')
        CoveragePercentTarget = 60
        OutputFormat          = 'JaCoCo'
        OutputPath            = './coverage.xml'
    }
}
