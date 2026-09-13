BeforeAll {
    $script:RepositoryRoot = Split-Path $PSScriptRoot -Parent
    $script:Manifest = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'TokenTactics.psd1')
    $script:CommandIndex = Get-Content (Join-Path $script:RepositoryRoot 'docs/commands/README.md') -Raw
    $script:MarkdownFiles = @(Get-ChildItem -Path $script:RepositoryRoot -Filter '*.md' -File -Recurse |
        Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' })

    function Get-TestMarkdownAnchors {
        param([Parameter(Mandatory)][string]$Path)
        $counts = @{}
        $anchors = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($line in Get-Content -LiteralPath $Path) {
            if ($line -notmatch '^#{1,6}\s+(.+?)\s*$') { continue }
            $heading = $Matches[1] -replace '\s+#+\s*$', ''
            $slug = $heading.ToLowerInvariant()
            $slug = $slug -replace '<[^>]+>', ''
            $slug = $slug -replace '[^\p{L}\p{N}\s_-]', ''
            $slug = ($slug -replace '\s', '-').Trim('-')
            if ($counts.ContainsKey($slug)) {
                $counts[$slug]++
                $slug = "$slug-$($counts[$slug])"
            } else {
                $counts[$slug] = 0
            }
            [void]$anchors.Add($slug)
        }
        return $anchors
    }
}

Describe 'Documentation integrity' {
    It 'indexes every exported function and alias' {
        foreach ($command in @($script:Manifest.FunctionsToExport) + @($script:Manifest.AliasesToExport)) {
            $script:CommandIndex | Should -Match ([regex]::Escape($command))
        }
    }

    It 'contains no unresolved merge-conflict markers' {
        foreach ($file in $script:MarkdownFiles) {
            (Get-Content -LiteralPath $file.FullName -Raw) |
                Should -Not -Match '(?m)^(<<<<<<< .+|=======|>>>>>>> .+)$'
        }
    }

    It 'resolves every local Markdown target and anchor' {
        $errors = [System.Collections.Generic.List[string]]::new()
        foreach ($file in $script:MarkdownFiles) {
            $content = Get-Content -LiteralPath $file.FullName -Raw
            foreach ($match in [regex]::Matches($content, '!?(?<!\!)\[[^\]]*\]\(([^)]+)\)')) {
                $destination = $match.Groups[1].Value.Trim()
                if ($destination -match '^(?:https?://|mailto:)' -or [string]::IsNullOrWhiteSpace($destination)) { continue }
                if ($destination.StartsWith('<') -and $destination.EndsWith('>')) {
                    $destination = $destination.Substring(1, $destination.Length - 2)
                }
                $parts = $destination.Split('#', 2)
                $relativePath = [System.Net.WebUtility]::UrlDecode($parts[0])
                $anchor = if ($parts.Count -eq 2) { [System.Net.WebUtility]::UrlDecode($parts[1]).ToLowerInvariant() } else { $null }
                $target = if ([string]::IsNullOrWhiteSpace($relativePath)) {
                    $file.FullName
                } else {
                    [IO.Path]::GetFullPath((Join-Path $file.DirectoryName $relativePath))
                }
                if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
                    $errors.Add("$($file.FullName): missing target '$destination'")
                    continue
                }
                if ($anchor) {
                    $anchors = Get-TestMarkdownAnchors -Path $target
                    if (-not $anchors.Contains($anchor)) {
                        $errors.Add("$($file.FullName): missing anchor '#$anchor' in '$target'")
                    }
                }
            }
        }
        $errors | Should -BeNullOrEmpty
    }
}
