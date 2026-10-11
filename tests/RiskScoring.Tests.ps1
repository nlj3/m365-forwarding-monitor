#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares BeforeDiscovery and BeforeEach variables with It blocks.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Justification = 'The stub functions are global so the script under test can call them, and they read the current scenario from one global variable.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'The stub functions accept the same parameters as the commands they replace but do not need them.')]
param()

# Unit tests for src/RiskScoring.psm1, plus an offline run of src/Invoke-ForwardingMonitor.ps1
# against stubbed Microsoft calls.
# All fixture data is synthetic: contoso.com, contoso.onmicrosoft.com and example.com only.

BeforeDiscovery {
    $sourceFiles = Get-ChildItem -Path (Join-Path (Join-Path $PSScriptRoot '..') 'src') -File |
        Where-Object { $_.Extension -in '.ps1', '.psm1' } |
        ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } }
}

BeforeAll {
    $modulePath = Join-Path (Join-Path $PSScriptRoot '..') 'src/RiskScoring.psm1'
    Import-Module $modulePath -Force

    function Get-TestSetting {
        param([hashtable]$Override = @{})
        $values = [ordered]@{ OutboundWarningThreshold = 100; OutboundCriticalThreshold = 250 }
        foreach ($key in $Override.Keys) { $values[$key] = $Override[$key] }
        return [pscustomobject]$values
    }

    function Get-OutboundLevel {
        param(
            [int]$Sent = 0,
            [int]$AfterHours = 0,
            [int]$Samples = 5,
            [bool]$Above = $false,
            [object]$Settings = (Get-TestSetting)
        )
        return Get-M365OutboundRiskLevel -ExternalSentCount $Sent -AfterHoursCount $AfterHours `
            -BaselineSampleCount $Samples -IsAboveBaseline $Above -Settings $Settings
    }

    function Get-TestExceptionRow {
        param(
            [string]$User = 'alex@contoso.com',
            [string]$Target = 'archive@example.com',
            [string]$Expires = ''
        )
        return [pscustomobject]@{
            UserPrincipalName = $User
            ApprovedTarget    = $Target
            Reason            = 'Synthetic test row'
            ApprovedBy        = 'security.manager@contoso.com'
            ExpirationDate    = $Expires
        }
    }

    function Get-TestDateText {
        param([int]$OffsetDays)
        return (Get-Date).AddDays($OffsetDays).ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
    }

    function Get-TestFailure {
        param([string]$Message = 'request failed', [object]$StatusCode)
        $failure = [System.InvalidOperationException]::new($Message)
        if ($null -ne $StatusCode) {
            $failure | Add-Member -NotePropertyName Response -NotePropertyValue ([pscustomobject]@{ StatusCode = $StatusCode })
        }
        return $failure
    }
}

AfterAll {
    Remove-Module RiskScoring -Force -ErrorAction SilentlyContinue
}

Describe 'Get-M365TargetDomain' {
    It 'returns the lower-cased domain of a plain address: <Target>' -ForEach @(
        @{ Target = 'alex@contoso.com' }
        @{ Target = 'ALEX@Contoso.COM' }
        @{ Target = '   alex@contoso.com   ' }
        @{ Target = 'alex+tag@CONTOSO.com' }
    ) {
        Get-M365TargetDomain -Target $Target | Should -BeExactly 'contoso.com'
    }

    It 'extracts the address from an SMTP: prefix or a display-name form: <Target>' -ForEach @(
        @{ Target = 'SMTP:alex@example.com' }
        @{ Target = 'smtp:alex@Example.com' }
        @{ Target = 'Alex Wilber <alex@example.com>' }
        @{ Target = '"Wilber, Alex" <alex@example.com>' }
        @{ Target = '<alex@example.com>' }
    ) {
        Get-M365TargetDomain -Target $Target | Should -BeExactly 'example.com'
    }

    It 'keeps subdomains and a trailing dot as written instead of normalising them' {
        Get-M365TargetDomain -Target 'alex@mail.contoso.com' | Should -BeExactly 'mail.contoso.com'
        Get-M365TargetDomain -Target 'alex@contoso.com.' | Should -BeExactly 'contoso.com.'
    }

    It 'returns no domain when there is nothing usable: <Name>' -ForEach @(
        @{ Name = 'null'; Target = $null }
        @{ Name = 'empty string'; Target = '' }
        @{ Name = 'whitespace only'; Target = '   ' }
        @{ Name = 'bare domain without an at sign'; Target = 'contoso.com' }
        @{ Name = 'display name only'; Target = 'Alex Wilber' }
        @{ Name = 'canonical recipient path'; Target = 'contoso.com/Staff/Alex Wilber' }
        @{ Name = 'address with nothing after the at sign'; Target = 'alex@' }
    ) {
        $result = Get-M365TargetDomain -Target $Target
        $result | Should -BeNullOrEmpty
    }
}

Describe 'Test-M365InternalDomain' {
    It 'matches a listed domain exactly, ignoring case on both sides: <Domain>' -ForEach @(
        @{ Domain = 'contoso.com' }
        @{ Domain = 'CONTOSO.com' }
        @{ Domain = 'contoso.onmicrosoft.com' }
    ) {
        Test-M365InternalDomain -Domain $Domain -InternalDomains @('Contoso.COM', 'contoso.onmicrosoft.com') |
            Should -BeTrue
    }

    It 'does not match subdomains, lookalikes, blanks or an empty list: <Name>' -ForEach @(
        @{ Name = 'subdomain of a listed domain'; Domain = 'mail.contoso.com'; Internal = @('contoso.com') }
        @{ Name = 'longer lookalike'; Domain = 'notcontoso.com'; Internal = @('contoso.com') }
        @{ Name = 'listed domain used as a prefix'; Domain = 'contoso.com.example.com'; Internal = @('contoso.com') }
        @{ Name = 'null domain'; Domain = $null; Internal = @('contoso.com') }
        @{ Name = 'whitespace domain'; Domain = '  '; Internal = @('contoso.com') }
        @{ Name = 'domain with padding spaces'; Domain = ' contoso.com '; Internal = @('contoso.com') }
        @{ Name = 'empty internal list'; Domain = 'contoso.com'; Internal = @() }
    ) {
        Test-M365InternalDomain -Domain $Domain -InternalDomains $Internal | Should -BeFalse
    }
}

Describe 'Test-M365PersonalDomain' {
    It 'matches only exact listed domains, ignoring case: <Name>' -ForEach @(
        @{ Name = 'listed'; Domain = 'webmail.example.com'; List = @('webmail.example.com', 'FREEMAIL.example.com'); Expected = $true }
        @{ Name = 'listed, different case'; Domain = 'WEBMAIL.example.com'; List = @('webmail.example.com', 'FREEMAIL.example.com'); Expected = $true }
        @{ Name = 'listed, list entry in upper case'; Domain = 'freemail.example.com'; List = @('webmail.example.com', 'FREEMAIL.example.com'); Expected = $true }
        @{ Name = 'corporate domain'; Domain = 'contoso.com'; List = @('webmail.example.com', 'FREEMAIL.example.com'); Expected = $false }
        @{ Name = 'subdomain of a listed domain'; Domain = 'mail.webmail.example.com'; List = @('webmail.example.com', 'FREEMAIL.example.com'); Expected = $false }
        @{ Name = 'null domain'; Domain = $null; List = @('webmail.example.com', 'FREEMAIL.example.com'); Expected = $false }
        @{ Name = 'empty domain'; Domain = ''; List = @('webmail.example.com', 'FREEMAIL.example.com'); Expected = $false }
        @{ Name = 'empty personal list'; Domain = 'webmail.example.com'; List = @(); Expected = $false }
    ) {
        Test-M365PersonalDomain -Domain $Domain -PersonalDomains $List | Should -Be $Expected
    }
}

Describe 'Test-M365ApprovedException' {
    It 'approves nothing when there are no exceptions or no target: <Name>' -ForEach @(
        @{ Name = 'no exceptions supplied'; Target = 'archive@example.com'; Rows = @() }
        @{ Name = 'null target'; Target = $null; Rows = @('row') }
        @{ Name = 'blank target'; Target = '  '; Rows = @('row') }
    ) {
        $rows = if ($Rows.Count -gt 0) { @(Get-TestExceptionRow -Target '*') } else { @() }
        Test-M365ApprovedException -UserPrincipalName 'alex@contoso.com' -Target $Target -ApprovedExceptions $rows |
            Should -BeFalse
    }

    It 'approves the user and address named in the exception, ignoring case and an SMTP: prefix: <Target>' -ForEach @(
        @{ Target = 'archive@example.com' }
        @{ Target = 'ARCHIVE@Example.COM' }
        @{ Target = 'SMTP:archive@example.com' }
    ) {
        $rows = @(Get-TestExceptionRow -User 'Alex@Contoso.com' -Target 'archive@example.com')
        Test-M365ApprovedException -UserPrincipalName 'alex@contoso.com' -Target $Target -ApprovedExceptions $rows |
            Should -BeTrue
    }

    It 'also approves a different address at the same domain, so an address exception acts as a domain exception' {
        $rows = @(Get-TestExceptionRow -Target 'archive@example.com')
        Test-M365ApprovedException -UserPrincipalName 'alex@contoso.com' -Target 'someone.else@example.com' -ApprovedExceptions $rows |
            Should -BeTrue
    }

    It 'does not approve another domain, a subdomain, or another user: <Name>' -ForEach @(
        @{ Name = 'different domain'; User = 'alex@contoso.com'; Target = 'archive@contoso.com' }
        @{ Name = 'subdomain of the approved domain'; User = 'alex@contoso.com'; Target = 'archive@mail.example.com' }
        @{ Name = 'different user'; User = 'sam@contoso.com'; Target = 'archive@example.com' }
    ) {
        $rows = @(Get-TestExceptionRow -User 'alex@contoso.com' -Target 'archive@example.com')
        Test-M365ApprovedException -UserPrincipalName $User -Target $Target -ApprovedExceptions $rows | Should -BeFalse
    }

    It 'treats <Wildcard> as a user-wide exception for any target, but only for that user' -ForEach @(
        @{ Wildcard = '*' }
        @{ Wildcard = 'any' }
        @{ Wildcard = 'ANY' }
    ) {
        $rows = @(Get-TestExceptionRow -User 'alex@contoso.com' -Target $Wildcard)
        Test-M365ApprovedException -UserPrincipalName 'alex@contoso.com' -Target 'x@example.com' -ApprovedExceptions $rows | Should -BeTrue
        Test-M365ApprovedException -UserPrincipalName 'sam@contoso.com' -Target 'x@example.com' -ApprovedExceptions $rows | Should -BeFalse
    }

    It 'matches a bare-domain exception only against a bare-domain target, not against addresses at that domain' {
        $rows = @(Get-TestExceptionRow -Target 'example.com')
        Test-M365ApprovedException -UserPrincipalName 'alex@contoso.com' -Target 'example.com' -ApprovedExceptions $rows | Should -BeTrue
        Test-M365ApprovedException -UserPrincipalName 'alex@contoso.com' -Target 'archive@example.com' -ApprovedExceptions $rows | Should -BeFalse
    }

    It 'skips rows with a blank user or blank approved target and still finds a later valid row' {
        $blankRows = @(
            (Get-TestExceptionRow -User '' -Target '*'),
            (Get-TestExceptionRow -User 'alex@contoso.com' -Target '')
        )
        Test-M365ApprovedException -UserPrincipalName 'alex@contoso.com' -Target 'x@example.com' -ApprovedExceptions $blankRows |
            Should -BeFalse

        $withValidRow = @($blankRows + (Get-TestExceptionRow -Target 'x@example.com'))
        Test-M365ApprovedException -UserPrincipalName 'alex@contoso.com' -Target 'x@example.com' -ApprovedExceptions $withValidRow |
            Should -BeTrue
    }

    It 'ignores an exception that expired yesterday' {
        $rows = @(Get-TestExceptionRow -Target '*' -Expires (Get-TestDateText -OffsetDays -1))
        Test-M365ApprovedException -UserPrincipalName 'alex@contoso.com' -Target 'x@example.com' -ApprovedExceptions $rows |
            Should -BeFalse
    }

    It 'honours an exception that expires today or later: <Name>' -ForEach @(
        @{ Name = 'expires today'; Offset = 0 }
        @{ Name = 'expires in 30 days'; Offset = 30 }
    ) {
        $rows = @(Get-TestExceptionRow -Target '*' -Expires (Get-TestDateText -OffsetDays $Offset))
        Test-M365ApprovedException -UserPrincipalName 'alex@contoso.com' -Target 'x@example.com' -ApprovedExceptions $rows |
            Should -BeTrue
    }

    It 'honours an exception whose expiry date is blank' {
        $rows = @(Get-TestExceptionRow -Target '*' -Expires '')
        Test-M365ApprovedException -UserPrincipalName 'alex@contoso.com' -Target 'x@example.com' -ApprovedExceptions $rows |
            Should -BeTrue
    }

    It 'does not approve when the expiry date cannot be read, and still finds a later valid row: <Text>' -ForEach @(
        @{ Text = 'not-a-date' }
        @{ Text = '2026-13-45' }
        @{ Text = 'next year' }
    ) {
        $unreadable = Get-TestExceptionRow -Target '*' -Expires $Text
        Test-M365ApprovedException -UserPrincipalName 'alex@contoso.com' -Target 'x@example.com' -ApprovedExceptions @($unreadable) |
            Should -BeFalse

        $valid = Get-TestExceptionRow -Target 'x@example.com' -Expires (Get-TestDateText -OffsetDays 30)
        Test-M365ApprovedException -UserPrincipalName 'alex@contoso.com' -Target 'x@example.com' -ApprovedExceptions @($unreadable, $valid) |
            Should -BeTrue
    }

    It 'throws on bad input: a row without an ExpirationDate column, or an empty user name' {
        $noExpiryColumn = @([pscustomobject]@{ UserPrincipalName = 'alex@contoso.com'; ApprovedTarget = 'x@example.com' })
        { Test-M365ApprovedException -UserPrincipalName 'alex@contoso.com' -Target 'x@example.com' -ApprovedExceptions $noExpiryColumn } |
            Should -Throw -ExpectedMessage '*ExpirationDate*'

        { Test-M365ApprovedException -UserPrincipalName '' -Target 'x@example.com' -ApprovedExceptions @(Get-TestExceptionRow) } |
            Should -Throw
    }
}

Describe 'Get-M365ForwardingRiskLevel' {
    It 'maps rule state, scope and approval to a label: enabled=<Enabled> external=<External> personal=<Personal> approved=<Approved>' -ForEach @(
        @{ Enabled = $true; External = $true; Personal = $true; Approved = $false; Expected = 'Critical' }
        @{ Enabled = $true; External = $true; Personal = $false; Approved = $false; Expected = 'High' }
        @{ Enabled = $true; External = $false; Personal = $true; Approved = $false; Expected = 'Low' }
        @{ Enabled = $true; External = $false; Personal = $false; Approved = $false; Expected = 'Low' }
        @{ Enabled = $false; External = $true; Personal = $true; Approved = $false; Expected = 'Low' }
        @{ Enabled = $false; External = $true; Personal = $false; Approved = $false; Expected = 'Low' }
        @{ Enabled = $false; External = $false; Personal = $true; Approved = $false; Expected = 'Low' }
        @{ Enabled = $false; External = $false; Personal = $false; Approved = $false; Expected = 'Low' }
        @{ Enabled = $true; External = $true; Personal = $true; Approved = $true; Expected = 'Exception' }
        @{ Enabled = $true; External = $true; Personal = $false; Approved = $true; Expected = 'Exception' }
        @{ Enabled = $true; External = $false; Personal = $true; Approved = $true; Expected = 'Exception' }
        @{ Enabled = $true; External = $false; Personal = $false; Approved = $true; Expected = 'Exception' }
        @{ Enabled = $false; External = $true; Personal = $true; Approved = $true; Expected = 'Exception' }
        @{ Enabled = $false; External = $true; Personal = $false; Approved = $true; Expected = 'Exception' }
        @{ Enabled = $false; External = $false; Personal = $true; Approved = $true; Expected = 'Exception' }
        @{ Enabled = $false; External = $false; Personal = $false; Approved = $true; Expected = 'Exception' }
    ) {
        Get-M365ForwardingRiskLevel -RuleEnabled $Enabled -IsExternal $External -IsPersonalDomain $Personal -ApprovedException $Approved |
            Should -BeExactly $Expected
    }

    It 'treats an omitted RuleEnabled value as an enabled rule' {
        Get-M365ForwardingRiskLevel -IsExternal $true -IsPersonalDomain $false -ApprovedException $false | Should -BeExactly 'High'
    }
}

Describe 'Get-M365OutboundRiskLevel' {
    It 'returns Critical at the critical threshold and Medium just below it: <Sent>' -ForEach @(
        @{ Sent = 250; Expected = 'Critical' }
        @{ Sent = 1000; Expected = 'Critical' }
        @{ Sent = 249; Expected = 'Medium' }
    ) {
        Get-OutboundLevel -Sent $Sent | Should -BeExactly $Expected
    }

    It 'returns Medium at the warning threshold and Low just below it when the baseline is established: <Sent>' -ForEach @(
        @{ Sent = 100; Expected = 'Medium' }
        @{ Sent = 99; Expected = 'Low' }
        @{ Sent = 0; Expected = 'Low' }
    ) {
        Get-OutboundLevel -Sent $Sent -Samples 5 | Should -BeExactly $Expected
    }

    It 'flags attention-level volume as Medium while the baseline is still learning: samples=<Samples> sent=<Sent>' -ForEach @(
        @{ Samples = 0; Sent = 20; Expected = 'Medium' }
        @{ Samples = 2; Sent = 20; Expected = 'Medium' }
        @{ Samples = 2; Sent = 19; Expected = 'Low' }
    ) {
        Get-OutboundLevel -Sent $Sent -Samples $Samples | Should -BeExactly $Expected
    }

    It 'flags attention-level volume once the baseline is established only when above baseline: samples=<Samples> sent=<Sent> above=<Above>' -ForEach @(
        @{ Samples = 3; Sent = 20; Above = $true; Expected = 'Medium' }
        @{ Samples = 3; Sent = 20; Above = $false; Expected = 'Low' }
        @{ Samples = 3; Sent = 19; Above = $true; Expected = 'Low' }
        @{ Samples = 10; Sent = 99; Above = $false; Expected = 'Low' }
    ) {
        Get-OutboundLevel -Sent $Sent -Samples $Samples -Above $Above | Should -BeExactly $Expected
    }

    It 'derives the after-hours threshold as the larger of 10 and a quarter of the warning threshold, rounded up: warning=<Warning> afterHours=<AfterHours>' -ForEach @(
        @{ Warning = 100; AfterHours = 24; Expected = 'Low' }
        @{ Warning = 100; AfterHours = 25; Expected = 'Medium' }
        @{ Warning = 20; AfterHours = 9; Expected = 'Low' }
        @{ Warning = 20; AfterHours = 10; Expected = 'Medium' }
        @{ Warning = 102; AfterHours = 25; Expected = 'Low' }
        @{ Warning = 102; AfterHours = 26; Expected = 'Medium' }
    ) {
        $settings = Get-TestSetting -Override @{ OutboundWarningThreshold = $Warning; OutboundCriticalThreshold = 1000 }
        Get-OutboundLevel -AfterHours $AfterHours -Settings $settings | Should -BeExactly $Expected
    }

    It 'uses AfterHoursWarningThreshold, OutboundAttentionThreshold and BaselineMinimumSamples from settings when present' {
        $settings = Get-TestSetting -Override @{ AfterHoursWarningThreshold = 3; OutboundAttentionThreshold = 5; BaselineMinimumSamples = 1 }

        Get-OutboundLevel -AfterHours 3 -Settings $settings | Should -BeExactly 'Medium'
        Get-OutboundLevel -AfterHours 2 -Settings $settings | Should -BeExactly 'Low'
        Get-OutboundLevel -Sent 5 -Samples 0 -Settings $settings | Should -BeExactly 'Medium'
        Get-OutboundLevel -Sent 4 -Samples 0 -Settings $settings | Should -BeExactly 'Low'
        Get-OutboundLevel -Sent 5 -Samples 1 -Above $false -Settings $settings | Should -BeExactly 'Low'
        Get-OutboundLevel -Sent 5 -Samples 1 -Above $true -Settings $settings | Should -BeExactly 'Medium'
    }

    It 'lets the critical threshold win over after-hours volume and over a warning threshold set above it' {
        Get-OutboundLevel -Sent 300 -AfterHours 300 | Should -BeExactly 'Critical'

        $misordered = Get-TestSetting -Override @{ OutboundWarningThreshold = 200; OutboundCriticalThreshold = 100 }
        Get-OutboundLevel -Sent 150 -Settings $misordered | Should -BeExactly 'Critical'
    }

    It 'ignores the BaselineAverage value: only the sample count and IsAboveBaseline matter' {
        $settings = Get-TestSetting
        $withAverage = Get-M365OutboundRiskLevel -ExternalSentCount 30 -AfterHoursCount 0 -BaselineAverage 1000 `
            -BaselineSampleCount 5 -IsAboveBaseline $false -Settings $settings
        $withoutAverage = Get-M365OutboundRiskLevel -ExternalSentCount 30 -AfterHoursCount 0 `
            -BaselineSampleCount 5 -IsAboveBaseline $false -Settings $settings

        $withAverage | Should -BeExactly 'Low'
        $withoutAverage | Should -BeExactly 'Low'
    }

    It 'only ever returns Low, Medium or Critical, never High' {
        $levels = foreach ($sent in 0, 19, 20, 99, 100, 249, 250, 400) {
            foreach ($samples in 0, 5) {
                Get-OutboundLevel -Sent $sent -AfterHours 30 -Samples $samples -Above $true
                Get-OutboundLevel -Sent $sent -AfterHours 0 -Samples $samples -Above $false
            }
        }
        @($levels | Select-Object -Unique | Sort-Object) | Should -Be @('Critical', 'Low', 'Medium')
    }

    It 'throws when a required threshold is missing from the settings: <Missing>' -ForEach @(
        @{ Missing = 'OutboundWarningThreshold'; Settings = [pscustomobject]@{ OutboundCriticalThreshold = 250 } }
        @{ Missing = 'OutboundCriticalThreshold'; Settings = [pscustomobject]@{ OutboundWarningThreshold = 100 } }
    ) {
        { Get-M365OutboundRiskLevel -ExternalSentCount 5 -AfterHoursCount 0 -Settings $Settings } |
            Should -Throw -ExpectedMessage "*$Missing*"
    }
}

Describe 'ConvertTo-M365CsvSafeValue' {
    It 'returns null for null' {
        ConvertTo-M365CsvSafeValue -Value $null | Should -BeNullOrEmpty
    }

    It 'joins array elements with a semicolon and a space: <Name>' -ForEach @(
        @{ Name = 'two elements'; Value = @('a.example.com:5', 'b.example.com:2'); Expected = 'a.example.com:5; b.example.com:2' }
        @{ Name = 'one element'; Value = @('only'); Expected = 'only' }
        @{ Name = 'empty array'; Value = @(); Expected = '' }
        @{ Name = 'a null element keeps its place'; Value = @('a', $null, 'b'); Expected = 'a; ; b' }
    ) {
        ConvertTo-M365CsvSafeValue -Value $Value | Should -BeExactly $Expected
    }

    It 'returns ordinary values unchanged and keeps their type: <Name>' -ForEach @(
        @{ Name = 'text'; Value = 'plain text' }
        @{ Name = 'address'; Value = 'alex@contoso.com' }
        @{ Name = 'empty string'; Value = '' }
        @{ Name = 'leading space'; Value = ' spaced' }
        @{ Name = 'trigger characters that are not first'; Value = 'a=b+c-d@e' }
        @{ Name = 'domain and count'; Value = 'vendor.example.com:12' }
        @{ Name = 'already prefixed text'; Value = "'=1+1" }
        @{ Name = 'integer'; Value = 42 }
        @{ Name = 'negative integer'; Value = -5 }
        @{ Name = 'negative double'; Value = -3.5 }
        @{ Name = 'boolean'; Value = $true }
    ) {
        $result = ConvertTo-M365CsvSafeValue -Value $Value
        $result | Should -BeExactly $Value
        $result | Should -BeOfType $Value.GetType()
    }

    It 'prefixes a string that starts with <Name> with one apostrophe' -ForEach @(
        @{ Name = 'an equals sign'; Value = '=1+1'; Expected = "'=1+1" }
        @{ Name = 'a plus sign'; Value = '+cmd'; Expected = "'+cmd" }
        @{ Name = 'a minus sign'; Value = '-2+3'; Expected = "'-2+3" }
        @{ Name = 'an at sign'; Value = '@SUM(A1)'; Expected = "'@SUM(A1)" }
        @{ Name = 'a tab'; Value = "`tcmd"; Expected = "'`tcmd" }
        @{ Name = 'a carriage return (which then becomes a space)'; Value = "`rcmd"; Expected = "' cmd" }
        @{ Name = 'a line feed (which then becomes a space)'; Value = "`ncmd"; Expected = "' cmd" }
        @{ Name = 'a line feed before a formula'; Value = "`n=1+1"; Expected = "' =1+1" }
    ) {
        ConvertTo-M365CsvSafeValue -Value $Value | Should -BeExactly $Expected
    }

    It 'replaces embedded carriage returns and line feeds with a single space: <Name>' -ForEach @(
        @{ Name = 'line feed'; Value = "line one`nline two"; Expected = 'line one line two' }
        @{ Name = 'carriage return'; Value = "line one`rline two"; Expected = 'line one line two' }
        @{ Name = 'CR LF pair'; Value = "line one`r`nline two"; Expected = 'line one line two' }
        @{ Name = 'a formula after a line break'; Value = "note`n=1+1"; Expected = 'note =1+1' }
    ) {
        ConvertTo-M365CsvSafeValue -Value $Value | Should -BeExactly $Expected
    }

    It 'applies the same rules to every element of an array before joining' {
        ConvertTo-M365CsvSafeValue -Value @('=a', 'b', '-c', "d`ne", 7) | Should -BeExactly "'=a; b; '-c; d e; 7"
    }

    It 'gives the same result when applied twice' {
        foreach ($value in '=1+1', '+cmd', '-2+3', '@SUM(A1)', "`tcmd", "`rcmd", "`ncmd", "a`nb", 'plain') {
            $once = ConvertTo-M365CsvSafeValue -Value $value
            ConvertTo-M365CsvSafeValue -Value $once | Should -BeExactly $once
        }
    }

    It 'leaves no string cell that spreadsheet software reads as a formula, after a real CSV round trip' {
        $rows = foreach ($value in '=1+1', '+cmd', '-2+3', '@SUM(A1)', "`tcmd", "`rcmd", "`n=y", "x`n=y") {
            [pscustomobject]@{ Cell = ConvertTo-M365CsvSafeValue -Value $value }
        }
        $roundTrip = @($rows | ConvertTo-Csv -NoTypeInformation | ConvertFrom-Csv)

        $roundTrip.Count | Should -Be 8
        foreach ($row in $roundTrip) {
            $row.Cell | Should -Not -Match '^[=+\-@\t\r\n]'
        }
    }
}

Describe 'Invoke-M365CallWithRetry' {
    BeforeEach {
        Mock Start-Sleep {} -ModuleName RiskScoring
        Mock Write-Warning {} -ModuleName RiskScoring
        $outputPath = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $state = @{ Calls = 0 }
    }

    It 'returns the script block output on the first success without sleeping or logging' {
        $result = Invoke-M365CallWithRetry -OperationName 'works' -OutputPath $outputPath -ScriptBlock { 'payload' }

        $result | Should -BeExactly 'payload'
        Should -Invoke Start-Sleep -ModuleName RiskScoring -Times 0 -Exactly
        Join-Path $outputPath 'errors.log' | Should -Not -Exist
    }

    It 'retries a failing script block and returns the result of the first success' {
        $result = Invoke-M365CallWithRetry -OperationName 'flaky' -OutputPath $outputPath -ScriptBlock {
            $state.Calls++
            if ($state.Calls -lt 3) { throw 'connection reset' }
            'recovered'
        }

        $result | Should -BeExactly 'recovered'
        $state.Calls | Should -Be 3
        Should -Invoke Start-Sleep -ModuleName RiskScoring -Times 2 -Exactly -ParameterFilter { $Seconds -eq 2 }
    }

    It 'gives up after MaxAttempts, returns null and emits one warning when ThrowOnFailure is not set' {
        $result = Invoke-M365CallWithRetry -OperationName 'hopeless' -OutputPath $outputPath -MaxAttempts 3 -ScriptBlock {
            $state.Calls++
            throw 'always fails'
        }

        $result | Should -BeNullOrEmpty
        $state.Calls | Should -Be 3
        Should -Invoke Write-Warning -ModuleName RiskScoring -Times 1 -Exactly -ParameterFilter { $Message -like 'hopeless failed*' }
    }

    It 'throws a message naming the operation and attempt count when ThrowOnFailure is set' {
        { Invoke-M365CallWithRetry -OperationName 'must-succeed' -OutputPath $outputPath -MaxAttempts 2 -ThrowOnFailure -ScriptBlock { throw 'nope' } } |
            Should -Throw -ExpectedMessage '*must-succeed failed after 2 attempt(s)*'
    }

    It 'waits <Expected> seconds before retrying when the failure is: <Name>' -ForEach @(
        @{ Name = 'HTTP 429'; Message = 'request failed'; Status = 429; Expected = 10 }
        @{ Name = 'HTTP 503'; Message = 'request failed'; Status = 503; Expected = 10 }
        @{ Name = 'a throttling message'; Message = 'Request was THROTTLED by the service'; Status = $null; Expected = 10 }
        @{ Name = 'a too-many-requests message'; Message = 'Too Many Requests'; Status = $null; Expected = 10 }
        @{ Name = 'a temporary-failure message'; Message = 'Service temporarily unavailable'; Status = $null; Expected = 10 }
        @{ Name = 'HTTP 500 (not a throttle)'; Message = 'internal error'; Status = 500; Expected = 2 }
        @{ Name = 'a plain error (not a throttle)'; Message = 'connection reset'; Status = $null; Expected = 2 }
    ) {
        $failure = Get-TestFailure -Message $Message -StatusCode $Status
        $null = Invoke-M365CallWithRetry -OperationName 'delay-check' -OutputPath $outputPath -MaxAttempts 2 -ScriptBlock { throw $failure }

        Should -Invoke Start-Sleep -ModuleName RiskScoring -Times 1 -Exactly
        Should -Invoke Start-Sleep -ModuleName RiskScoring -Times 1 -Exactly -ParameterFilter { $Seconds -eq $Expected }
    }

    It 'doubles the throttle delay on each attempt and caps it at 60 seconds' {
        $failure = Get-TestFailure -StatusCode 429
        $null = Invoke-M365CallWithRetry -OperationName 'backoff' -OutputPath $outputPath -MaxAttempts 5 -ScriptBlock { throw $failure }

        Should -Invoke Start-Sleep -ModuleName RiskScoring -Times 4 -Exactly
        foreach ($expectedDelay in 10, 20, 40, 60) {
            Should -Invoke Start-Sleep -ModuleName RiskScoring -Times 1 -Exactly -ParameterFilter { $Seconds -eq $expectedDelay }
        }
    }

    It 'runs the script block <Calls> time(s) and never sleeps when MaxAttempts is <Max>' -ForEach @(
        @{ Max = 1; Calls = 1 }
        @{ Max = 0; Calls = 0 }
    ) {
        $result = Invoke-M365CallWithRetry -OperationName 'edge' -OutputPath $outputPath -MaxAttempts $Max -ScriptBlock {
            $state.Calls++
            throw 'fails'
        }

        $result | Should -BeNullOrEmpty
        $state.Calls | Should -Be $Calls
        Should -Invoke Start-Sleep -ModuleName RiskScoring -Times 0 -Exactly
    }

    It 'writes one errors.log line per failed attempt, tagged with the operation name' {
        $null = Invoke-M365CallWithRetry -OperationName 'Graph users list' -OutputPath $outputPath -MaxAttempts 3 -ScriptBlock { throw 'denied' }

        $lines = @(Get-Content -Path (Join-Path $outputPath 'errors.log'))
        $lines.Count | Should -Be 3
        foreach ($attempt in 1, 2, 3) {
            $lines[$attempt - 1] | Should -BeLike "*Graph users list failed on attempt $attempt.*denied"
        }
    }
}

Describe 'Write-M365MonitorError' {
    BeforeEach {
        Mock Write-Warning {} -ModuleName RiskScoring
        $outputPath = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    }

    It 'creates a missing output folder, including parents, and writes errors.log into it' {
        $nested = Join-Path (Join-Path $outputPath 'level1') 'level2'

        Write-M365MonitorError -Message 'first problem' -OutputPath $nested

        Join-Path $nested 'errors.log' | Should -Exist
    }

    It 'appends one ISO-8601 timestamped line per call' {
        Write-M365MonitorError -Message 'first problem' -OutputPath $outputPath
        Write-M365MonitorError -Message 'second problem' -OutputPath $outputPath

        $lines = @(Get-Content -Path (Join-Path $outputPath 'errors.log'))
        $lines.Count | Should -Be 2
        $lines[0] | Should -Match '^\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+(Z|[+-]\d{2}:\d{2})\] first problem\s*$'
        $lines[1] | Should -Match '\] second problem\s*$'
    }

    It 'appends the error record text after the message when one is supplied' {
        try { throw 'inner failure detail' } catch { $record = $_ }

        Write-M365MonitorError -Message 'Graph call failed.' -ErrorRecord $record -OutputPath $outputPath

        Get-Content -Path (Join-Path $outputPath 'errors.log') | Should -Match 'Graph call failed\. inner failure detail$'
    }

    It 'does not throw when the output path is an existing file, and only warns if -ErrorAction Stop makes the write error terminating' {
        $notAFolder = Join-Path $TestDrive 'not-a-folder'
        Set-Content -Path $notAFolder -Value 'occupied'

        { Write-M365MonitorError -Message 'cannot be logged' -OutputPath $notAFolder -ErrorAction SilentlyContinue } |
            Should -Not -Throw
        Join-Path $notAFolder 'errors.log' | Should -Not -Exist
        Should -Invoke Write-Warning -ModuleName RiskScoring -Times 0 -Exactly

        { Write-M365MonitorError -Message 'cannot be logged' -OutputPath $notAFolder -ErrorAction Stop } |
            Should -Not -Throw
        Should -Invoke Write-Warning -ModuleName RiskScoring -Times 1 -Exactly -ParameterFilter { $Message -like 'Unable to write to errors.log*' }
    }
}

Describe 'Scoring helpers used together, as the collectors use them' {
    It 'rates an enabled forward to a mixed-case personal address with an SMTP prefix as Critical' {
        $target = 'SMTP:Sam.Okafor@WEBMAIL.example.com'
        $domain = Get-M365TargetDomain -Target $target
        $external = -not (Test-M365InternalDomain -Domain $domain -InternalDomains @('contoso.com', 'contoso.onmicrosoft.com'))
        $personal = Test-M365PersonalDomain -Domain $domain -PersonalDomains @('webmail.example.com')
        $approved = Test-M365ApprovedException -UserPrincipalName 'sam.okafor@contoso.com' -Target $target -ApprovedExceptions @()

        Get-M365ForwardingRiskLevel -RuleEnabled $true -IsExternal $external -IsPersonalDomain $personal -ApprovedException $approved |
            Should -BeExactly 'Critical'
    }

    It 'treats a forwarding address with no at sign as external, because an empty domain is never internal' {
        $domain = Get-M365TargetDomain -Target 'contoso.com/Staff/Alex Wilber'
        $isExternal = -not (Test-M365InternalDomain -Domain $domain -InternalDomains @('contoso.com'))

        $domain | Should -BeNullOrEmpty
        $isExternal | Should -BeTrue
    }
}

Describe 'Source scripts' {
    It 'parse with no syntax errors: <Name>' -ForEach $sourceFiles {
        $tokens = $null
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)

        @($errors).Count | Should -Be 0
    }
}

Describe 'Invoke-ForwardingMonitor.ps1 run against stubbed Microsoft calls' {
    BeforeAll {
        $monitorScript = Join-Path (Join-Path $PSScriptRoot '..') 'src/Invoke-ForwardingMonitor.ps1'
        $expectedFindingColumns = @(
            'UserPrincipalName', 'DisplayName', 'ForwardingType', 'ForwardTarget', 'TargetDomain', 'IsExternal',
            'IsPersonalDomain', 'ApprovedException', 'RiskLevel', 'DetectedAt',
            'DeliverToMailboxAndForward', 'RuleName', 'RuleId', 'RuleEnabled'
        )

        # The stubs stand in for Invoke-MgGraphRequest, Get-Mailbox and Get-MessageTraceV2.
        # They read whatever the current scenario put in $global:OfflineRun.
        function global:Invoke-MgGraphRequest {
            [CmdletBinding()]
            param($Method, $Uri)
            if ($Uri -match '/users/(?<upn>[^/]+)/mailFolders/inbox/messageRules$') {
                $rules = $global:OfflineRun.Rules[$Matches['upn']]
                return @{ value = @($rules | Where-Object { $_ }) }
            }
            return @{ value = @($global:OfflineRun.Users) }
        }
        function global:Get-Mailbox {
            [CmdletBinding()]
            param($Identity)
            $forwardTo = $global:OfflineRun.Mailboxes[$Identity]
            $user = @($global:OfflineRun.Users | Where-Object { $_.userPrincipalName -eq $Identity })[0]
            return [pscustomobject]@{
                DisplayName                = $user.displayName
                UserPrincipalName          = $Identity
                PrimarySmtpAddress         = $Identity
                ForwardingAddress          = $null
                ForwardingSmtpAddress      = $forwardTo
                DeliverToMailboxAndForward = $true
            }
        }
        function global:Get-MessageTraceV2 {
            [CmdletBinding()]
            param($StartDate, $EndDate)
            return @($global:OfflineRun.Traces)
        }

        function Get-OfflineUser {
            param([string]$Name, [string]$DisplayName)
            return @{
                id                = '00000000-0000-0000-0000-000000000000'
                displayName       = $DisplayName
                userPrincipalName = "$Name@contoso.com"
                mail              = "$Name@contoso.com"
                accountEnabled    = $true
                userType          = 'Member'
            }
        }

        function Get-OfflineRule {
            param([string]$Name, [string]$Target)
            return @{
                id          = '00000000-0000-0000-0000-000000000000'
                displayName = $Name
                isEnabled   = $true
                actions     = @{ forwardTo = @(@{ emailAddress = @{ address = $Target; name = $Target } }) }
            }
        }

        function Get-OfflineTrace {
            param([string]$SenderAddress, [string]$Recipient)
            return [pscustomobject]@{
                Received         = (Get-Date).Date.AddHours(11)
                SenderAddress    = $SenderAddress
                RecipientAddress = $Recipient
                Directionality   = 'Outbound'
                Status           = 'Delivered'
            }
        }

        function Invoke-OfflineMonitorRun {
            param([string]$Name, [hashtable]$Scenario, [string]$ExceptionTarget, [scriptblock]$Seed)

            $global:OfflineRun = $Scenario
            $runRoot = Join-Path $TestDrive $Name
            $outputDir = Join-Path $runRoot 'output'
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
            if ($Seed) { & $Seed $outputDir }

            [ordered]@{
                TenantId                   = '00000000-0000-0000-0000-000000000000'
                InternalDomains            = @('contoso.com', 'contoso.onmicrosoft.com')
                PersonalDomains            = @('webmail.example.com')
                LookbackHours              = 24
                OutboundWarningThreshold   = 100
                OutboundCriticalThreshold  = 250
                OutboundAttentionThreshold = 20
                AfterHoursWarningThreshold = 25
                BaselineMultiplier         = 2.5
                BaselineMinimumSamples     = 3
                BaselineRetentionDays      = 90
                BusinessHoursStart         = 8
                BusinessHoursEnd           = 18
                OutputPath                 = $outputDir
                PrivacyMode                = $true
            } | ConvertTo-Json | Set-Content -Path (Join-Path $runRoot 'settings.json')

            [pscustomobject]@{
                UserPrincipalName = 'alex.wilber@contoso.com'
                ApprovedTarget    = $ExceptionTarget
                Reason            = 'Synthetic test row'
                ApprovedBy        = 'security.manager@contoso.com'
                ExpirationDate    = (Get-Date).AddDays(30).ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
            } | Export-Csv -Path (Join-Path $runRoot 'exceptions.csv') -NoTypeInformation

            & $monitorScript -SettingsPath (Join-Path $runRoot 'settings.json') `
                -ApprovedExceptionsPath (Join-Path $runRoot 'exceptions.csv') -SkipConnect 6>$null
            return $outputDir
        }
    }

    AfterAll {
        Remove-Item -Path Function:\global:Invoke-MgGraphRequest, Function:\global:Get-Mailbox, Function:\global:Get-MessageTraceV2 -ErrorAction SilentlyContinue
        Remove-Variable -Name OfflineRun -Scope Global -ErrorAction SilentlyContinue
    }

    Context 'with mailbox forwarding, an approved exception and hostile display names' {
        BeforeAll {
            $scenario = @{
                Users     = @(
                    (Get-OfflineUser -Name 'alex.wilber' -DisplayName '=HYPERLINK("http://example.com","Alex")')
                    (Get-OfflineUser -Name 'sam.okafor' -DisplayName '@Sam Okafor')
                    (Get-OfflineUser -Name 'priya.nair' -DisplayName 'Priya Nair')
                )
                Mailboxes = @{
                    'alex.wilber@contoso.com' = 'smtp:records@partner.example.com'
                    'sam.okafor@contoso.com'  = 'smtp:sam.home@webmail.example.com'
                }
                Rules     = @{
                    'priya.nair@contoso.com' = @(
                        (Get-OfflineRule -Name '=Copy to vendor' -Target 'billing@vendor.example.com')
                    )
                }
                Traces    = @(
                    (Get-OfflineTrace -SenderAddress 'priya.nair@contoso.com' -Recipient 'a@vendor.example.com')
                    (Get-OfflineTrace -SenderAddress 'priya.nair@contoso.com' -Recipient 'b@vendor.example.com')
                    (Get-OfflineTrace -SenderAddress '=ops@contoso.com' -Recipient 'c@vendor.example.com')
                )
            }
            $outputDir = Invoke-OfflineMonitorRun -Name 'mailbox' -Scenario $scenario -ExceptionTarget 'records@partner.example.com'
        }

        It 'collects users, mailbox forwards and outbound counts and writes every report file' {
            foreach ($file in 'summary.json', 'forwarding-findings.json', 'forwarding-findings.csv', 'outbound-metadata-counts.json',
                'outbound-metadata-counts.csv', 'summary.csv', 'outbound-baseline-history.json', 'dashboard.html') {
                Join-Path $outputDir $file | Should -Exist
            }

            $summary = Get-Content -Path (Join-Path $outputDir 'summary.json') -Raw | ConvertFrom-Json
            $summary.TotalUsersScanned | Should -Be 3
            $summary.UsersWithMailboxForwarding | Should -Be 2
            $summary.UsersWithInboxRuleForwarding | Should -Be 1
            $summary.ExternalForwardingCount | Should -Be 3
            $summary.PersonalDomainForwardingCount | Should -Be 1
            $summary.ApprovedExceptionsCount | Should -Be 1
        }

        It 'labels the findings: the approved one as Exception and the personal-domain one as Critical' {
            $findings = @(Get-Content -Path (Join-Path $outputDir 'forwarding-findings.json') -Raw | ConvertFrom-Json)

            ($findings | Where-Object UserPrincipalName -eq 'alex.wilber@contoso.com').RiskLevel | Should -BeExactly 'Exception'
            ($findings | Where-Object UserPrincipalName -eq 'sam.okafor@contoso.com').RiskLevel | Should -BeExactly 'Critical'
        }

        It 'writes the full column set to the findings CSV even though mailbox forwards sort first' {
            $csv = @(Import-Csv -Path (Join-Path $outputDir 'forwarding-findings.csv'))

            $csv[0].ForwardingType | Should -BeExactly 'MailboxForwarding'
            $csv[0].PSObject.Properties.Name | Should -Be $expectedFindingColumns
            ($csv | Where-Object UserPrincipalName -eq 'priya.nair@contoso.com').RuleName | Should -BeExactly "'=Copy to vendor"
            ($csv | Where-Object UserPrincipalName -eq 'priya.nair@contoso.com').RuleId | Should -BeExactly '00000000-0000-0000-0000-000000000000'
            ($csv | Where-Object UserPrincipalName -eq 'priya.nair@contoso.com').RuleEnabled | Should -BeExactly 'True'
            ($csv | Where-Object UserPrincipalName -eq 'alex.wilber@contoso.com').RuleName | Should -BeNullOrEmpty
        }

        It 'records one baseline history entry per sender' {
            $history = @(Get-Content -Path (Join-Path $outputDir 'outbound-baseline-history.json') -Raw | ConvertFrom-Json)

            $history.Count | Should -Be 2
            ($history | Where-Object SenderAddress -eq 'priya.nair@contoso.com').ExternalSentCount | Should -Be 2
            ($history | Where-Object SenderAddress -eq '=ops@contoso.com').ExternalSentCount | Should -Be 1
        }

        It 'neutralises a formula-like sender address in the outbound CSV but keeps the raw value in the JSON' {
            $csv = @(Import-Csv -Path (Join-Path $outputDir 'outbound-metadata-counts.csv'))
            $json = @(Get-Content -Path (Join-Path $outputDir 'outbound-metadata-counts.json') -Raw | ConvertFrom-Json)

            ($csv | Where-Object ExternalSentCount -eq 1).SenderAddress | Should -BeExactly "'=ops@contoso.com"
            ($csv | Where-Object ExternalSentCount -eq 1).UserPrincipalName | Should -BeExactly "'=ops@contoso.com"
            ($json | Where-Object ExternalSentCount -eq 1).SenderAddress | Should -BeExactly '=ops@contoso.com'
        }

        It 'neutralises formula-like display names in the findings CSV but keeps the raw value in the JSON' {
            $csv = @(Import-Csv -Path (Join-Path $outputDir 'forwarding-findings.csv'))
            $json = @(Get-Content -Path (Join-Path $outputDir 'forwarding-findings.json') -Raw | ConvertFrom-Json)

            ($csv | Where-Object UserPrincipalName -eq 'alex.wilber@contoso.com').DisplayName |
                Should -BeExactly "'=HYPERLINK(`"http://example.com`",`"Alex`")"
            ($csv | Where-Object UserPrincipalName -eq 'sam.okafor@contoso.com').DisplayName | Should -BeExactly "'@Sam Okafor"
            ($json | Where-Object UserPrincipalName -eq 'sam.okafor@contoso.com').DisplayName | Should -BeExactly '@Sam Okafor'
        }
    }

    Context 'with an inbox rule whose name is a spreadsheet formula' {
        BeforeAll {
            $scenario = @{
                Users     = @(
                    (Get-OfflineUser -Name 'jordan.reyes' -DisplayName 'Jordan Reyes')
                    (Get-OfflineUser -Name 'chris.lindqvist' -DisplayName 'Chris Lindqvist')
                )
                Mailboxes = @{}
                Rules     = @{
                    'jordan.reyes@contoso.com' = @(
                        (Get-OfflineRule -Name '=HYPERLINK("http://example.com","x")' -Target 'invoices@vendor.example.com')
                    )
                    'chris.lindqvist@contoso.com' = @(
                        (Get-OfflineRule -Name '-1+2' -Target '+bookkeeper@vendor.example.com')
                    )
                }
                Traces    = @(
                    (Get-OfflineTrace -SenderAddress 'jordan.reyes@contoso.com' -Recipient 'a@vendor.example.com')
                )
            }
            $outputDir = Invoke-OfflineMonitorRun -Name 'rules' -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com'
        }

        It 'finds the inbox rule forwards and writes the dashboard' {
            $summary = Get-Content -Path (Join-Path $outputDir 'summary.json') -Raw | ConvertFrom-Json
            $summary.UsersWithInboxRuleForwarding | Should -Be 2
            $summary.HighCriticalRiskCount | Should -Be 2
            Join-Path $outputDir 'dashboard.html' | Should -Exist
        }

        It 'neutralises the rule name and forward target in the findings CSV but keeps the raw rule name in the JSON' {
            $csv = @(Import-Csv -Path (Join-Path $outputDir 'forwarding-findings.csv'))
            $json = @(Get-Content -Path (Join-Path $outputDir 'forwarding-findings.json') -Raw | ConvertFrom-Json)

            $csv[0].PSObject.Properties.Name | Should -Be $expectedFindingColumns
            ($csv | Where-Object UserPrincipalName -eq 'jordan.reyes@contoso.com').RuleName |
                Should -BeExactly "'=HYPERLINK(`"http://example.com`",`"x`")"
            ($csv | Where-Object UserPrincipalName -eq 'chris.lindqvist@contoso.com').RuleName | Should -BeExactly "'-1+2"
            ($csv | Where-Object UserPrincipalName -eq 'chris.lindqvist@contoso.com').ForwardTarget | Should -BeExactly "'+bookkeeper@vendor.example.com"
            ($json | Where-Object UserPrincipalName -eq 'chris.lindqvist@contoso.com').RuleName | Should -BeExactly '-1+2'
        }
    }

    Context 'on a quiet day with no external outbound mail and earlier baseline history' {
        BeforeAll {
            $scenario = @{
                Users     = @(
                    (Get-OfflineUser -Name 'jordan.reyes' -DisplayName 'Jordan Reyes')
                    (Get-OfflineUser -Name 'chris.lindqvist' -DisplayName 'Chris Lindqvist')
                )
                Mailboxes = @{ 'chris.lindqvist@contoso.com' = 'smtp:records@partner.example.com' }
                Rules     = @{
                    'jordan.reyes@contoso.com' = @((Get-OfflineRule -Name 'Copy invoices' -Target 'invoices@vendor.example.com'))
                }
                Traces    = @()
            }
            $seed = {
                param($Dir)
                $earlier = [pscustomobject]@{
                    Date                         = (Get-Date).AddDays(-1).ToString('yyyy-MM-dd')
                    SenderAddress                = 'old.sender@contoso.com'
                    ExternalSentCount            = 12
                    UniqueExternalRecipientCount = 3
                    TopExternalDomains           = @('vendor.example.com:12')
                    AfterHoursCount              = 0
                    DetectedAt                   = (Get-Date).AddDays(-1).ToString('o')
                }
                ConvertTo-Json -InputObject @($earlier) -Depth 5 | Set-Content -Path (Join-Path $Dir 'outbound-baseline-history.json')
                ConvertTo-Json -InputObject @($earlier) -Depth 5 | Set-Content -Path (Join-Path $Dir 'outbound-metadata-counts.json')
            }
            $outputDir = Invoke-OfflineMonitorRun -Name 'quiet-history' -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com' -Seed $seed
        }

        It 'completes and still writes the summary, the dashboard and every CSV file' {
            foreach ($file in 'summary.json', 'summary.csv', 'dashboard.html', 'forwarding-findings.csv', 'outbound-metadata-counts.csv') {
                Join-Path $outputDir $file | Should -Exist
            }

            $summary = Get-Content -Path (Join-Path $outputDir 'summary.json') -Raw | ConvertFrom-Json
            $summary.TotalUsersScanned | Should -Be 2
            $summary.AbnormalOutboundCount | Should -Be 0
            $summary.AboveBaselineOutboundCount | Should -Be 0
            $summary.HighCriticalRiskCount | Should -Be 2
            Get-Content -Path (Join-Path $outputDir 'dashboard.html') -Raw | Should -BeLike '*No abnormal outbound metadata counts found.*'
        }

        It 'replaces the earlier outbound report with an empty one instead of leaving yesterday''s rows' {
            $json = @(Get-Content -Path (Join-Path $outputDir 'outbound-metadata-counts.json') -Raw | ConvertFrom-Json)
            $json.Count | Should -Be 0
            @(Import-Csv -Path (Join-Path $outputDir 'outbound-metadata-counts.csv')).Count | Should -Be 0
        }

        It 'keeps the earlier baseline history and adds no records' {
            $history = @(Get-Content -Path (Join-Path $outputDir 'outbound-baseline-history.json') -Raw | ConvertFrom-Json)

            $history.Count | Should -Be 1
            $history[0].SenderAddress | Should -BeExactly 'old.sender@contoso.com'
            $history[0].ExternalSentCount | Should -Be 12
        }

        It 'writes the full findings column set when mailbox forwards and rule forwards are both present' {
            $csv = @(Import-Csv -Path (Join-Path $outputDir 'forwarding-findings.csv'))

            $csv.Count | Should -Be 2
            $csv[0].PSObject.Properties.Name | Should -Be $expectedFindingColumns
        }
    }

    Context 'on a first run where nothing is forwarded and no external mail was sent' {
        BeforeAll {
            $scenario = @{
                Users     = @((Get-OfflineUser -Name 'robin.castellan' -DisplayName 'Robin Castellan'))
                Mailboxes = @{}
                Rules     = @{}
                Traces    = @()
            }
            $outputDir = Invoke-OfflineMonitorRun -Name 'quiet-first' -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com'
        }

        It 'completes, writes empty JSON arrays for the findings, outbound counts and baseline history, and still writes the dashboard' {
            foreach ($file in 'forwarding-findings.json', 'outbound-metadata-counts.json', 'outbound-baseline-history.json') {
                $path = Join-Path $outputDir $file
                $path | Should -Exist
                @(Get-Content -Path $path -Raw | ConvertFrom-Json).Count | Should -Be 0
            }
            Join-Path $outputDir 'dashboard.html' | Should -Exist
            Join-Path $outputDir 'forwarding-findings.csv' | Should -Exist
            Join-Path $outputDir 'outbound-metadata-counts.csv' | Should -Exist

            $summary = Get-Content -Path (Join-Path $outputDir 'summary.json') -Raw | ConvertFrom-Json
            $summary.TotalUsersScanned | Should -Be 1
            $summary.ExternalForwardingCount | Should -Be 0
            $summary.HighCriticalRiskCount | Should -Be 0
        }
    }
}
