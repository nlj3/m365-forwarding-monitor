#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares BeforeDiscovery and BeforeEach variables with It blocks.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Justification = 'The stub functions are global so the script under test can call them, and they read the current scenario from one global variable.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'The stub functions accept the same parameters as the commands they replace but do not need them.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'The offline run replaces Start-Sleep with a no-op so failed calls do not wait between retries, and wraps Move-Item to record the order in which files are put in place.')]
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

    function Get-FunctionTextFromFile {
        param([string]$Path, [string]$Name)
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
        $found = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $Name }, $true)
        return $found[0].Extent.Text
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

    It 'keeps subdomains and a trailing dot as written instead of normalizing them' {
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
        @{ Target = 'Archive <archive@example.com>' }
        @{ Target = '  archive@example.com  ' }
    ) {
        $rows = @(Get-TestExceptionRow -User 'Alex@Contoso.com' -Target 'archive@example.com')
        Test-M365ApprovedException -UserPrincipalName 'alex@contoso.com' -Target $Target -ApprovedExceptions $rows |
            Should -BeTrue
    }

    It 'approves only the exact address named in the exception, not other addresses at its domain: <Name>' -ForEach @(
        @{ Name = 'another mailbox at the same domain'; Target = 'attacker@partner.example.com' }
        @{ Name = 'the same name with a plus tag'; Target = 'bookkeeper+tag@partner.example.com' }
        @{ Name = 'a longer local part'; Target = 'bookkeeper2@partner.example.com' }
        @{ Name = 'a shorter local part'; Target = 'bookkeepe@partner.example.com' }
        @{ Name = 'a subdomain'; Target = 'bookkeeper@mail.partner.example.com' }
        @{ Name = 'a longer domain that starts the same'; Target = 'bookkeeper@partner.example.com.example.com' }
        @{ Name = 'a domain that ends the same'; Target = 'bookkeeper@xpartner.example.com' }
        @{ Name = 'a matching display name in front of a different address'; Target = 'Bookkeeper <attacker@partner.example.com>' }
        @{ Name = 'the approved address as display text in front of a different address'; Target = 'bookkeeper@partner.example.com <attacker@partner.example.com>' }
    ) {
        $rows = @(Get-TestExceptionRow -Target 'bookkeeper@partner.example.com')
        Test-M365ApprovedException -UserPrincipalName 'alex@contoso.com' -Target $Target -ApprovedExceptions $rows | Should -BeFalse
    }

    It 'does not treat an exception that starts with an at sign as a domain exception' {
        $rows = @(Get-TestExceptionRow -Target '@partner.example.com')
        Test-M365ApprovedException -UserPrincipalName 'alex@contoso.com' -Target 'bookkeeper@partner.example.com' -ApprovedExceptions $rows |
            Should -BeFalse
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

    It 'approves any address at a bare-domain exception, ignoring case, but not subdomains or lookalikes: <Name>' -ForEach @(
        @{ Name = 'an address at the domain'; Target = 'anyone@example.com'; Expected = $true }
        @{ Name = 'the same in upper case'; Target = 'ANYONE@EXAMPLE.COM'; Expected = $true }
        @{ Name = 'an address with an SMTP: prefix'; Target = 'smtp:anyone@example.com'; Expected = $true }
        @{ Name = 'a target that is the bare domain'; Target = 'example.com'; Expected = $true }
        @{ Name = 'a subdomain'; Target = 'anyone@mail.example.com'; Expected = $false }
        @{ Name = 'a longer domain that starts the same'; Target = 'anyone@example.com.example.com'; Expected = $false }
        @{ Name = 'a domain that ends the same'; Target = 'anyone@notexample.com'; Expected = $false }
        @{ Name = 'a different domain'; Target = 'anyone@contoso.com'; Expected = $false }
    ) {
        $rows = @(Get-TestExceptionRow -Target 'Example.com')
        Test-M365ApprovedException -UserPrincipalName 'alex@contoso.com' -Target $Target -ApprovedExceptions $rows | Should -Be $Expected
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

    It 'honors an exception that expires today or later: <Name>' -ForEach @(
        @{ Name = 'expires today'; Offset = 0 }
        @{ Name = 'expires in 30 days'; Offset = 30 }
    ) {
        $rows = @(Get-TestExceptionRow -Target '*' -Expires (Get-TestDateText -OffsetDays $Offset))
        Test-M365ApprovedException -UserPrincipalName 'alex@contoso.com' -Target 'x@example.com' -ApprovedExceptions $rows |
            Should -BeTrue
    }

    It 'treats a blank or whitespace-only expiry date as no expiry: <Name>' -ForEach @(
        @{ Name = 'empty'; Text = '' }
        @{ Name = 'spaces'; Text = '   ' }
        @{ Name = 'tab'; Text = "`t" }
    ) {
        $rows = @(Get-TestExceptionRow -Target '*' -Expires $Text)
        Test-M365ApprovedException -UserPrincipalName 'alex@contoso.com' -Target 'x@example.com' -ApprovedExceptions $rows |
            Should -BeTrue
    }

    It 'reads the expiry date only as yyyy-MM-dd and skips the exception for any other form: <Text>' -ForEach @(
        @{ Text = '11/05/2026' }
        @{ Text = '05/11/2026' }
        @{ Text = '31.12.2026' }
        @{ Text = '2026-10-10T23:30:00-12:00' }
        @{ Text = '2099-12-31T00:00:00Z' }
        @{ Text = '2099-12-31 00:00' }
        @{ Text = '2099-1-5' }
        @{ Text = '20991231' }
        @{ Text = ' 2099-12-31' }
        @{ Text = '2099-12-31 ' }
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

    It 'reads the expiry date the same way under any culture' {
        $original = [cultureinfo]::CurrentCulture
        try {
            foreach ($cultureName in 'de-DE', 'en-US', 'ja-JP') {
                [cultureinfo]::CurrentCulture = [cultureinfo]::GetCultureInfo($cultureName)

                $dotted = @(Get-TestExceptionRow -Target '*' -Expires '31.12.2099')
                Test-M365ApprovedException -UserPrincipalName 'alex@contoso.com' -Target 'x@example.com' -ApprovedExceptions $dotted |
                    Should -BeFalse -Because "a dotted date must fail closed under $cultureName"

                $iso = @(Get-TestExceptionRow -Target '*' -Expires '2099-12-31')
                Test-M365ApprovedException -UserPrincipalName 'alex@contoso.com' -Target 'x@example.com' -ApprovedExceptions $iso |
                    Should -BeTrue -Because "an ISO date must be honored under $cultureName"
            }
        }
        finally {
            [cultureinfo]::CurrentCulture = $original
        }
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

Describe 'Get-M365BusinessHoursTimeZone' {
    It 'uses the time zone of the computer when the key is absent or blank: <Name>' -ForEach @(
        @{ Name = 'absent'; Settings = [pscustomobject]@{ BusinessHoursStart = 8 } }
        @{ Name = 'empty'; Settings = [pscustomobject]@{ BusinessHoursTimeZone = '' } }
        @{ Name = 'spaces'; Settings = [pscustomobject]@{ BusinessHoursTimeZone = '   ' } }
    ) {
        (Get-M365BusinessHoursTimeZone -Settings $Settings).Id | Should -BeExactly ([System.TimeZoneInfo]::Local.Id)
    }

    It 'finds a time zone by IANA id or by Windows id: <Id>' -ForEach @(
        @{ Id = 'UTC'; Offset = '00:00:00' }
        @{ Id = 'Asia/Kolkata'; Offset = '05:30:00' }
        @{ Id = 'India Standard Time'; Offset = '05:30:00' }
    ) {
        $zone = Get-M365BusinessHoursTimeZone -Settings ([pscustomobject]@{ BusinessHoursTimeZone = $Id })
        $zone.BaseUtcOffset.ToString() | Should -BeExactly $Offset
    }

    It 'throws a message naming the key when the id is not a known time zone' {
        { Get-M365BusinessHoursTimeZone -Settings ([pscustomobject]@{ BusinessHoursTimeZone = 'Nowhere/Land' }) } |
            Should -Throw -ExpectedMessage "*BusinessHoursTimeZone 'Nowhere/Land'*"
    }

    It 'resolves the key shipped in config/settings.example.json' {
        $example = Get-Content -Path (Join-Path (Join-Path $PSScriptRoot '..') 'config/settings.example.json') -Raw | ConvertFrom-Json

        $example.PSObject.Properties.Name | Should -Contain 'BusinessHoursTimeZone'
        { Get-M365BusinessHoursTimeZone -Settings $example } | Should -Not -Throw
    }
}

Describe 'Get-M365BusinessHour' {
    It 'converts a UTC time to the hour in the business time zone: <Name>' -ForEach @(
        @{ Name = 'UTC kept'; Received = [datetime]::SpecifyKind([datetime]'2026-06-15 03:00:00', 'Utc'); Zone = 'UTC'; Expected = 3 }
        @{ Name = 'Kolkata is 5h30 ahead'; Received = [datetime]::SpecifyKind([datetime]'2026-06-15 03:00:00', 'Utc'); Zone = 'Asia/Kolkata'; Expected = 8 }
        @{ Name = 'Kolkata crosses midnight'; Received = [datetime]::SpecifyKind([datetime]'2026-06-15 20:00:00', 'Utc'); Zone = 'Asia/Kolkata'; Expected = 1 }
        @{ Name = 'Kolkata on the half hour'; Received = [datetime]::SpecifyKind([datetime]'2026-06-15 12:45:00', 'Utc'); Zone = 'Asia/Kolkata'; Expected = 18 }
    ) {
        $zone = [System.TimeZoneInfo]::FindSystemTimeZoneById($Zone)
        Get-M365BusinessHour -Received $Received -TimeZone $zone | Should -Be $Expected
    }

    It 'treats a time with no kind as UTC and converts a local time through UTC' {
        $zone = [System.TimeZoneInfo]::FindSystemTimeZoneById('Asia/Kolkata')

        $unspecified = [datetime]::SpecifyKind([datetime]'2026-06-15 03:00:00', 'Unspecified')
        Get-M365BusinessHour -Received $unspecified -TimeZone $zone | Should -Be 8

        $local = [datetime]::SpecifyKind([datetime]'2026-06-15 03:00:00', 'Local')
        $expected = [System.TimeZoneInfo]::ConvertTimeFromUtc($local.ToUniversalTime(), $zone).Hour
        Get-M365BusinessHour -Received $local -TimeZone $zone | Should -Be $expected
    }
}

Describe 'Get-M365OutboundMetadataCounts after-hours counting' {
    BeforeAll {
        . (Join-Path (Join-Path $PSScriptRoot '..') 'src/Get-OutboundMetadataCounts.ps1')

        function global:Get-MessageTraceV2 {
            [CmdletBinding()]
            param($StartDate, $EndDate, $ResultSize)
            $global:TraceStub.LastResultSize = $ResultSize
            return @($global:TraceStub.Rows)
        }

        function Get-TraceRowAt {
            param([string]$SenderAddress, [string]$UtcText)
            return [pscustomobject]@{
                Received         = [datetime]::SpecifyKind([datetime]$UtcText, 'Utc')
                SenderAddress    = $SenderAddress
                RecipientAddress = 'someone@example.com'
                Directionality   = 'Outbound'
                Status           = 'Delivered'
            }
        }

        function Get-HoursSetting {
            param([hashtable]$Override = @{})
            return Get-TestSetting -Override (@{
                    LookbackHours      = 24
                    InternalDomains    = @('contoso.com')
                    BusinessHoursStart = 8
                    BusinessHoursEnd   = 18
                    BaselineMultiplier = 2.5
                } + $Override)
        }

        $global:TraceStub = @{
            Rows = @(
                (Get-TraceRowAt -SenderAddress 'early@contoso.com' -UtcText '2026-06-15 03:00:00')
                (Get-TraceRowAt -SenderAddress 'early@contoso.com' -UtcText '2026-06-15 03:10:00')
                (Get-TraceRowAt -SenderAddress 'midday@contoso.com' -UtcText '2026-06-15 13:00:00')
            )
        }
    }

    AfterAll {
        Remove-Item -Path Function:\global:Get-MessageTraceV2 -ErrorAction SilentlyContinue
        Remove-Variable -Name TraceStub -Scope Global -ErrorAction SilentlyContinue
    }

    It 'counts hours in the configured time zone, not in UTC: <Zone>' -ForEach @(
        @{ Zone = 'UTC'; EarlyAfterHours = 2; MiddayAfterHours = 0 }
        @{ Zone = 'Asia/Kolkata'; EarlyAfterHours = 0; MiddayAfterHours = 1 }
    ) {
        $settings = Get-HoursSetting -Override @{ BusinessHoursTimeZone = $Zone }
        $counts = @(Get-M365OutboundMetadataCounts -Settings $settings -OutputPath (Join-Path $TestDrive 'hours'))

        ($counts | Where-Object SenderAddress -eq 'early@contoso.com').AfterHoursCount | Should -Be $EarlyAfterHours
        ($counts | Where-Object SenderAddress -eq 'midday@contoso.com').AfterHoursCount | Should -Be $MiddayAfterHours
    }

    It 'uses the time zone of the computer when the key is absent' {
        $zone = [System.TimeZoneInfo]::Local
        $expectedEarly = 0
        foreach ($row in $global:TraceStub.Rows | Where-Object SenderAddress -eq 'early@contoso.com') {
            $hour = [System.TimeZoneInfo]::ConvertTimeFromUtc($row.Received, $zone).Hour
            if ($hour -lt 8 -or $hour -ge 18) { $expectedEarly++ }
        }

        $counts = @(Get-M365OutboundMetadataCounts -Settings (Get-HoursSetting) -OutputPath (Join-Path $TestDrive 'hours-local'))

        ($counts | Where-Object SenderAddress -eq 'early@contoso.com').AfterHoursCount | Should -Be $expectedEarly
    }

    It 'stops with a clear message when the configured time zone is unknown, before it asks for the trace' {
        $global:TraceStub.LastResultSize = 'not called'
        $settings = Get-HoursSetting -Override @{ BusinessHoursTimeZone = 'Nowhere/Land' }

        { Get-M365OutboundMetadataCounts -Settings $settings -OutputPath (Join-Path $TestDrive 'hours-bad') } |
            Should -Throw -ExpectedMessage '*BusinessHoursTimeZone*'
        $global:TraceStub.LastResultSize | Should -BeExactly 'not called'
    }

    It 'asks for at most 5000 trace rows and reports no truncation for a short result' {
        $status = @{ Truncated = $false; RowCount = 0 }

        $null = Get-M365OutboundMetadataCounts -Settings (Get-HoursSetting) -OutputPath (Join-Path $TestDrive 'hours-limit') -TraceStatus $status

        $global:TraceStub.LastResultSize | Should -Be 5000
        $status.Truncated | Should -BeFalse
        $status.RowCount | Should -Be 3
    }
}

Describe 'Test-UiScanRequest in the local web interface' {
    BeforeAll {
        $uiScript = Join-Path (Join-Path $PSScriptRoot '..') 'src/Start-ForwardingMonitorUi.ps1'
        . ([scriptblock]::Create((Get-FunctionTextFromFile -Path $uiScript -Name 'Test-UiScanRequest')))
        $pageHtml = & ([scriptblock]::Create((Get-FunctionTextFromFile -Path $uiScript -Name 'Get-UiIndexHtml') + "`nGet-UiIndexHtml"))
    }

    It 'allows a request with no Origin header or the server''s own origin, and a JSON body: <Name>' -ForEach @(
        @{ Name = 'no Origin'; Origin = $null; ContentType = 'application/json' }
        @{ Name = 'own origin'; Origin = 'http://localhost:8181'; ContentType = 'application/json' }
        @{ Name = 'own origin in other case'; Origin = 'HTTP://LocalHost:8181'; ContentType = 'application/json' }
        @{ Name = 'charset parameter'; Origin = 'http://localhost:8181'; ContentType = 'application/json; charset=utf-8' }
        @{ Name = 'upper-case media type'; Origin = $null; ContentType = 'Application/JSON' }
    ) {
        (Test-UiScanRequest -Origin $Origin -ContentType $ContentType -Port 8181).Allowed | Should -BeTrue
    }

    It 'rejects an Origin header that is not the server''s own: <Name>' -ForEach @(
        @{ Name = 'another site'; Origin = 'http://evil.example.com' }
        @{ Name = 'opaque origin'; Origin = 'null' }
        @{ Name = 'same host, other port'; Origin = 'http://localhost:8182' }
        @{ Name = 'same host, https'; Origin = 'https://localhost:8181' }
        @{ Name = 'longer host name'; Origin = 'http://localhost.example.com:8181' }
        @{ Name = 'loopback address instead of the name'; Origin = 'http://127.0.0.1:8181' }
        @{ Name = 'empty header'; Origin = '' }
    ) {
        $result = Test-UiScanRequest -Origin $Origin -ContentType 'application/json' -Port 8181

        $result.Allowed | Should -BeFalse
        $result.Reason | Should -BeLike '*origin*'
    }

    It 'rejects a body that is not declared as application/json: <Name>' -ForEach @(
        @{ Name = 'missing'; ContentType = $null }
        @{ Name = 'empty'; ContentType = '' }
        @{ Name = 'plain text'; ContentType = 'text/plain' }
        @{ Name = 'form post'; ContentType = 'application/x-www-form-urlencoded' }
        @{ Name = 'multipart form'; ContentType = 'multipart/form-data; boundary=x' }
        @{ Name = 'a longer JSON type'; ContentType = 'application/json-patch+json' }
        @{ Name = 'a JSON type with a prefix'; ContentType = 'text/application/json' }
    ) {
        $result = Test-UiScanRequest -Origin 'http://localhost:8181' -ContentType $ContentType -Port 8181

        $result.Allowed | Should -BeFalse
        $result.Reason | Should -BeLike '*Content-Type*'
    }

    It 'rejects a request that is wrong on both counts' {
        (Test-UiScanRequest -Origin 'http://evil.example.com' -ContentType 'text/plain' -Port 8181).Allowed | Should -BeFalse
    }

    It 'sends the JSON content type from the page itself so its own button still works' {
        $pageHtml | Should -BeLike "*fetch('/api/scan'*Content-Type*application/json*"
    }
}

Describe 'Local web interface over HTTP' {
    BeforeAll {
        $uiScript = Join-Path (Join-Path $PSScriptRoot '..') 'src/Start-ForwardingMonitorUi.ps1'
        $projectRoot = Join-Path $TestDrive 'ui-project'
        New-Item -ItemType Directory -Path $projectRoot -Force | Out-Null

        $probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $probe.Start()
        $uiPort = $probe.LocalEndpoint.Port
        $probe.Stop()

        $uiLog = Join-Path $TestDrive 'ui-output.log'
        $uiProcess = Start-Process -FilePath (Get-Process -Id $PID).Path -PassThru -RedirectStandardOutput $uiLog -RedirectStandardError (Join-Path $TestDrive 'ui-error.log') `
            -ArgumentList @('-NoProfile', '-File', $uiScript, '-ProjectRoot', $projectRoot, '-Port', $uiPort)

        $uiReady = $false
        for ($attempt = 0; $attempt -lt 60 -and -not $uiReady; $attempt++) {
            try {
                $uiReady = (Invoke-WebRequest -Uri "http://localhost:$uiPort/api/status" -TimeoutSec 2 -SkipHttpErrorCheck).StatusCode -eq 200
            }
            catch { Start-Sleep -Milliseconds 500 }
        }

        function Send-ScanRequest {
            param([hashtable]$Headers = @{}, [string]$ContentType, [string]$Method = 'Post')
            $parameters = @{ Uri = "http://localhost:$uiPort/api/scan"; Method = $Method; Headers = $Headers; Body = '{}'; SkipHttpErrorCheck = $true; TimeoutSec = 10 }
            if ($ContentType) { $parameters.ContentType = $ContentType }
            return Invoke-WebRequest @parameters
        }
    }

    AfterAll {
        if ($uiProcess -and -not $uiProcess.HasExited) { Stop-Process -Id $uiProcess.Id -Force }
    }

    It 'starts and answers the status request' {
        $uiReady | Should -BeTrue -Because 'the UI process did not answer within 30 seconds'
    }

    It 'answers 403 to a scan request from another origin, even with a JSON body' {
        $response = Send-ScanRequest -Headers @{ Origin = 'http://evil.example.com' } -ContentType 'application/json'

        [int]$response.StatusCode | Should -Be 403
        $response.Content | Should -BeLike '*origin*'
    }

    It 'answers 403 to a scan request that is not declared as JSON: <Name>' -ForEach @(
        @{ Name = 'form body, no origin'; Headers = @{}; ContentType = 'application/x-www-form-urlencoded' }
        @{ Name = 'plain text, own origin'; Headers = @{ Origin = 'http://localhost:PORT' }; ContentType = 'text/plain' }
    ) {
        if ($Headers.ContainsKey('Origin')) { $Headers.Origin = $Headers.Origin -replace 'PORT', $uiPort }
        $response = Send-ScanRequest -Headers $Headers -ContentType $ContentType

        [int]$response.StatusCode | Should -Be 403
        $response.Content | Should -BeLike '*Content-Type*'
    }

    It 'still answers 405 to a scan request that is not a POST' {
        [int](Send-ScanRequest -Method Get).StatusCode | Should -Be 405
    }
}

Describe 'New-M365ForwardingDashboard warnings' {
    BeforeAll {
        . (Join-Path (Join-Path $PSScriptRoot '..') 'src/New-Dashboard.ps1')

        function Get-DashboardText {
            param([object]$Summary)
            $folder = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            $path = New-M365ForwardingDashboard -Summary $Summary -ForwardingFindings @() -OutboundCounts @() -OutputPath $folder
            return (Get-Content -LiteralPath $path -Raw)
        }

        function Get-DashboardSummary {
            param([string[]]$MailboxFailed = @(), [string[]]$RuleFailed = @(), [bool]$Truncated = $false)
            return [pscustomobject]@{
                TotalUsersScanned             = 5
                UsersWithMailboxForwarding    = 0
                UsersWithInboxRuleForwarding  = 0
                ExternalForwardingCount       = 0
                PersonalDomainForwardingCount = 0
                ApprovedExceptionsCount       = 0
                HighCriticalRiskCount         = 0
                AbnormalOutboundCount         = 0
                AboveBaselineOutboundCount    = 0
                TraceTruncated                = $Truncated
                CollectionFailures            = [pscustomobject]@{
                    MailboxForwarding = [pscustomobject]@{ Count = $MailboxFailed.Count; UserPrincipalNames = $MailboxFailed }
                    InboxRules        = [pscustomobject]@{ Count = $RuleFailed.Count; UserPrincipalNames = $RuleFailed }
                }
            }
        }
    }

    It 'shows no warning block when nothing failed and the trace was complete' {
        Get-DashboardText -Summary (Get-DashboardSummary) | Should -Not -BeLike '*Incomplete scan*'
    }

    It 'renders a summary without the failure fields, as older runs wrote it, with no warning' {
        $older = Get-DashboardSummary | Select-Object -Property * -ExcludeProperty CollectionFailures, TraceTruncated

        Get-DashboardText -Summary $older | Should -Not -BeLike '*Incomplete scan*'
    }

    It 'puts a warning with the counts and names at the top when collection failed' {
        $html = Get-DashboardText -Summary (Get-DashboardSummary -MailboxFailed @('a@contoso.com', 'b@contoso.com') -RuleFailed @('c@contoso.com'))

        $html | Should -BeLike '*Incomplete scan*'
        $html | Should -BeLike '*Mailbox forwarding could not be read for 2 users: a@contoso.com, b@contoso.com*'
        $html | Should -BeLike '*Inbox rules could not be read for 1 user: c@contoso.com*'
        $html.IndexOf('Incomplete scan') | Should -BeLessThan $html.IndexOf('Total users scanned')
    }

    It 'encodes the user names it lists and caps a long list' {
        $names = @('x<script>@contoso.com') + @(1..30 | ForEach-Object { "user$_@contoso.com" })
        $html = Get-DashboardText -Summary (Get-DashboardSummary -MailboxFailed $names)

        $html | Should -BeLike '*x&lt;script&gt;@contoso.com*'
        $html | Should -Not -BeLike '*<script>@contoso.com*'
        $html | Should -BeLike '*and 6 more*'
    }

    It 'warns that outbound counts can be too low when the trace reached its row limit' {
        $html = Get-DashboardText -Summary (Get-DashboardSummary -Truncated $true)

        $html | Should -BeLike '*Incomplete scan*'
        $html | Should -BeLike '*message trace reached its row limit*'
    }
}

Describe 'Docker image contents' {
    It 'keeps .env out of the image' {
        Get-Content -Path (Join-Path (Join-Path $PSScriptRoot '..') '.dockerignore') | Should -Contain '.env'
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
                $ruleUpn = $Matches['upn']
                if ($global:OfflineRun.RuleErrors -contains $ruleUpn) { throw "Graph rules call failed for $ruleUpn" }
                $rules = $global:OfflineRun.Rules[$ruleUpn]
                return @{ value = @($rules | Where-Object { $_ }) }
            }
            if ($global:OfflineRun.UsersError) { throw 'Graph user list is unavailable' }
            return @{ value = @($global:OfflineRun.Users) }
        }
        function global:Get-Mailbox {
            [CmdletBinding()]
            param($Identity)
            if ($global:OfflineRun.MailboxErrors -contains $Identity) { throw "Mailbox $Identity is unavailable" }
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
            param($StartDate, $EndDate, $ResultSize)
            $global:OfflineRun.LastResultSize = $ResultSize
            if ($global:OfflineRun.TraceError) { throw 'Message trace is unavailable' }
            if (-not $ResultSize) { $ResultSize = 1000 }
            return @($global:OfflineRun.Traces | Select-Object -First $ResultSize)
        }
        function global:Start-Sleep {
            [CmdletBinding()]
            param($Seconds, $Milliseconds)
        }
        function global:Move-Item {
            [CmdletBinding()]
            param($LiteralPath, $Destination, [switch]$Force)
            $global:MoveLog += (Split-Path -Leaf $Destination)
            Microsoft.PowerShell.Management\Move-Item -LiteralPath $LiteralPath -Destination $Destination -Force:$Force
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
                Received         = [datetime]::SpecifyKind((Get-Date).Date.AddHours(11), 'Utc')
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
                -ApprovedExceptionsPath (Join-Path $runRoot 'exceptions.csv') -SkipConnect 6>$null 3>$null
            return $outputDir
        }

        function Get-OutputSnapshot {
            param([string]$Directory)
            $snapshot = [ordered]@{}
            foreach ($file in Get-ChildItem -LiteralPath $Directory -File -Force | Where-Object Name -ne 'errors.log' | Sort-Object Name) {
                $snapshot[$file.Name] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
            }
            return ($snapshot | ConvertTo-Json -Compress)
        }
    }

    AfterAll {
        Remove-Item -Path Function:\global:Invoke-MgGraphRequest, Function:\global:Get-Mailbox, Function:\global:Get-MessageTraceV2, Function:\global:Start-Sleep, Function:\global:Move-Item -ErrorAction SilentlyContinue
        Remove-Variable -Name OfflineRun, MoveLog -Scope Global -ErrorAction SilentlyContinue
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
            $global:MoveLog = @()
            $outputDir = Invoke-OfflineMonitorRun -Name 'mailbox' -Scenario $scenario -ExceptionTarget 'records@partner.example.com'
            $moved = @($global:MoveLog)
        }

        It 'puts the eight output files in place with the dashboard last' {
            $moved.Count | Should -Be 8
            $moved[-1] | Should -BeExactly 'dashboard.html'
            @($moved | Sort-Object) | Should -Be @('dashboard.html', 'forwarding-findings.csv', 'forwarding-findings.json',
                'outbound-baseline-history.json', 'outbound-metadata-counts.csv', 'outbound-metadata-counts.json',
                'summary.csv', 'summary.json')
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

        It 'records no collection failures, asks the trace for 5000 rows, leaves no temporary files and shows no warning' {
            $summary = Get-Content -Path (Join-Path $outputDir 'summary.json') -Raw | ConvertFrom-Json

            $summary.TraceTruncated | Should -BeFalse
            $summary.CollectionFailures.MailboxForwarding.Count | Should -Be 0
            $summary.CollectionFailures.InboxRules.Count | Should -Be 0
            @($summary.CollectionFailures.MailboxForwarding.UserPrincipalNames).Count | Should -Be 0
            $scenario.LastResultSize | Should -Be 5000
            @(Get-ChildItem -LiteralPath $outputDir -Force -Filter '*.tmp').Count | Should -Be 0
            Get-Content -Path (Join-Path $outputDir 'dashboard.html') -Raw | Should -Not -BeLike '*Incomplete scan*'
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

        It 'neutralizes a formula-like sender address in the outbound CSV but keeps the raw value in the JSON' {
            $csv = @(Import-Csv -Path (Join-Path $outputDir 'outbound-metadata-counts.csv'))
            $json = @(Get-Content -Path (Join-Path $outputDir 'outbound-metadata-counts.json') -Raw | ConvertFrom-Json)

            ($csv | Where-Object ExternalSentCount -eq 1).SenderAddress | Should -BeExactly "'=ops@contoso.com"
            ($csv | Where-Object ExternalSentCount -eq 1).UserPrincipalName | Should -BeExactly "'=ops@contoso.com"
            ($json | Where-Object ExternalSentCount -eq 1).SenderAddress | Should -BeExactly '=ops@contoso.com'
        }

        It 'neutralizes formula-like display names in the findings CSV but keeps the raw value in the JSON' {
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

        It 'neutralizes the rule name and forward target in the findings CSV but keeps the raw rule name in the JSON' {
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

    Context 'with a single finding and a single outbound sender' {
        BeforeAll {
            $scenario = @{
                Users     = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber'))
                Mailboxes = @{ 'alex.wilber@contoso.com' = 'smtp:records@partner.example.com' }
                Rules     = @{}
                Traces    = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com'))
            }
            $outputDir = Invoke-OfflineMonitorRun -Name 'single' -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com'
            $firstRun = @{}
            foreach ($file in 'forwarding-findings.json', 'outbound-metadata-counts.json', 'outbound-baseline-history.json') {
                $firstRun[$file] = Get-Content -Path (Join-Path $outputDir $file) -Raw
            }
            $null = Invoke-OfflineMonitorRun -Name 'single' -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com'
        }

        It 'writes one finding, one outbound row and one history record as one-element JSON arrays: <File>' -ForEach @(
            @{ File = 'forwarding-findings.json' }
            @{ File = 'outbound-metadata-counts.json' }
            @{ File = 'outbound-baseline-history.json' }
        ) {
            $firstRun[$File].TrimStart() | Should -BeLike '`[*'
            $parsed = $firstRun[$File] | ConvertFrom-Json -NoEnumerate
            ($parsed -is [array]) | Should -BeTrue
            $parsed.Count | Should -Be 1
        }

        It 'reads a one-record history back as a list and appends to it on the next run' {
            $history = Get-Content -Path (Join-Path $outputDir 'outbound-baseline-history.json') -Raw | ConvertFrom-Json -NoEnumerate

            ($history -is [array]) | Should -BeTrue
            $history.Count | Should -Be 2
        }
    }

    Context 'when the user list cannot be read' {
        BeforeAll {
            $users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber'), (Get-OfflineUser -Name 'sam.okafor' -DisplayName 'Sam Okafor'))
            $good = @{ Users = $users; Mailboxes = @{ 'alex.wilber@contoso.com' = 'smtp:records@partner.example.com' }; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com')) }
            $outputDir = Invoke-OfflineMonitorRun -Name 'users-fail' -Scenario $good -ExceptionTarget 'nobody@partner.example.com'
            $before = Get-OutputSnapshot -Directory $outputDir

            $thrown = $null
            try {
                $null = Invoke-OfflineMonitorRun -Name 'users-fail' -ExceptionTarget 'nobody@partner.example.com' `
                    -Scenario @{ Users = $users; UsersError = $true; Mailboxes = @{}; Rules = @{}; Traces = @() }
            }
            catch { $thrown = $_ }
        }

        It 'stops the run with an error that names the call' {
            $thrown | Should -Not -BeNullOrEmpty
            $thrown.Exception.Message | Should -BeLike '*Graph users list failed after 3 attempt(s)*'
        }

        It 'leaves every earlier output file untouched and writes no temporary file' {
            Get-OutputSnapshot -Directory $outputDir | Should -BeExactly $before
        }
    }

    Context 'when Get-Mailbox fails for every user' {
        BeforeAll {
            $users = @(
                (Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber')
                (Get-OfflineUser -Name 'sam.okafor' -DisplayName 'Sam Okafor')
                (Get-OfflineUser -Name 'priya.nair' -DisplayName 'Priya Nair')
            )
            $good = @{ Users = $users; Mailboxes = @{ 'alex.wilber@contoso.com' = 'smtp:records@partner.example.com' }; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com')) }
            $outputDir = Invoke-OfflineMonitorRun -Name 'mailbox-all-fail' -Scenario $good -ExceptionTarget 'nobody@partner.example.com'
            $before = Get-OutputSnapshot -Directory $outputDir

            $thrown = $null
            try {
                $null = Invoke-OfflineMonitorRun -Name 'mailbox-all-fail' -ExceptionTarget 'nobody@partner.example.com' -Scenario @{
                    Users = $users; Mailboxes = @{}; Rules = @{}; Traces = @()
                    MailboxErrors = @('alex.wilber@contoso.com', 'sam.okafor@contoso.com', 'priya.nair@contoso.com')
                }
            }
            catch { $thrown = $_ }
        }

        It 'stops the run instead of reporting all clear' {
            $thrown | Should -Not -BeNullOrEmpty
            $thrown.Exception.Message | Should -BeLike '*Mailbox forwarding could not be read for any scanned user (3 of 3 failed)*No output files were changed*'
        }

        It 'leaves every earlier output file untouched and writes no temporary file' {
            Get-OutputSnapshot -Directory $outputDir | Should -BeExactly $before
        }

        It 'records the stop in errors.log' {
            Get-Content -Path (Join-Path $outputDir 'errors.log') -Raw | Should -BeLike '*Invoke-ForwardingMonitor failed.*Mailbox forwarding could not be read*'
        }
    }

    Context 'when every inbox rule call fails' {
        BeforeAll {
            $users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber'), (Get-OfflineUser -Name 'sam.okafor' -DisplayName 'Sam Okafor'))
            $good = @{ Users = $users; Mailboxes = @{}; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com')) }
            $outputDir = Invoke-OfflineMonitorRun -Name 'rules-all-fail' -Scenario $good -ExceptionTarget 'nobody@partner.example.com'
            $before = Get-OutputSnapshot -Directory $outputDir

            $thrown = $null
            try {
                $null = Invoke-OfflineMonitorRun -Name 'rules-all-fail' -ExceptionTarget 'nobody@partner.example.com' -Scenario @{
                    Users = $users; Mailboxes = @{}; Rules = @{}; Traces = @()
                    RuleErrors = @('alex.wilber@contoso.com', 'sam.okafor@contoso.com')
                }
            }
            catch { $thrown = $_ }
        }

        It 'stops the run and leaves every earlier output file untouched' {
            $thrown.Exception.Message | Should -BeLike '*Inbox rules could not be read for any scanned user (2 of 2 failed)*'
            Get-OutputSnapshot -Directory $outputDir | Should -BeExactly $before
        }
    }

    Context 'when the message trace cannot be read' {
        BeforeAll {
            $users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber'))
            $good = @{ Users = $users; Mailboxes = @{}; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com')) }
            $outputDir = Invoke-OfflineMonitorRun -Name 'trace-fail' -Scenario $good -ExceptionTarget 'nobody@partner.example.com'
            $before = Get-OutputSnapshot -Directory $outputDir

            $thrown = $null
            try {
                $null = Invoke-OfflineMonitorRun -Name 'trace-fail' -ExceptionTarget 'nobody@partner.example.com' `
                    -Scenario @{ Users = $users; Mailboxes = @{}; Rules = @{}; Traces = @(); TraceError = $true }
            }
            catch { $thrown = $_ }
        }

        It 'stops the run with an error that names the call, not an empty outbound report' {
            $thrown | Should -Not -BeNullOrEmpty
            $thrown.Exception.Message | Should -BeLike '*Get-MessageTraceV2 outbound metadata failed after 3 attempt(s)*'
        }

        It 'leaves every earlier output file untouched and writes no temporary file' {
            Get-OutputSnapshot -Directory $outputDir | Should -BeExactly $before
        }
    }

    Context 'when Get-Mailbox fails for one user and the inbox rule call fails for another' {
        BeforeAll {
            $scenario = @{
                Users         = @(
                    (Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber')
                    (Get-OfflineUser -Name 'sam.okafor' -DisplayName 'Sam Okafor')
                    (Get-OfflineUser -Name 'priya.nair' -DisplayName 'Priya Nair')
                    (Get-OfflineUser -Name 'chris.lindqvist' -DisplayName 'Chris Lindqvist')
                )
                Mailboxes     = @{ 'alex.wilber@contoso.com' = 'smtp:records@partner.example.com' }
                Rules         = @{ 'chris.lindqvist@contoso.com' = @((Get-OfflineRule -Name 'Copy invoices' -Target 'invoices@vendor.example.com')) }
                Traces        = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com'))
                MailboxErrors = @('sam.okafor@contoso.com')
                RuleErrors    = @('priya.nair@contoso.com')
            }
            $outputDir = Invoke-OfflineMonitorRun -Name 'partial' -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com'
        }

        It 'completes and counts each failure by collector with the user names in summary.json' {
            $summary = Get-Content -Path (Join-Path $outputDir 'summary.json') -Raw | ConvertFrom-Json

            $summary.TotalUsersScanned | Should -Be 4
            $summary.CollectionFailures.MailboxForwarding.Count | Should -Be 1
            @($summary.CollectionFailures.MailboxForwarding.UserPrincipalNames) | Should -Be @('sam.okafor@contoso.com')
            $summary.CollectionFailures.InboxRules.Count | Should -Be 1
            @($summary.CollectionFailures.InboxRules.UserPrincipalNames) | Should -Be @('priya.nair@contoso.com')
        }

        It 'still reports the findings it could read' {
            $findings = @(Get-Content -Path (Join-Path $outputDir 'forwarding-findings.json') -Raw | ConvertFrom-Json)

            $findings.Count | Should -Be 2
            ($findings | Where-Object UserPrincipalName -eq 'alex.wilber@contoso.com').ForwardingType | Should -BeExactly 'MailboxForwarding'
            ($findings | Where-Object UserPrincipalName -eq 'chris.lindqvist@contoso.com').ForwardingType | Should -BeExactly 'InboxRuleForward'
        }

        It 'shows an incomplete-scan warning that names both users at the top of the dashboard' {
            $html = Get-Content -Path (Join-Path $outputDir 'dashboard.html') -Raw

            $html | Should -BeLike '*Incomplete scan*'
            $html | Should -BeLike '*Mailbox forwarding could not be read for 1 user: sam.okafor@contoso.com*'
            $html | Should -BeLike '*Inbox rules could not be read for 1 user: priya.nair@contoso.com*'
            $html.IndexOf('Incomplete scan') | Should -BeLessThan $html.IndexOf('Total users scanned')
        }

        It 'adds the failure counts to summary.csv' {
            $row = @(Import-Csv -Path (Join-Path $outputDir 'summary.csv'))[0]

            $row.MailboxForwardingFailures | Should -BeExactly '1'
            $row.InboxRuleFailures | Should -BeExactly '1'
            $row.TraceTruncated | Should -BeExactly 'False'
        }
    }

    Context 'when forwarding-findings.csv cannot be replaced' {
        BeforeAll {
            $users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber'), (Get-OfflineUser -Name 'sam.okafor' -DisplayName 'Sam Okafor'))
            $first = @{ Users = $users; Mailboxes = @{ 'alex.wilber@contoso.com' = 'smtp:records@partner.example.com' }; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com')) }
            $outputDir = Invoke-OfflineMonitorRun -Name 'read-only' -Scenario $first -ExceptionTarget 'nobody@partner.example.com'
            $csvPath = Join-Path $outputDir 'forwarding-findings.csv'
            $before = Get-OutputSnapshot -Directory $outputDir
            Set-ItemProperty -LiteralPath $csvPath -Name IsReadOnly -Value $true

            $changed = @{ Users = $users; Mailboxes = @{ 'sam.okafor@contoso.com' = 'smtp:sam.home@webmail.example.com' }; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'sam.okafor@contoso.com' -Recipient 'b@vendor.example.com')) }
            $thrown = $null
            try { $null = Invoke-OfflineMonitorRun -Name 'read-only' -Scenario $changed -ExceptionTarget 'nobody@partner.example.com' }
            catch { $thrown = $_ }
            $after = Get-OutputSnapshot -Directory $outputDir
        }

        AfterAll {
            Set-ItemProperty -LiteralPath $csvPath -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
        }

        It 'stops the run with a message that names the read-only file' {
            $thrown | Should -Not -BeNullOrEmpty
            $thrown.Exception.Message | Should -BeLike '*read-only*forwarding-findings.csv*'
        }

        It 'leaves the whole earlier set unchanged: dashboard, JSON, CSV and history, with no temporary files' {
            $after | Should -BeExactly $before
        }
    }

    Context 'when the message trace returns the maximum number of rows' {
        BeforeAll {
            $scenario = @{
                Users     = @((Get-OfflineUser -Name 'priya.nair' -DisplayName 'Priya Nair'))
                Mailboxes = @{}
                Rules     = @{}
                Traces    = @(1..5000 | ForEach-Object { Get-OfflineTrace -SenderAddress 'priya.nair@contoso.com' -Recipient "r$($_ % 20)@vendor.example.com" })
            }
            $outputDir = Invoke-OfflineMonitorRun -Name 'truncated' -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com'
        }

        It 'sets TraceTruncated in summary.json and summary.csv and still reports the rows it got' {
            $summary = Get-Content -Path (Join-Path $outputDir 'summary.json') -Raw | ConvertFrom-Json
            $counts = @(Get-Content -Path (Join-Path $outputDir 'outbound-metadata-counts.json') -Raw | ConvertFrom-Json)

            $scenario.LastResultSize | Should -Be 5000
            $summary.TraceTruncated | Should -BeTrue
            @(Import-Csv -Path (Join-Path $outputDir 'summary.csv'))[0].TraceTruncated | Should -BeExactly 'True'
            $counts[0].ExternalSentCount | Should -Be 5000
        }

        It 'writes a warning to errors.log and shows one on the dashboard' {
            Get-Content -Path (Join-Path $outputDir 'errors.log') -Raw | Should -BeLike '*Message trace returned the maximum of 5000 rows*'
            $html = Get-Content -Path (Join-Path $outputDir 'dashboard.html') -Raw
            $html | Should -BeLike '*Incomplete scan*'
            $html | Should -BeLike '*message trace reached its row limit*'
        }
    }
}
