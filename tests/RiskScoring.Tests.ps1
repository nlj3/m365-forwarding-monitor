#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares BeforeDiscovery and BeforeEach variables with It blocks.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Justification = 'The stub functions are global so the script under test can call them, and they read the current scenario from one global variable.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'The stub functions accept the same parameters as the commands they replace but do not need them.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'The offline run replaces Start-Sleep with a no-op so failed calls do not wait between retries.')]
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

    # Stands in for the exception Exchange Online throws when Get-Mailbox finds no such recipient.
    if (-not ('Microsoft.Exchange.Configuration.Tasks.ManagementObjectNotFoundException' -as [type])) {
        Add-Type -TypeDefinition 'namespace Microsoft.Exchange.Configuration.Tasks { public class ManagementObjectNotFoundException : System.Exception { public ManagementObjectNotFoundException(string message) : base(message) { } } }'
    }

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
        @{ Name = 'domain with no local part'; Target = '@contoso.com' }
        @{ Name = 'two at signs in a row'; Target = 'alex@@contoso.com' }
        @{ Name = 'a quoted local part that holds another address'; Target = '"a@contoso.com x"@evil.example.com' }
        @{ Name = 'display text holding one address in front of another'; Target = 'Bob smtp:a@good.example.com <b@evil.example.com>' }
        @{ Name = 'two addresses separated by a space'; Target = 'a@good.example.com b@evil.example.com' }
        @{ Name = 'two addresses separated by a semicolon'; Target = 'b@evil.example.com;a@good.example.com' }
        @{ Name = 'two addresses separated by a comma'; Target = 'a@good.example.com,b@evil.example.com' }
        @{ Name = 'two SMTP: addresses'; Target = 'SMTP:alex@contoso.com;smtp:b@example.com' }
    ) {
        $result = Get-M365TargetDomain -Target $Target
        $result | Should -BeNullOrEmpty
    }

    It 'does not return a domain that only looks like a listed one: <Name>' -ForEach @(
        @{ Name = 'soft hyphen in the domain'; Target = "alex@con`u{00AD}toso.com" }
        @{ Name = 'zero-width space in the domain'; Target = "alex@contoso`u{200B}.com" }
    ) {
        $domain = Get-M365TargetDomain -Target $Target

        [string]::Equals($domain, 'contoso.com', [System.StringComparison]::OrdinalIgnoreCase) | Should -BeFalse
    }
}

Describe 'Get-M365TargetAddress' {
    It 'returns the lower-cased address from every plain form: <Target>' -ForEach @(
        @{ Target = 'alex@contoso.com' }
        @{ Target = 'ALEX@Contoso.COM' }
        @{ Target = '   alex@contoso.com   ' }
        @{ Target = 'SMTP:alex@contoso.com' }
        @{ Target = 'smtp:Alex@Contoso.com' }
        @{ Target = 'sMtP: alex@contoso.com' }
        @{ Target = 'Alex Wilber <alex@contoso.com>' }
        @{ Target = '"Wilber, Alex" <alex@contoso.com>' }
        @{ Target = '<alex@contoso.com>' }
    ) {
        Get-M365TargetAddress -Target $Target | Should -BeExactly 'alex@contoso.com'
    }

    It 'returns no address when the text holds none or more than one: <Name>' -ForEach @(
        @{ Name = 'null'; Target = $null }
        @{ Name = 'blank'; Target = '  ' }
        @{ Name = 'no at sign'; Target = 'Alex Wilber' }
        @{ Name = 'a quoted local part that holds another address'; Target = '"a@contoso.com x"@evil.example.com' }
        @{ Name = 'display text holding one address in front of another'; Target = 'Bob smtp:a@good.example.com <b@evil.example.com>' }
        @{ Name = 'two addresses separated by a space'; Target = 'a@good.example.com b@evil.example.com' }
        @{ Name = 'two addresses separated by a semicolon'; Target = 'b@evil.example.com;a@good.example.com' }
        @{ Name = 'two addresses separated by a comma'; Target = 'a@good.example.com, b@evil.example.com' }
        @{ Name = 'two at signs in a row'; Target = 'a@@good.example.com' }
        @{ Name = 'a bare at sign and domain'; Target = '@good.example.com' }
    ) {
        $result = Get-M365TargetAddress -Target $Target
        $result | Should -BeNullOrEmpty
    }

    It 'does not return text that only looks like a plain address: <Name>' -ForEach @(
        @{ Name = 'soft hyphen in the local part'; Target = "al`u{00AD}ice@good.example.com" }
        @{ Name = 'zero-width space in the local part'; Target = "al`u{200B}ice@good.example.com" }
        @{ Name = 'soft hyphen in the domain'; Target = "alice@good.exam`u{00AD}ple.com" }
    ) {
        $result = Get-M365TargetAddress -Target $Target

        [string]::Equals($result, 'alice@good.example.com', [System.StringComparison]::OrdinalIgnoreCase) | Should -BeFalse
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
        @{ Name = 'soft hyphen inside a listed domain'; Domain = "con`u{00AD}toso.com"; Internal = @('contoso.com') }
        @{ Name = 'zero-width space inside a listed domain'; Domain = "contoso`u{200B}.com"; Internal = @('contoso.com') }
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
        @{ Name = 'soft hyphen inside a listed domain'; Domain = "web`u{00AD}mail.example.com"; List = @('webmail.example.com', 'FREEMAIL.example.com'); Expected = $false }
        @{ Name = 'zero-width space inside a listed domain'; Domain = "webmail`u{200B}.example.com"; List = @('webmail.example.com', 'FREEMAIL.example.com'); Expected = $false }
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
        @{ Name = 'a quoted local part that holds the approved address'; Target = '"bookkeeper@partner.example.com x"@evil.example.com' }
        @{ Name = 'two addresses with a space between them'; Target = 'bookkeeper@partner.example.com attacker@evil.example.com' }
        @{ Name = 'two addresses with a semicolon between them'; Target = 'attacker@evil.example.com;bookkeeper@partner.example.com' }
        @{ Name = 'a soft hyphen in the local part'; Target = "book`u{00AD}keeper@partner.example.com" }
        @{ Name = 'a zero-width space in the local part'; Target = "book`u{200B}keeper@partner.example.com" }
        @{ Name = 'a soft hyphen in the domain'; Target = "bookkeeper@part`u{00AD}ner.example.com" }
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
        @{ Name = 'a soft hyphen in the domain'; Target = "anyone@exam`u{00AD}ple.com"; Expected = $false }
        @{ Name = 'a zero-width space in the domain'; Target = "anyone@example`u{200B}.com"; Expected = $false }
        @{ Name = 'a quoted local part that holds an address at the domain'; Target = '"a@example.com x"@evil.example.com'; Expected = $false }
        @{ Name = 'two addresses, one at the domain'; Target = 'anyone@example.com attacker@evil.example.com'; Expected = $false }
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

Describe 'Test-M365ApprovedException user names' {
    It 'does not approve a user name that only looks like the one in the exception: <Name>' -ForEach @(
        @{ Name = 'soft hyphen'; User = "al`u{00AD}ex@contoso.com" }
        @{ Name = 'zero-width space'; User = "alex`u{200B}@contoso.com" }
    ) {
        $rows = @(Get-TestExceptionRow -User 'alex@contoso.com' -Target '*')
        Test-M365ApprovedException -UserPrincipalName $User -Target 'x@example.com' -ApprovedExceptions $rows | Should -BeFalse
    }

    It 'treats a wildcard written with a lookalike character as an ordinary address, not a wildcard' {
        $rows = @(Get-TestExceptionRow -Target "an`u{00AD}y")
        Test-M365ApprovedException -UserPrincipalName 'alex@contoso.com' -Target 'x@example.com' -ApprovedExceptions $rows | Should -BeFalse
    }
}

Describe 'Get-M365ExceptionExpiry' {
    It 'reports the state and date of an expiry value: <Name>' -ForEach @(
        @{ Name = 'blank'; Text = ''; State = 'None' }
        @{ Name = 'whitespace'; Text = "  `t"; State = 'None' }
        @{ Name = 'a plain date'; Text = '2099-12-31'; State = 'Valid' }
        @{ Name = 'a date with a time'; Text = '2099-12-31T10:00:00Z'; State = 'Unreadable' }
        @{ Name = 'a day-first date'; Text = '31.12.2099'; State = 'Unreadable' }
        @{ Name = 'text'; Text = 'next year'; State = 'Unreadable' }
    ) {
        $expiry = Get-M365ExceptionExpiry -Exception (Get-TestExceptionRow -Expires $Text)

        $expiry.State | Should -BeExactly $State
        if ($State -eq 'Valid') { $expiry.Date | Should -Be ([datetime]'2099-12-31') }
    }

    It 'throws when the row has no ExpirationDate column' {
        { Get-M365ExceptionExpiry -Exception ([pscustomobject]@{ UserPrincipalName = 'alex@contoso.com'; ApprovedTarget = '*' }) } |
            Should -Throw -ExpectedMessage '*ExpirationDate*'
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

    It 'stops at once and rethrows the original error when it matches NoRetryPattern' {
        $thrown = $null
        try {
            Invoke-M365CallWithRetry -OperationName 'lookup' -OutputPath $outputPath -MaxAttempts 3 -ThrowOnFailure -NoRetryPattern 'not here' -ScriptBlock {
                $state.Calls++
                throw 'The thing is not here at all'
            }
        }
        catch { $thrown = $_ }

        $state.Calls | Should -Be 1
        $thrown.Exception.Message | Should -BeExactly 'The thing is not here at all'
        Should -Invoke Start-Sleep -ModuleName RiskScoring -Times 0 -Exactly
        Join-Path $outputPath 'errors.log' | Should -Not -Exist
    }

    It 'stops at once and rethrows the original error when NoRetryWhen says so for it' {
        $thrown = $null
        try {
            Invoke-M365CallWithRetry -OperationName 'lookup' -OutputPath $outputPath -MaxAttempts 3 -ThrowOnFailure -NoRetryWhen { param($ErrorRecord) $ErrorRecord.CategoryInfo.Category -eq 'ObjectNotFound' } -ScriptBlock {
                $state.Calls++
                Write-Error -Message 'Objekt nicht gefunden' -Category ObjectNotFound -ErrorAction Stop
            }
        }
        catch { $thrown = $_ }

        $state.Calls | Should -Be 1
        $thrown.Exception.Message | Should -BeExactly 'Objekt nicht gefunden'
        $thrown.CategoryInfo.Category | Should -Be 'ObjectNotFound'
        Should -Invoke Start-Sleep -ModuleName RiskScoring -Times 0 -Exactly
        Join-Path $outputPath 'errors.log' | Should -Not -Exist
    }

    It 'still retries an error that does not match NoRetryPattern' {
        $null = Invoke-M365CallWithRetry -OperationName 'lookup' -OutputPath $outputPath -MaxAttempts 3 -NoRetryPattern 'not here' -ScriptBlock {
            $state.Calls++
            throw 'a different failure'
        }

        $state.Calls | Should -Be 3
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

Describe 'Test-M365NoMailboxError' {
    It 'recognizes an account with no mailbox: <Name>' -ForEach @(
        @{ Name = 'Exchange says the object could not be found'; Source = 'Mailbox'; Text = "The operation couldn't be performed because object 'alex@contoso.com' couldn't be found on 'DM1PR01'." }
        @{ Name = 'Exchange, other wording'; Source = 'Mailbox'; Text = "The object 'alex@contoso.com' could not be found." }
        @{ Name = 'Graph, mailbox not enabled for REST'; Source = 'InboxRules'; Text = '{"error":{"code":"MailboxNotEnabledForRESTAPI","message":"The mailbox is either inactive, soft-deleted, or is hosted on-premise."}}' }
        @{ Name = 'Graph, item not found'; Source = 'InboxRules'; Text = '{"error":{"code":"ErrorItemNotFound","message":"The specified object was not found in the store."}}' }
    ) {
        $record = try { throw $Text } catch { $_ }

        Test-M365NoMailboxError -ErrorRecord $record -Source $Source | Should -BeTrue
    }

    It 'recognizes the Exchange not-found when the message is in another language, by its <Name>' -ForEach @(
        @{ Name = 'category, ObjectNotFound'; Kind = 'Category' }
        @{ Name = 'exception type, ManagementObjectNotFoundException'; Kind = 'Type' }
        @{ Name = 'type name inside the message, as Exchange Online writes it'; Kind = 'Text' }
    ) {
        $record = switch ($Kind) {
            'Category' {
                [System.Management.Automation.ErrorRecord]::new([System.Exception]::new("Der Vorgang konnte nicht ausgefuehrt werden, da das Objekt 'alex@contoso.com' auf 'DM1PR01' nicht gefunden wurde."),
                    'NotFound', [System.Management.Automation.ErrorCategory]::ObjectNotFound, 'alex@contoso.com')
            }
            'Type' {
                [System.Management.Automation.ErrorRecord]::new((New-Object -TypeName 'Microsoft.Exchange.Configuration.Tasks.ManagementObjectNotFoundException' -ArgumentList "Objet 'alex@contoso.com' introuvable."),
                    'NotFound', [System.Management.Automation.ErrorCategory]::NotSpecified, 'alex@contoso.com')
            }
            'Text' {
                try { throw "Ex6F9304|Microsoft.Exchange.Configuration.Tasks.ManagementObjectNotFoundException|Der Vorgang konnte nicht ausgefuehrt werden." } catch { $_ }
            }
        }

        Test-M365NoMailboxError -ErrorRecord $record -Source Mailbox | Should -BeTrue
    }

    It 'does not take a missing Get-Mailbox command for a missing mailbox, although both are ObjectNotFound' {
        $record = try { Get-NoSuchCommandForTheMonitorTest -ErrorAction Stop } catch { $_ }

        $record.CategoryInfo.Category | Should -Be 'ObjectNotFound'
        Test-M365NoMailboxError -ErrorRecord $record -Source Mailbox | Should -BeFalse
    }

    It 'goes by the Graph error codes only for inbox rules, not by the category' {
        $record = [System.Management.Automation.ErrorRecord]::new([System.Exception]::new('Nicht gefunden'), 'NotFound', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $null)

        Test-M365NoMailboxError -ErrorRecord $record -Source InboxRules | Should -BeFalse
    }

    It 'reads the code from the error details as well as the message' {
        $record = try { throw 'Response status code does not indicate success: 404' } catch { $_ }
        $record.ErrorDetails = [System.Management.Automation.ErrorDetails]::new('{"error":{"code":"ErrorItemNotFound"}}')

        Test-M365NoMailboxError -ErrorRecord $record -Source InboxRules | Should -BeTrue
    }

    It 'does not call anything else a missing mailbox: <Name>' -ForEach @(
        @{ Name = 'a throttle'; Source = 'Mailbox'; Text = 'Too many requests' }
        @{ Name = 'a timeout'; Source = 'InboxRules'; Text = 'The operation has timed out' }
        @{ Name = 'a Graph code on the Exchange call'; Source = 'Mailbox'; Text = '{"error":{"code":"ErrorItemNotFound"}}' }
        @{ Name = 'an Exchange message on the Graph call'; Source = 'InboxRules'; Text = "object 'a' couldn't be found" }
        @{ Name = 'access denied'; Source = 'InboxRules'; Text = '{"error":{"code":"ErrorAccessDenied"}}' }
    ) {
        $record = try { throw $Text } catch { $_ }

        Test-M365NoMailboxError -ErrorRecord $record -Source $Source | Should -BeFalse
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

    It 'counts a recipient whose domain only looks internal as external' {
        $original = $global:TraceStub.Rows
        try {
            $lookalike = Get-TraceRowAt -SenderAddress 'sender@contoso.com' -UtcText '2026-06-15 13:00:00'
            $lookalike.RecipientAddress = "someone@con`u{00AD}toso.com"
            $global:TraceStub.Rows = @($lookalike)

            $counts = @(Get-M365OutboundMetadataCounts -Settings (Get-HoursSetting) -OutputPath (Join-Path $TestDrive 'hours-lookalike'))

            $counts.Count | Should -Be 1
            $counts[0].ExternalSentCount | Should -Be 1
        }
        finally {
            $global:TraceStub.Rows = $original
        }
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

    It 'accepts an Origin with no port only when the server is on port 80: <Name>' -ForEach @(
        @{ Name = 'port 80, no port in the origin'; Port = 80; Origin = 'http://localhost'; Expected = $true }
        @{ Name = 'port 80, the port written out'; Port = 80; Origin = 'http://localhost:80'; Expected = $true }
        @{ Name = 'port 80, another port'; Port = 80; Origin = 'http://localhost:81'; Expected = $false }
        @{ Name = 'port 80, https'; Port = 80; Origin = 'https://localhost'; Expected = $false }
        @{ Name = 'port 8181, no port in the origin'; Port = 8181; Origin = 'http://localhost'; Expected = $false }
    ) {
        (Test-UiScanRequest -Origin $Origin -ContentType 'application/json' -Port $Port).Allowed | Should -Be $Expected
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
        $projectRoot = Join-Path $TestDrive 'ui project [prod]'
        New-Item -ItemType Directory -Path $projectRoot -Force | Out-Null

        $probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $probe.Start()
        $uiPort = $probe.LocalEndpoint.Port
        $probe.Stop()

        $uiLog = Join-Path $TestDrive 'ui-output.log'
        # Each argument is quoted so that a path with a space or a bracket reaches the script intact.
        $uiArguments = '-NoProfile -File "{0}" -ProjectRoot "{1}" -Port {2}' -f $uiScript, $projectRoot, $uiPort
        $uiProcess = Start-Process -FilePath (Get-Process -Id $PID).Path -PassThru -RedirectStandardOutput $uiLog -RedirectStandardError (Join-Path $TestDrive 'ui-error.log') `
            -ArgumentList $uiArguments

        $uiReady = $false
        $uiDeadline = [datetime]::UtcNow.AddSeconds(30)
        while (-not $uiReady -and [datetime]::UtcNow -lt $uiDeadline) {
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
            param([object]$Summary, [object[]]$Findings = @())
            $folder = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            $path = New-M365ForwardingDashboard -Summary $Summary -ForwardingFindings $Findings -OutboundCounts @() -OutputPath $folder
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

    It 'puts a warning with the counts and names at the top when collection failed' {
        $html = Get-DashboardText -Summary (Get-DashboardSummary -MailboxFailed @('a@contoso.com', 'b@contoso.com') -RuleFailed @('c@contoso.com'))

        $html | Should -BeLike '*Incomplete scan*'
        $html | Should -BeLike '*Mailbox forwarding could not be read for 2 users: a@contoso.com, b@contoso.com*'
        $html | Should -BeLike '*Inbox rules could not be read for 1 user: c@contoso.com*'
        $html.IndexOf('Incomplete scan') | Should -BeLessThan $html.IndexOf('Total users scanned')
    }

    It 'lists every failed name: the first 25 in view and the rest inside a details element' {
        $names = @(1..31 | ForEach-Object { "user$_@contoso.com" })
        $html = Get-DashboardText -Summary (Get-DashboardSummary -MailboxFailed $names)

        $detailsStart = $html.IndexOf('<details>')
        $detailsStart | Should -BeGreaterThan 0
        $html.IndexOf('user25@contoso.com') | Should -BeLessThan $detailsStart
        $html.IndexOf('user26@contoso.com') | Should -BeGreaterThan $detailsStart
        $html.IndexOf('user31@contoso.com') | Should -BeLessThan $html.IndexOf('</details>')
        $html | Should -BeLike '*<summary>and 6 more</summary>*'
    }

    It 'adds no details element when the names fit in the first 25' {
        $html = Get-DashboardText -Summary (Get-DashboardSummary -MailboxFailed @(1..25 | ForEach-Object { "user$_@contoso.com" }))

        $html | Should -BeLike '*user25@contoso.com*'
        $html | Should -Not -BeLike '*<details>*'
    }

    It 'encodes the user names it lists, inside and outside the details element' {
        $names = @('x<script>@contoso.com') + @(1..29 | ForEach-Object { "user$_@contoso.com" }) + @('y<img>@contoso.com')
        $html = Get-DashboardText -Summary (Get-DashboardSummary -MailboxFailed $names)

        $html | Should -BeLike '*x&lt;script&gt;@contoso.com*'
        $html | Should -BeLike '*y&lt;img&gt;@contoso.com*'
        $html | Should -Not -BeLike '*<script>@contoso.com*'
        $html | Should -Not -BeLike '*<img>@contoso.com*'
    }

    It 'warns that outbound counts can be too low when the trace reached its row limit' {
        $html = Get-DashboardText -Summary (Get-DashboardSummary -Truncated $true)

        $html | Should -BeLike '*Incomplete scan*'
        $html | Should -BeLike '*message trace reached its row limit*'
    }

    It 'names the accounts without a mailbox on a line under the warning block whenever there are any' {
        $summary = Get-DashboardSummary -RuleFailed @('c@contoso.com')
        $summary | Add-Member -NotePropertyName UsersWithoutMailbox -NotePropertyValue ([pscustomobject]@{ Count = 2; UserPrincipalNames = @('kim@contoso.com', 'lee@contoso.com') })
        $html = Get-DashboardText -Summary $summary

        $html | Should -BeLike '*2 accounts have no mailbox and were not checked: kim@contoso.com, lee@contoso.com*'
        $html.IndexOf('have no mailbox') | Should -BeGreaterThan $html.IndexOf('</section>')
        $html.IndexOf('have no mailbox') | Should -BeLessThan $html.IndexOf('Total users scanned')

        $clean = Get-DashboardSummary
        $clean | Add-Member -NotePropertyName UsersWithoutMailbox -NotePropertyValue ([pscustomobject]@{ Count = 1; UserPrincipalNames = @('lee@contoso.com') })
        $cleanHtml = Get-DashboardText -Summary $clean
        $cleanHtml | Should -BeLike '*1 account has no mailbox and was not checked: lee@contoso.com*'
        $cleanHtml | Should -Not -BeLike '*Incomplete scan*'

        $none = Get-DashboardSummary
        $none | Add-Member -NotePropertyName UsersWithoutMailbox -NotePropertyValue ([pscustomobject]@{ Count = 0; UserPrincipalNames = @() })
        Get-DashboardText -Summary $none | Should -Not -BeLike '*no mailbox*'
    }

    It 'warns when the outbound baseline history could not be read' {
        $summary = Get-DashboardSummary
        $summary | Add-Member -NotePropertyName BaselineDegraded -NotePropertyValue $true
        $html = Get-DashboardText -Summary $summary

        $html | Should -BeLike '*Incomplete scan*'
        $html | Should -BeLike '*outbound baseline history could not be read*'
    }

    It 'says that forwards found by an earlier scan are kept only when the page shows such forwards, and never when the previous report could not be read' {
        $kept = [pscustomobject]@{ UserPrincipalName = 'c@contoso.com'; ForwardingType = 'InboxRuleForward'; ForwardTarget = 'c.home@webmail.example.com'
            TargetDomain = 'webmail.example.com'; IsExternal = $true; RiskLevel = 'Critical'; DetectedAt = '2026-01-05T09:00:00.0000000Z'; NotRechecked = $true; KeptBecause = 'Failed' }

        Get-DashboardText -Summary (Get-DashboardSummary -RuleFailed @('c@contoso.com')) -Findings @($kept) | Should -BeLike '*earlier scan*marked not re-checked*'
        Get-DashboardText -Summary (Get-DashboardSummary -RuleFailed @('c@contoso.com')) | Should -Not -BeLike '*earlier scan*'
        Get-DashboardText -Summary (Get-DashboardSummary -Truncated $true) | Should -Not -BeLike '*not re-checked*'

        $unreadable = Get-DashboardSummary -RuleFailed @('c@contoso.com')
        $unreadable | Add-Member -NotePropertyName PreviousReportUnreadable -NotePropertyValue $true
        $html = Get-DashboardText -Summary $unreadable -Findings @($kept)
        $html | Should -BeLike '*previous forwarding-findings.json could not be read*'
        $html | Should -Not -BeLike '*still listed*'
    }

    It 'marks a finding kept from an earlier scan as not re-checked in the risky users table, and no other finding' {
        $findings = @(
            [pscustomobject]@{ UserPrincipalName = 'alice.ng@contoso.com'; ForwardingType = 'MailboxForwarding'; ForwardTarget = 'alice.home@webmail.example.com'
                TargetDomain = 'webmail.example.com'; IsExternal = $true; RiskLevel = 'Critical'; DetectedAt = '2026-01-05T09:00:00.0000000Z'; NotRechecked = $true }
            [pscustomobject]@{ UserPrincipalName = 'bob.diaz@contoso.com'; ForwardingType = 'InboxRuleForward'; ForwardTarget = 'invoices@vendor.example.com'
                TargetDomain = 'vendor.example.com'; IsExternal = $true; RiskLevel = 'High'; DetectedAt = '2026-01-06T09:00:00.0000000Z'; NotRechecked = $false }
            # A finding without the property, as an older version wrote them.
            [pscustomobject]@{ UserPrincipalName = 'carol.otieno@contoso.com'; ForwardingType = 'MailboxForwarding'; ForwardTarget = 'records@partner.example.com'
                TargetDomain = 'partner.example.com'; IsExternal = $true; RiskLevel = 'High'; DetectedAt = '2026-01-06T09:00:00.0000000Z' }
        )
        $path = New-M365ForwardingDashboard -Summary (Get-DashboardSummary -MailboxFailed @('alice.ng@contoso.com')) -ForwardingFindings $findings `
            -OutboundCounts @() -OutputPath (Join-Path $TestDrive 'risky-table')
        $rows = @([regex]::Matches((Get-Content -LiteralPath $path -Raw), '<tr><td>[^<]+@contoso\.com</td>.*?</tr>') | ForEach-Object Value)

        $rows.Count | Should -Be 3
        @($rows | Where-Object { $_ -like '*alice.ng@contoso.com*' }) | Should -BeLike '*not re-checked*'
        @($rows | Where-Object { $_ -like '*not re-checked*' }).Count | Should -Be 1

        # The external domains table counts the kept finding too, so it says so there as well.
        $domainRows = @([regex]::Matches((Get-Content -LiteralPath $path -Raw), '<tr><td>[a-z.]+\.example\.com</td>.*?</tr>') | ForEach-Object Value)
        $domainRows.Count | Should -Be 3
        @($domainRows | Where-Object { $_ -like '*webmail.example.com*' }) | Should -BeLike '*1 not re-checked*'
        @($domainRows | Where-Object { $_ -like '*not re-checked*' }).Count | Should -Be 1
    }
}

Describe 'Connect-M365Monitor' {
    BeforeAll {
        . (Join-Path (Join-Path $PSScriptRoot '..') 'src/Connect-M365.ps1')

        # Stand-ins for the sign-in commands. Each records the parameters it was given.
        function global:Connect-MgGraph {
            [CmdletBinding()]
            param($TenantId, $ClientId, $Certificate, $Scopes, [switch]$UseDeviceCode, [switch]$NoWelcome)
            $global:ConnectCalls.Add(@{ Command = 'Connect-MgGraph'; Parameters = @{} + $PSBoundParameters })
        }
        function global:Get-MgContext {
            [CmdletBinding()]
            param()
            return [pscustomobject]@{ TenantId = '00000000-0000-0000-0000-000000000000' }
        }
        function global:Connect-ExchangeOnline {
            [CmdletBinding()]
            param($Certificate, $AppId, $Organization, [switch]$Device, [switch]$ShowBanner)
            $global:ConnectCalls.Add(@{ Command = 'Connect-ExchangeOnline'; Parameters = @{} + $PSBoundParameters })
        }
    }

    AfterAll {
        Remove-Item -Path Function:\global:Connect-MgGraph, Function:\global:Get-MgContext, Function:\global:Connect-ExchangeOnline -ErrorAction SilentlyContinue
        Remove-Variable -Name ConnectCalls -Scope Global -ErrorAction SilentlyContinue
    }

    BeforeEach {
        Mock Import-Module {} -ParameterFilter { @($Name)[0] -in @('Microsoft.Graph.Authentication', 'ExchangeOnlineManagement') }
        $global:ConnectCalls = [System.Collections.Generic.List[object]]::new()
    }

    It 'signs in to Exchange Online in the ExchangeOrganization tenant with <Mode> sign-in, so it cannot land in a different tenant than Graph' -ForEach @(
        @{ Mode = 'device-code'; Device = $true }
        @{ Mode = 'interactive'; Device = $false }
    ) {
        $settings = [pscustomobject]@{ TenantId = '00000000-0000-0000-0000-000000000000'; ExchangeOrganization = 'contoso.onmicrosoft.com' }

        Connect-M365Monitor -Settings $settings -OutputPath (Join-Path $TestDrive 'connect') -UseDeviceAuthentication:$Device 6>$null

        $exchange = @($global:ConnectCalls | Where-Object { $_.Command -eq 'Connect-ExchangeOnline' })
        $exchange.Count | Should -Be 1
        $exchange[0].Parameters['Organization'] | Should -BeExactly 'contoso.onmicrosoft.com'
        $exchange[0].Parameters.ContainsKey('Device') | Should -Be $Device
    }

    It 'leaves Organization out when ExchangeOrganization is not set' {
        $settings = [pscustomobject]@{ TenantId = '00000000-0000-0000-0000-000000000000'; ExchangeOrganization = '' }

        Connect-M365Monitor -Settings $settings -OutputPath (Join-Path $TestDrive 'connect') -UseDeviceAuthentication 6>$null

        $exchange = @($global:ConnectCalls | Where-Object { $_.Command -eq 'Connect-ExchangeOnline' })
        $exchange[0].Parameters.ContainsKey('Organization') | Should -BeFalse
    }
}

Describe 'Write-M365TextFile' {
    It 'writes the text as UTF-8 without a byte order mark and replaces what was there' {
        $path = Join-Path $TestDrive 'durable.txt'
        [System.IO.File]::WriteAllText($path, 'an older and longer content')

        Write-M365TextFile -Path $path -Text "caf$([char]0xE9)`n"

        [System.IO.File]::ReadAllBytes($path) | Should -Be ([byte[]](0x63, 0x61, 0x66, 0xC3, 0xA9, 0x0A))
    }

}

Describe 'Reading the outbound baseline history' {
    BeforeAll {
        $monitorScript = Join-Path (Join-Path $PSScriptRoot '..') 'src/Invoke-ForwardingMonitor.ps1'
        foreach ($functionName in 'Read-M365JsonFile', 'Test-M365IsoTimestamp', 'Read-M365HistoryFile', 'Add-M365Property', 'Update-M365OutboundBaseline') {
            . ([scriptblock]::Create((Get-FunctionTextFromFile -Path $monitorScript -Name $functionName)))
        }

        function Invoke-TestBaseline {
            param([string]$HistoryText, [object]$RetentionDays = 90)
            $folder = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $folder | Out-Null
            [System.IO.File]::WriteAllText((Join-Path $folder 'outbound-baseline-history.json'), $HistoryText)
            $settings = [pscustomobject]@{ BaselineRetentionDays = $RetentionDays; OutboundWarningThreshold = 100; OutboundCriticalThreshold = 250 }
            $row = [pscustomobject]@{
                Date = (Get-Date).ToString('yyyy-MM-dd'); SenderAddress = 'a@contoso.com'; ExternalSentCount = 3; UniqueExternalRecipientCount = 1
                TopExternalDomains = @('vendor.example.com:3'); AfterHoursCount = 0; DetectedAt = (Get-Date).ToString('o')
            }
            $result = Update-M365OutboundBaseline -OutboundCounts @($row) -Settings $settings -OutputPath $folder 3>$null
            return [pscustomobject]@{ Result = $result; Row = $row; Folder = $folder }
        }

        $recent = (Get-Date).AddDays(-1).ToString('o')
    }

    It 'treats a history whose DetectedAt is <Case> as unreadable, although [datetime] would take it' -ForEach @(
        @{ Case = 'a number of ticks'; Value = '638000000000000000' }
        @{ Case = 'zero'; Value = '0' }
        @{ Case = 'text that is not ISO 8601'; Value = '"10/11/2026 12:00"' }
    ) {
        $text = "[{`"SenderAddress`":`"a@contoso.com`",`"ExternalSentCount`":5,`"DetectedAt`":`"$recent`"},{`"SenderAddress`":`"a@contoso.com`",`"ExternalSentCount`":7,`"DetectedAt`":$Value}]"
        $run = Invoke-TestBaseline -HistoryText $text

        $run.Result.HistoryUnreadable | Should -BeTrue
        Get-Content -LiteralPath (Join-Path $run.Folder 'errors.log') -Raw | Should -BeLike '*Could not read outbound baseline history*'
    }

    It 'treats a history whose DetectedAt is <Case> as unreadable' -ForEach @(
        @{ Case = 'true'; Value = 'true' }
        @{ Case = 'empty text'; Value = '""' }
        @{ Case = 'null'; Value = 'null' }
    ) {
        $run = Invoke-TestBaseline -HistoryText "[{`"SenderAddress`":`"a@contoso.com`",`"ExternalSentCount`":5,`"DetectedAt`":$Value}]"

        $run.Result.HistoryUnreadable | Should -BeTrue
    }

    It 'treats a history with a record that has no DetectedAt as unreadable' {
        $run = Invoke-TestBaseline -HistoryText "[{`"SenderAddress`":`"a@contoso.com`",`"ExternalSentCount`":5,`"DetectedAt`":`"$recent`"},{`"SenderAddress`":`"a@contoso.com`",`"ExternalSentCount`":7}]"

        $run.Result.HistoryUnreadable | Should -BeTrue
    }

    It 'reads a history whose DetectedAt is <Case>' -ForEach @(
        @{ Case = 'ISO 8601 in UTC'; Json = '[{"SenderAddress":"a@contoso.com","ExternalSentCount":5,"DetectedAt":"<UTC>"}]' }
        @{ Case = 'ISO 8601 with an offset'; Json = '[{"SenderAddress":"a@contoso.com","ExternalSentCount":5,"DetectedAt":"<LOCAL>"}]' }
        @{ Case = 'in a single bare object, as an older version wrote one record'; Json = '{"SenderAddress":"a@contoso.com","ExternalSentCount":5,"DetectedAt":"<LOCAL>"}' }
    ) {
        $text = $Json.Replace('<UTC>', [datetime]::UtcNow.AddDays(-1).ToString('o')).Replace('<LOCAL>', $recent)
        $run = Invoke-TestBaseline -HistoryText $text

        $run.Result.HistoryUnreadable | Should -BeFalse
        $run.Row.BaselineSampleCount | Should -Be 1
    }

    It 'uses the default of 90 days, with a warning, when BaselineRetentionDays is <Days>' -ForEach @(
        @{ Days = 0 }
        @{ Days = -5 }
    ) {
        $old = (Get-Date).AddDays(-30).ToString('o')
        $run = Invoke-TestBaseline -RetentionDays $Days -HistoryText "[{`"SenderAddress`":`"a@contoso.com`",`"ExternalSentCount`":5,`"DetectedAt`":`"$old`"}]"

        @($run.Result.Records).Count | Should -Be 2
        $run.Row.BaselineSampleCount | Should -Be 1
        Get-Content -LiteralPath (Join-Path $run.Folder 'errors.log') -Raw | Should -BeLike "*BaselineRetentionDays is $Days*default of 90*"
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

    It 'write the report files with Write-M365TextFile, which flushes them to the disk, and never with <Command>' -ForEach @(
        @{ Command = 'Set-Content' }
        @{ Command = 'Export-Csv' }
        @{ Command = 'Out-File' }
        @{ Command = 'Add-Content' }
    ) {
        foreach ($file in 'Invoke-ForwardingMonitor.ps1', 'New-Dashboard.ps1') {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path (Join-Path (Join-Path $PSScriptRoot '..') 'src') $file), [ref]$null, [ref]$null)
            $uses = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq $Command }, $true))
            $uses.Count | Should -Be 0 -Because "$file should write through Write-M365TextFile"
        }
    }
}

Describe 'Invoke-ForwardingMonitor.ps1 run against stubbed Microsoft calls' {
    BeforeAll {
        $monitorScript = Join-Path (Join-Path $PSScriptRoot '..') 'src/Invoke-ForwardingMonitor.ps1'
        $expectedFindingColumns = @(
            'UserPrincipalName', 'DisplayName', 'ForwardingType', 'ForwardTarget', 'TargetDomain', 'IsExternal',
            'IsPersonalDomain', 'ApprovedException', 'RiskLevel', 'DetectedAt',
            'DeliverToMailboxAndForward', 'RuleName', 'RuleId', 'RuleEnabled', 'NotRechecked', 'KeptBecause'
        )

        # The stubs stand in for Invoke-MgGraphRequest, Get-Mailbox and Get-MessageTraceV2.
        # They read whatever the current scenario put in $global:OfflineRun.
        function global:Invoke-MgGraphRequest {
            [CmdletBinding()]
            param($Method, $Uri)
            $global:OfflineRun.GraphCalls = 1 + [int]$global:OfflineRun.GraphCalls
            # A # in a URL starts a fragment, so Graph never sees the rest of the path, as with an unencoded #EXT#.
            if ($Uri.Contains('#')) {
                throw "Resource not found for the segment '$(($Uri.Split('#')[0] -split '/')[-1])'."
            }
            if ($Uri -match '/users/(?<id>[^/]+)/mailFolders/inbox/messageRules$') {
                # Inbox rules are read by object id. The stub turns the id back into the user name the scenario uses.
                $key = [System.Uri]::UnescapeDataString($Matches['id'])
                $global:OfflineRun.RuleUris = @($global:OfflineRun.RuleUris | Where-Object { $_ }) + $Uri
                $ruleUser = @($global:OfflineRun.Users | Where-Object { $_.id -eq $key })[0]
                $ruleUpn = if ($ruleUser) { $ruleUser.userPrincipalName } else { $key }
                $global:OfflineRun.RuleCalls = @($global:OfflineRun.RuleCalls | Where-Object { $_ }) + $ruleUpn
                if ($global:OfflineRun.RulesNoMailbox -contains $ruleUpn) {
                    throw '{"error":{"code":"MailboxNotEnabledForRESTAPI","message":"The mailbox is either inactive, soft-deleted, or is hosted on-premise."}}'
                }
                if ($global:OfflineRun.RulesItemNotFound -contains $ruleUpn) {
                    throw '{"error":{"code":"ErrorItemNotFound","message":"The specified object was not found in the store."}}'
                }
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
            $global:OfflineRun.MailboxCalls = @($global:OfflineRun.MailboxCalls | Where-Object { $_ }) + $Identity
            if ($global:OfflineRun.AllNotFound -or $global:OfflineRun.NoMailbox -contains $Identity) {
                throw "The operation couldn't be performed because object '$Identity' couldn't be found on 'DM1PR01'."
            }
            if ($global:OfflineRun.NoMailboxLocalized -contains $Identity) {
                # A message in another language: only the category says what kind of error it is.
                $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new(
                        [System.Exception]::new("Der Vorgang konnte nicht ausgefuehrt werden, da das Objekt '$Identity' nicht gefunden wurde."),
                        'NotFound', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $Identity))
            }
            if ($global:OfflineRun.NoMailboxTyped -contains $Identity) {
                # Only the exception type says what kind of error it is.
                $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new(
                        (New-Object -TypeName 'Microsoft.Exchange.Configuration.Tasks.ManagementObjectNotFoundException' -ArgumentList "Objet '$Identity' introuvable."),
                        'NotFound', [System.Management.Automation.ErrorCategory]::NotSpecified, $Identity))
            }
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

        function Get-OfflineUser {
            param([string]$Name, [string]$DisplayName)
            # A made-up object id per name, so the inbox rule stub can tell users apart by id as Graph does.
            $hash = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($Name))
            return @{
                id                = '00000000-0000-0000-0000-{0}' -f (-join ($hash[0..5] | ForEach-Object { $_.ToString('x2') }))
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
            param([string]$Name, [hashtable]$Scenario, [string]$ExceptionTarget, [scriptblock]$Seed, [string]$ExceptionExpiration, [hashtable]$SettingsOverride = @{}, [switch]$CaptureVerbose)

            $global:OfflineRun = $Scenario
            $runRoot = Join-Path $TestDrive $Name
            $outputDir = Join-Path $runRoot 'output'
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
            if ($Seed) { & $Seed $outputDir }

            $settingsValues = [ordered]@{
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
            }
            foreach ($key in $SettingsOverride.Keys) { $settingsValues[$key] = $SettingsOverride[$key] }
            $settingsValues | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runRoot 'settings.json')

            [pscustomobject]@{
                UserPrincipalName = 'alex.wilber@contoso.com'
                ApprovedTarget    = $ExceptionTarget
                Reason            = 'Synthetic test row'
                ApprovedBy        = 'security.manager@contoso.com'
                ExpirationDate    = if ($ExceptionExpiration) { $ExceptionExpiration } else { (Get-Date).AddDays(30).ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture) }
            } | Export-Csv -LiteralPath (Join-Path $runRoot 'exceptions.csv') -NoTypeInformation

            $global:LASTEXITCODE = 0
            $arguments = @{
                SettingsPath           = Join-Path $runRoot 'settings.json'
                ApprovedExceptionsPath = Join-Path $runRoot 'exceptions.csv'
                SkipConnect            = $true
            }
            if ($CaptureVerbose) {
                # The script says "Put <file> in place." on the verbose stream as it replaces each output file.
                $Scenario.Published = @(& $monitorScript @arguments -Verbose 4>&1 6>$null 3>$null | ForEach-Object {
                        if ($_ -is [System.Management.Automation.VerboseRecord] -and $_.Message -match '^Put (?<leaf>.+) in place\.$') { $Matches['leaf'] }
                    })
            }
            else {
                & $monitorScript @arguments 6>$null 3>$null
            }
            $Scenario.ExitCode = $LASTEXITCODE
            return $outputDir
        }

        function Get-OutputSnapshot {
            param([string]$Directory)
            # The scan lock is left out: a scan writes it whenever it holds it, and a held lock cannot be read.
            $snapshot = [ordered]@{}
            foreach ($file in Get-ChildItem -LiteralPath $Directory -File -Force | Where-Object { $_.Name -notin 'errors.log', '.scan.lock' } | Sort-Object Name) {
                $snapshot[$file.Name] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
            }
            return ($snapshot | ConvertTo-Json -Compress)
        }

        function Test-ScanLockHeld {
            param([string]$Directory)
            # True while some process holds the scan lock: opening it with no sharing fails then.
            $path = Join-Path $Directory '.scan.lock'
            if (-not [System.IO.File]::Exists($path)) { return $false }
            try {
                ([System.IO.FileStream]::new($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)).Dispose()
                return $false
            }
            catch {
                return $true
            }
        }
    }

    AfterAll {
        Remove-Item -Path Function:\global:Invoke-MgGraphRequest, Function:\global:Get-Mailbox, Function:\global:Get-MessageTraceV2, Function:\global:Start-Sleep -ErrorAction SilentlyContinue
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
            $outputDir = Invoke-OfflineMonitorRun -Name 'mailbox' -Scenario $scenario -ExceptionTarget 'records@partner.example.com' -CaptureVerbose
            $moved = @($scenario.Published)
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

            $scenario.ExitCode | Should -Be 0
            $summary.UsersWithoutMailbox.Count | Should -Be 0
            $summary.TraceTruncated | Should -BeFalse
            $summary.BaselineDegraded | Should -BeFalse
            $summary.CollectionFailures.MailboxForwarding.Count | Should -Be 0
            $summary.CollectionFailures.InboxRules.Count | Should -Be 0
            @($summary.CollectionFailures.MailboxForwarding.UserPrincipalNames).Count | Should -Be 0
            $scenario.LastResultSize | Should -Be 5000
            @(Get-ChildItem -LiteralPath $outputDir -Force | Where-Object Name -match '\.(tmp|prev)$').Count | Should -Be 0
            Test-ScanLockHeld -Directory $outputDir | Should -BeFalse
            Get-Content -Path (Join-Path $outputDir 'dashboard.html') -Raw | Should -Not -BeLike '*Incomplete scan*'
        }

        It 'marks every finding as checked in this run' {
            $findings = @(Get-Content -Path (Join-Path $outputDir 'forwarding-findings.json') -Raw | ConvertFrom-Json)

            @($findings | Where-Object { $_.NotRechecked -ne $false }).Count | Should -Be 0
            @(Import-Csv -Path (Join-Path $outputDir 'forwarding-findings.csv') | Select-Object -ExpandProperty NotRechecked -Unique) | Should -Be @('False')
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

        It 'exits with code 2 and retried each failing user three times before counting it' {
            $scenario.ExitCode | Should -Be 2
            @($scenario.MailboxCalls | Where-Object { $_ -eq 'sam.okafor@contoso.com' }).Count | Should -Be 3
            @($scenario.RuleCalls | Where-Object { $_ -eq 'priya.nair@contoso.com' }).Count | Should -Be 3
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

    Context 'with accounts that have no mailbox, as both collectors agree' {
        BeforeAll {
            # Both calls say "no mailbox" for sam, priya, kim and lee. For kim the Exchange message is in German and
            # only its category says what it is; for lee only the exception type does.
            $scenario = @{
                Users              = @(
                    (Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber')
                    (Get-OfflineUser -Name 'sam.okafor' -DisplayName 'Sam Okafor')
                    (Get-OfflineUser -Name 'priya.nair' -DisplayName 'Priya Nair')
                    (Get-OfflineUser -Name 'chris.lindqvist' -DisplayName 'Chris Lindqvist')
                    (Get-OfflineUser -Name 'kim.tanaka' -DisplayName 'Kim Tanaka')
                    (Get-OfflineUser -Name 'lee.moreau' -DisplayName 'Lee Moreau')
                )
                Mailboxes          = @{ 'alex.wilber@contoso.com' = 'smtp:records@partner.example.com' }
                Rules              = @{ 'chris.lindqvist@contoso.com' = @((Get-OfflineRule -Name 'Copy invoices' -Target 'invoices@vendor.example.com')) }
                Traces             = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com'))
                NoMailbox          = @('sam.okafor@contoso.com', 'priya.nair@contoso.com')
                NoMailboxLocalized = @('kim.tanaka@contoso.com')
                NoMailboxTyped     = @('lee.moreau@contoso.com')
                RulesNoMailbox     = @('sam.okafor@contoso.com', 'kim.tanaka@contoso.com', 'lee.moreau@contoso.com')
                RulesItemNotFound  = @('priya.nair@contoso.com')
            }
            $outputDir = Invoke-OfflineMonitorRun -Name 'no-mailbox' -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com'
        }

        It 'is not a failure: the run exits 0 and records no collection failures' {
            $summary = Get-Content -Path (Join-Path $outputDir 'summary.json') -Raw | ConvertFrom-Json

            $scenario.ExitCode | Should -Be 0
            $summary.CollectionFailures.MailboxForwarding.Count | Should -Be 0
            $summary.CollectionFailures.InboxRules.Count | Should -Be 0
            Get-Content -Path (Join-Path $outputDir 'dashboard.html') -Raw | Should -Not -BeLike '*Incomplete scan*'
        }

        It 'lists each such account once under UsersWithoutMailbox, in summary.json and as a count in summary.csv' {
            $summary = Get-Content -Path (Join-Path $outputDir 'summary.json') -Raw | ConvertFrom-Json

            $summary.UsersWithoutMailbox.Count | Should -Be 4
            @($summary.UsersWithoutMailbox.UserPrincipalNames | Sort-Object) | Should -Be @('kim.tanaka@contoso.com', 'lee.moreau@contoso.com', 'priya.nair@contoso.com', 'sam.okafor@contoso.com')
            @(Import-Csv -Path (Join-Path $outputDir 'summary.csv'))[0].UsersWithoutMailbox | Should -BeExactly '4'
        }

        It 'names them on the dashboard, where the warning block would go' {
            $html = Get-Content -Path (Join-Path $outputDir 'dashboard.html') -Raw

            $html | Should -BeLike '*4 accounts have no mailbox and were not checked:*kim.tanaka@contoso.com*'
            $html.IndexOf('have no mailbox') | Should -BeLessThan $html.IndexOf('Total users scanned')
        }

        It 'does not retry a missing mailbox, whatever language the message is in' {
            foreach ($upn in 'sam.okafor@contoso.com', 'kim.tanaka@contoso.com', 'lee.moreau@contoso.com') {
                @($scenario.MailboxCalls | Where-Object { $_ -eq $upn }).Count | Should -Be 1 -Because "$upn has no mailbox"
            }
            @($scenario.RuleCalls | Where-Object { $_ -eq 'sam.okafor@contoso.com' }).Count | Should -Be 1
            @($scenario.RuleCalls | Where-Object { $_ -eq 'priya.nair@contoso.com' }).Count | Should -Be 1
        }

        It 'still reports what it could read for the other users' {
            $findings = @(Get-Content -Path (Join-Path $outputDir 'forwarding-findings.json') -Raw | ConvertFrom-Json)

            $findings.Count | Should -Be 2
        }
    }

    Context 'when the business time zone is not a known id' {
        BeforeAll {
            $scenario = @{
                Users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber')); Mailboxes = @{}; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com'))
            }
            $thrown = $null
            try { $null = Invoke-OfflineMonitorRun -Name 'bad-zone' -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com' -SettingsOverride @{ BusinessHoursTimeZone = 'Nowhere/Land' } }
            catch { $thrown = $_ }
            $runRoot = Join-Path $TestDrive 'bad-zone'
        }

        It 'stops before it asks Microsoft for anything' {
            $thrown | Should -Not -BeNullOrEmpty
            $thrown.Exception.Message | Should -BeLike "*BusinessHoursTimeZone 'Nowhere/Land'*"
            [int]$scenario.GraphCalls | Should -Be 0
            @($scenario.MailboxCalls | Where-Object { $_ }).Count | Should -Be 0
        }

        It 'records the stop in errors.log and writes no report file' {
            Get-Content -Path (Join-Path $runRoot 'output/errors.log') -Raw | Should -BeLike "*BusinessHoursTimeZone 'Nowhere/Land'*"
            @(Get-ChildItem -LiteralPath (Join-Path $runRoot 'output') -File -Force | Where-Object { $_.Name -notin 'errors.log', '.scan.lock' }).Count | Should -Be 0
        }
    }

    Context 'when an approved exception has an expiry date the tool cannot read' {
        BeforeAll {
            $scenario = @{
                Users     = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber'))
                Mailboxes = @{ 'alex.wilber@contoso.com' = 'smtp:records@partner.example.com' }
                Rules     = @{ 'alex.wilber@contoso.com' = @((Get-OfflineRule -Name 'Copy to partner' -Target 'records@partner.example.com')) }
                Traces    = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com'))
            }
            $outputDir = Invoke-OfflineMonitorRun -Name 'bad-expiry' -Scenario $scenario -ExceptionTarget 'records@partner.example.com' -ExceptionExpiration '31.12.2099'
        }

        It 'does not approve the forward, so it is reported at its real level' {
            $findings = @(Get-Content -Path (Join-Path $outputDir 'forwarding-findings.json') -Raw | ConvertFrom-Json)

            $findings.Count | Should -Be 2
            @($findings | Where-Object ApprovedException).Count | Should -Be 0
            @($findings | Select-Object -ExpandProperty RiskLevel -Unique) | Should -Be @('High')
        }

        It 'logs the skipped row once for the run, with the user and the raw value, however many findings it would have covered' {
            $lines = @(Get-Content -Path (Join-Path $outputDir 'errors.log') | Where-Object { $_ -like "*ExpirationDate '31.12.2099'*" })

            $lines.Count | Should -Be 1
            $lines[0] | Should -BeLike '*alex.wilber@contoso.com*'
            $lines[0] | Should -BeLike '*yyyy-MM-dd*'
        }
    }

    Context 'when the output folder name contains brackets' {
        BeforeAll {
            $scenario = @{
                Users     = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber'))
                Mailboxes = @{ 'alex.wilber@contoso.com' = 'smtp:records@partner.example.com' }
                Rules     = @{}
                Traces    = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com'))
            }
            $outputDir = Invoke-OfflineMonitorRun -Name 'Scans [prod]' -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com' -ExceptionExpiration 'not-a-date'
            $null = Invoke-OfflineMonitorRun -Name 'Scans [prod]' -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com' -ExceptionExpiration 'not-a-date'
        }

        It 'writes every report file into the folder' {
            $outputDir | Should -BeLike '*Scans `[prod`]*'
            foreach ($file in 'summary.json', 'forwarding-findings.json', 'forwarding-findings.csv', 'outbound-metadata-counts.json',
                'outbound-metadata-counts.csv', 'summary.csv', 'outbound-baseline-history.json', 'dashboard.html') {
                [System.IO.File]::Exists((Join-Path $outputDir $file)) | Should -BeTrue -Because "$file should be in the folder"
            }
        }

        It 'finds the baseline history again on the second run instead of starting over' {
            $history = Get-Content -LiteralPath (Join-Path $outputDir 'outbound-baseline-history.json') -Raw | ConvertFrom-Json -NoEnumerate
            $log = Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') -Raw -ErrorAction SilentlyContinue

            $history.Count | Should -Be 2
            $log | Should -Not -BeLike '*Could not read outbound baseline history*'
        }

        It 'writes errors.log into the folder' {
            $lines = @(Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') | Where-Object { $_ -like "*ExpirationDate 'not-a-date'*" })

            $lines.Count | Should -Be 2
        }

        It 'documents the exit codes in the script help' {
            $help = Get-Help (Join-Path (Join-Path $PSScriptRoot '..') 'src/Invoke-ForwardingMonitor.ps1') -Full | Out-String

            $help | Should -BeLike '*0*clean*'
            $help | Should -BeLike '*1*stopped*'
            $help | Should -BeLike '*2*partial*'
            $help | Should -BeLike '*killed while it swaps files*already swapped stay in place*'
        }
    }

    Context 'when another program holds forwarding-findings.csv open while the files are put in place' {
        BeforeAll {
            $users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber'), (Get-OfflineUser -Name 'sam.okafor' -DisplayName 'Sam Okafor'))
            $first = @{ Users = $users; Mailboxes = @{ 'alex.wilber@contoso.com' = 'smtp:records@partner.example.com' }; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com')) }
            $outputDir = Invoke-OfflineMonitorRun -Name 'csv-held' -Scenario $first -ExceptionTarget 'nobody@partner.example.com'
            $before = Get-OutputSnapshot -Directory $outputDir

            # The fourth file staged is held open with no sharing, the way the reviewer locked it. On Windows the open
            # handle blocks the copy and the replace; on Linux and macOS .NET takes an exclusive lock that blocks the copy.
            $changed = @{ Users = $users; Mailboxes = @{ 'sam.okafor@contoso.com' = 'smtp:sam.home@webmail.example.com' }; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'sam.okafor@contoso.com' -Recipient 'b@vendor.example.com')) }
            $holder = [System.IO.FileStream]::new((Join-Path $outputDir 'forwarding-findings.csv'), 'Open', 'ReadWrite', 'None')
            $thrown = $null
            try { $null = Invoke-OfflineMonitorRun -Name 'csv-held' -Scenario $changed -ExceptionTarget 'nobody@partner.example.com' }
            catch { $thrown = $_ }
            finally { $holder.Dispose() }
            $after = Get-OutputSnapshot -Directory $outputDir
        }

        It 'stops the run with a message that names the file and says the earlier files were put back' {
            $thrown | Should -Not -BeNullOrEmpty
            $thrown.Exception.Message | Should -BeLike "*forwarding-findings.csv in place*The previous run's files were put back*"
        }

        It 'puts back the files it had already replaced, so the folder holds the previous run and no temporary file or backup' {
            $after | Should -BeExactly $before
        }

        It 'records the stop in errors.log' {
            Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') -Raw | Should -BeLike '*Invoke-ForwardingMonitor failed.*forwarding-findings.csv in place*'
        }
    }

    Context 'when a folder sits where outbound-metadata-counts.json goes' {
        BeforeAll {
            $users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber'))
            $good = @{ Users = $users; Mailboxes = @{ 'alex.wilber@contoso.com' = 'smtp:records@partner.example.com' }; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com')) }
            $outputDir = Invoke-OfflineMonitorRun -Name 'folder-in-the-way' -Scenario $good -ExceptionTarget 'nobody@partner.example.com'
            $countsPath = Join-Path $outputDir 'outbound-metadata-counts.json'
            Remove-Item -LiteralPath $countsPath
            New-Item -ItemType Directory -Path $countsPath | Out-Null
            $before = Get-OutputSnapshot -Directory $outputDir

            $thrown = $null
            try { $null = Invoke-OfflineMonitorRun -Name 'folder-in-the-way' -Scenario @{ Users = $users; Mailboxes = @{}; Rules = @{}; Traces = @() } -ExceptionTarget 'nobody@partner.example.com' }
            catch { $thrown = $_ }
        }

        It 'stops the run before any file changes, with a message that names the path' {
            $thrown.Exception.Message | Should -BeLike '*outbound-metadata-counts.json*not a plain file*No output files were changed*'
            Get-OutputSnapshot -Directory $outputDir | Should -BeExactly $before
            Test-Path -LiteralPath $countsPath -PathType Container | Should -BeTrue
        }
    }

    Context 'when the outbound baseline history is <Case>' -ForEach @(
        @{ Case = 'cut off after its first record'; Folder = 'history-cut' }
        @{ Case = 'empty'; Folder = 'history-empty' }
    ) {
        BeforeAll {
            $users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber'))
            $first = @{ Users = $users; Mailboxes = @{}; Rules = @{}
                Traces = @(
                    (Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com')
                    (Get-OfflineTrace -SenderAddress 'sam.okafor@contoso.com' -Recipient 'b@vendor.example.com')
                ) }
            $outputDir = Invoke-OfflineMonitorRun -Name $Folder -Scenario $first -ExceptionTarget 'nobody@partner.example.com'
            $historyPath = Join-Path $outputDir 'outbound-baseline-history.json'

            # A cut right after a complete record is the dangerous kind: ConvertFrom-Json reads it without an error
            # and returns the records before the cut, so a run that trusted it would write a shorter history back.
            $full = [System.IO.File]::ReadAllText($historyPath)
            $damaged = if ($Case -eq 'empty') { '' } else { $full.Substring(0, $full.IndexOf('},') + 2) }
            [System.IO.File]::WriteAllText($historyPath, $damaged)

            $second = @{ Users = $users; Mailboxes = @{ 'alex.wilber@contoso.com' = 'smtp:records@partner.example.com' }; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'c@vendor.example.com')) }
            $null = Invoke-OfflineMonitorRun -Name $Folder -Scenario $second -ExceptionTarget 'nobody@partner.example.com'
        }

        It 'leaves the history file exactly as it was instead of writing this run''s records over it' {
            [System.IO.File]::ReadAllText($historyPath) | Should -BeExactly $damaged
        }

        It 'writes the reason to errors.log' {
            Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') -Raw | Should -BeLike '*Could not read outbound baseline history*left as it is*'
        }

        It 'reports it: exit 2, BaselineDegraded in summary.json and summary.csv, and a line in the dashboard warning' {
            $second.ExitCode | Should -Be 2
            (Get-Content -LiteralPath (Join-Path $outputDir 'summary.json') -Raw | ConvertFrom-Json).BaselineDegraded | Should -BeTrue
            @(Import-Csv -LiteralPath (Join-Path $outputDir 'summary.csv'))[0].BaselineDegraded | Should -BeExactly 'True'
            $html = Get-Content -LiteralPath (Join-Path $outputDir 'dashboard.html') -Raw
            $html | Should -BeLike '*Incomplete scan*'
            $html | Should -BeLike '*outbound baseline history could not be read*'
        }

        It 'still writes the other reports, with no temporary file or backup' {
            (Get-Content -LiteralPath (Join-Path $outputDir 'summary.json') -Raw | ConvertFrom-Json).UsersWithMailboxForwarding | Should -Be 1
            $counts = @(Get-Content -LiteralPath (Join-Path $outputDir 'outbound-metadata-counts.json') -Raw | ConvertFrom-Json)
            $counts.Count | Should -Be 1
            $counts[0].BaselineSampleCount | Should -Be 0
            @(Get-ChildItem -LiteralPath $outputDir -Force | Where-Object Name -match '\.(tmp|prev)$').Count | Should -Be 0
        }
    }

    Context 'when another program holds the outbound baseline history open' {
        BeforeAll {
            $users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber'))
            $first = @{ Users = $users; Mailboxes = @{}; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com')) }
            $outputDir = Invoke-OfflineMonitorRun -Name 'history-held' -Scenario $first -ExceptionTarget 'nobody@partner.example.com'
            $historyPath = Join-Path $outputDir 'outbound-baseline-history.json'
            $historyBefore = (Get-FileHash -LiteralPath $historyPath -Algorithm SHA256).Hash

            $second = @{ Users = $users; Mailboxes = @{ 'alex.wilber@contoso.com' = 'smtp:records@partner.example.com' }; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'c@vendor.example.com')) }
            $holder = [System.IO.FileStream]::new($historyPath, 'Open', 'ReadWrite', 'None')
            try { $null = Invoke-OfflineMonitorRun -Name 'history-held' -Scenario $second -ExceptionTarget 'nobody@partner.example.com' }
            finally { $holder.Dispose() }
        }

        It 'leaves the history as it was, logs why, reports it with exit 2, and still writes the other reports' {
            (Get-FileHash -LiteralPath $historyPath -Algorithm SHA256).Hash | Should -BeExactly $historyBefore
            Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') -Raw | Should -BeLike '*Could not read outbound baseline history*'
            $second.ExitCode | Should -Be 2
            $summary = Get-Content -LiteralPath (Join-Path $outputDir 'summary.json') -Raw | ConvertFrom-Json
            $summary.BaselineDegraded | Should -BeTrue
            $summary.UsersWithMailboxForwarding | Should -Be 1
        }
    }

    Context 'when a user with a known forward cannot be read on a later run' {
        BeforeAll {
            $users = @(
                (Get-OfflineUser -Name 'alice.ng' -DisplayName 'Alice Ng')
                (Get-OfflineUser -Name 'bob.diaz' -DisplayName 'Bob Diaz')
                (Get-OfflineUser -Name 'carol.otieno' -DisplayName 'Carol Otieno')
            )
            $traces = @((Get-OfflineTrace -SenderAddress 'bob.diaz@contoso.com' -Recipient 'a@vendor.example.com'))
            $aliceRule = @{ 'alice.ng@contoso.com' = @((Get-OfflineRule -Name 'Copy invoices' -Target 'invoices@vendor.example.com')) }

            # Run one: alice forwards her mailbox to a personal address (Critical) and has an inbox rule that forwards
            # to a vendor (High). Carol forwards her mailbox to a partner.
            $runOne = @{ Users = $users; Traces = $traces; Rules = $aliceRule
                Mailboxes = @{ 'alice.ng@contoso.com' = 'smtp:alice.home@webmail.example.com'; 'carol.otieno@contoso.com' = 'smtp:records@partner.example.com' } }
            $outputDir = Invoke-OfflineMonitorRun -Name 'carry-forward' -Scenario $runOne -ExceptionTarget 'nobody@partner.example.com'
            $aliceOne = @(Get-Content -LiteralPath (Join-Path $outputDir 'forwarding-findings.json') -Raw | ConvertFrom-Json) |
                Where-Object { $_.UserPrincipalName -eq 'alice.ng@contoso.com' -and $_.ForwardingType -eq 'MailboxForwarding' }

            # Run two, twice: alice's mailbox cannot be read but her inbox rules can. Carol's mailbox read fails and
            # Graph says she has no mailbox, but the last report has a forward for her.
            $runTwo = @{ Users = $users; Traces = $traces; Rules = $aliceRule; Mailboxes = @{}
                MailboxErrors = @('alice.ng@contoso.com', 'carol.otieno@contoso.com'); RulesNoMailbox = @('carol.otieno@contoso.com') }
            $null = Invoke-OfflineMonitorRun -Name 'carry-forward' -Scenario $runTwo -ExceptionTarget 'nobody@partner.example.com'
            $findingsTwo = @(Get-Content -LiteralPath (Join-Path $outputDir 'forwarding-findings.json') -Raw | ConvertFrom-Json)
            $csvTwo = @(Import-Csv -LiteralPath (Join-Path $outputDir 'forwarding-findings.csv'))
            $summaryTwo = Get-Content -LiteralPath (Join-Path $outputDir 'summary.json') -Raw | ConvertFrom-Json
            $htmlTwo = Get-Content -LiteralPath (Join-Path $outputDir 'dashboard.html') -Raw
            $exitTwo = $runTwo.ExitCode

            $null = Invoke-OfflineMonitorRun -Name 'carry-forward' -Scenario $runTwo -ExceptionTarget 'nobody@partner.example.com'
            $findingsTwoAgain = @(Get-Content -LiteralPath (Join-Path $outputDir 'forwarding-findings.json') -Raw | ConvertFrom-Json)

            # Run three: alice can be read again and no longer forwards anything.
            $runThree = @{ Users = $users; Traces = $traces; Rules = @{}; Mailboxes = @{} }
            $null = Invoke-OfflineMonitorRun -Name 'carry-forward' -Scenario $runThree -ExceptionTarget 'nobody@partner.example.com'
            $findingsThree = @(Get-Content -LiteralPath (Join-Path $outputDir 'forwarding-findings.json') -Raw | ConvertFrom-Json)
        }

        It 'starts from a Critical mailbox forward for alice' {
            $aliceOne.RiskLevel | Should -BeExactly 'Critical'
            $aliceOne.NotRechecked | Should -BeFalse
        }

        It 'keeps alice''s mailbox forward when her mailbox cannot be read, marked not re-checked, with the first run''s DetectedAt' {
            $exitTwo | Should -Be 2
            $kept = @($findingsTwo | Where-Object { $_.UserPrincipalName -eq 'alice.ng@contoso.com' -and $_.ForwardingType -eq 'MailboxForwarding' })

            $kept.Count | Should -Be 1
            $kept[0].NotRechecked | Should -BeTrue
            $kept[0].RiskLevel | Should -BeExactly 'Critical'
            $kept[0].ForwardTarget | Should -BeExactly 'smtp:alice.home@webmail.example.com'
            $kept[0].DetectedAt | Should -Be $aliceOne.DetectedAt
            $kept[0].KeptBecause | Should -BeExactly 'Failed'
        }

        It 'reports alice''s inbox rule once, as read in this run, because the rules call worked' {
            $rules = @($findingsTwo | Where-Object { $_.UserPrincipalName -eq 'alice.ng@contoso.com' -and $_.ForwardingType -eq 'InboxRuleForward' })

            $rules.Count | Should -Be 1
            $rules[0].NotRechecked | Should -BeFalse
        }

        It 'keeps carol''s mailbox forward too, because her mailbox read failed, and does not list her as an account without a mailbox' {
            # Her inbox rules said "no mailbox" and the last report has no inbox rule forward of hers, so that answer
            # stands for the inbox rules; she is still a failed read, so she is not listed under UsersWithoutMailbox.
            $summaryTwo.UsersWithoutMailbox.Count | Should -Be 0
            @($summaryTwo.CollectionFailures.MailboxForwarding.UserPrincipalNames | Sort-Object) | Should -Be @('alice.ng@contoso.com', 'carol.otieno@contoso.com')
            $summaryTwo.CollectionFailures.InboxRules.Count | Should -Be 0
            $carol = @($findingsTwo | Where-Object { $_.UserPrincipalName -eq 'carol.otieno@contoso.com' })
            $carol.Count | Should -Be 1
            $carol[0].NotRechecked | Should -BeTrue
            $carol[0].KeptBecause | Should -BeExactly 'Failed'
        }

        It 'counts the kept forwards in the summary' {
            $summaryTwo.UsersWithMailboxForwarding | Should -Be 2
            $summaryTwo.HighCriticalRiskCount | Should -Be 3
        }

        It 'marks the domains of the kept forwards in the external domains table' {
            $domainRows = @([regex]::Matches($htmlTwo, '<tr><td>[a-z.]+\.example\.com</td>.*?</tr>') | ForEach-Object Value)

            @($domainRows | Where-Object { $_ -like '*webmail.example.com*' }) | Should -BeLike '*not re-checked*'
            @($domainRows | Where-Object { $_ -like '*partner.example.com*' }) | Should -BeLike '*not re-checked*'
            @($domainRows | Where-Object { $_ -like '*vendor.example.com*' }) | Should -Not -BeLike '*not re-checked*'
        }

        It 'carries the NotRechecked column in the findings CSV' {
            $csvTwo[0].PSObject.Properties.Name | Should -Be $expectedFindingColumns
            ($csvTwo | Where-Object { $_.ForwardingType -eq 'MailboxForwarding' -and $_.UserPrincipalName -eq 'alice.ng@contoso.com' }).NotRechecked | Should -BeExactly 'True'
            ($csvTwo | Where-Object ForwardingType -eq 'InboxRuleForward').NotRechecked | Should -BeExactly 'False'
        }

        It 'marks the kept forward not re-checked in the risky users table of the dashboard' {
            $rows = @([regex]::Matches($htmlTwo, '<tr><td>alice\.ng@contoso\.com</td>.*?</tr>') | ForEach-Object Value)

            $rows.Count | Should -Be 2
            @($rows | Where-Object { $_ -like '*webmail.example.com*' }) | Should -BeLike '*not re-checked*'
            @($rows | Where-Object { $_ -like '*vendor.example.com*' }) | Should -Not -BeLike '*not re-checked*'
        }

        It 'keeps the first run''s DetectedAt when her mailbox fails again' {
            $kept = @($findingsTwoAgain | Where-Object { $_.UserPrincipalName -eq 'alice.ng@contoso.com' -and $_.ForwardingType -eq 'MailboxForwarding' })

            $kept.Count | Should -Be 1
            $kept[0].NotRechecked | Should -BeTrue
            $kept[0].DetectedAt | Should -Be $aliceOne.DetectedAt
        }

        It 'drops the forward once her mailbox is read again and has none' {
            $runThree.ExitCode | Should -Be 0
            @($findingsThree | Where-Object { $_.UserPrincipalName -eq 'alice.ng@contoso.com' }).Count | Should -Be 0
        }
    }

    Context 'when two scans run one after the other in the same folder' {
        BeforeAll {
            $scenario = @{ Users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber')); Mailboxes = @{}; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com')) }
            $outputDir = Invoke-OfflineMonitorRun -Name 'back-to-back' -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com'
            $firstExit = $scenario.ExitCode
            $heldAfterFirst = Test-ScanLockHeld -Directory $outputDir
            $null = Invoke-OfflineMonitorRun -Name 'back-to-back' -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com'
        }

        It 'runs both to the end and lets go of the lock after each, leaving the lock file empty' {
            $firstExit | Should -Be 0
            $heldAfterFirst | Should -BeFalse
            $scenario.ExitCode | Should -Be 0
            Test-ScanLockHeld -Directory $outputDir | Should -BeFalse
            [System.IO.File]::ReadAllText((Join-Path $outputDir '.scan.lock')) | Should -BeExactly ''
            @(Get-Content -LiteralPath (Join-Path $outputDir 'outbound-baseline-history.json') -Raw | ConvertFrom-Json).Count | Should -Be 2
        }
    }

    Context 'when the output folder holds a lock file that no process here holds, written <Case>' -ForEach @(
        @{ Case = 'on another computer five minutes ago'; Machine = 'other-host.example.com'; Minutes = 5; TakenOver = $false; Folder = 'unheld-other-fresh' }
        @{ Case = 'on another computer seven hours ago'; Machine = 'other-host.example.com'; Minutes = 420; TakenOver = $true; Folder = 'unheld-other-old' }
        @{ Case = 'on this computer five minutes ago'; Machine = ''; Minutes = 5; TakenOver = $true; Folder = 'unheld-here-fresh' }
    ) {
        BeforeAll {
            # The lock this computer holds does not reach other computers that share the folder (iCloud, OneDrive, SMB,
            # NFS), so a lock another computer wrote counts for six hours. One written here that nobody holds is free.
            $scenario = @{ Users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber')); Mailboxes = @{}; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com')) }
            $outputDir = Invoke-OfflineMonitorRun -Name $Folder -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com'
            $lockPath = Join-Path $outputDir '.scan.lock'
            $machineName = if ($Machine) { $Machine } else { [System.Environment]::MachineName }
            $started = [datetime]::UtcNow.AddMinutes(-$Minutes)
            $startedText = $started.ToString('yyyy-MM-ddTHH:mm:ssZ', [cultureinfo]::InvariantCulture)
            $lockText = "ProcessId: 4242`nMachineName: $machineName`nStartedAt: $($started.ToString('o', [cultureinfo]::InvariantCulture))`n"
            [System.IO.File]::WriteAllText($lockPath, $lockText)
            $before = Get-OutputSnapshot -Directory $outputDir

            $thrown = $null
            $scenario.ExitCode = $null
            try { $null = Invoke-OfflineMonitorRun -Name $Folder -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com' }
            catch { $thrown = $_ }
        }

        It 'respects a lock from another computer for six hours, and takes over any other lock at once' {
            if ($TakenOver) {
                $thrown | Should -BeNullOrEmpty
                $scenario.ExitCode | Should -Be 0
                Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') -Raw | Should -BeLike "*Took over the scan lock*process 4242 on $machineName*"
                Test-ScanLockHeld -Directory $outputDir | Should -BeFalse
            }
            else {
                $thrown.Exception.Message.StartsWith("Another scan is running in $outputDir (started $startedText) on $machineName.") | Should -BeTrue
                Get-OutputSnapshot -Directory $outputDir | Should -BeExactly $before
                [System.IO.File]::ReadAllText($lockPath) | Should -BeExactly $lockText
            }
        }
    }

    Context 'when another scan holds the lock' {
        BeforeAll {
            $users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber'))
            $good = @{ Users = $users; Mailboxes = @{ 'alex.wilber@contoso.com' = 'smtp:records@partner.example.com' }; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com')) }
            $outputDir = Invoke-OfflineMonitorRun -Name 'busy' -Scenario $good -ExceptionTarget 'nobody@partner.example.com'
            $lockPath = Join-Path $outputDir '.scan.lock'

            # Another process holds the lock the way a scan does: open, with no sharing, for as long as it runs.
            $holderScript = Join-Path $TestDrive 'hold-scan-lock.ps1'
            Set-Content -LiteralPath $holderScript -Encoding UTF8 -Value @'
param([string]$LockPath, [string]$ReadyPath)
$stream = [System.IO.FileStream]::new($LockPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
$stream.SetLength(0)
$text = "ProcessId: $PID`nMachineName: $([System.Environment]::MachineName)`nStartedAt: $([datetime]::UtcNow.ToString('o', [cultureinfo]::InvariantCulture))`n"
$bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
$stream.Write($bytes, 0, $bytes.Length)
$stream.Flush($true)
[System.IO.File]::WriteAllText($ReadyPath, 'ready')
Start-Sleep -Seconds 120
'@
            $ready = Join-Path $TestDrive 'holder-ready'
            $holder = [System.Diagnostics.Process]::Start([System.Environment]::ProcessPath, [string[]]@('-NoProfile', '-NonInteractive', '-File', $holderScript, $lockPath, $ready))
            $deadline = [datetime]::UtcNow.AddSeconds(60)
            while (-not [System.IO.File]::Exists($ready) -and -not $holder.HasExited -and [datetime]::UtcNow -lt $deadline) { [System.Threading.Thread]::Sleep(20) }
            $startedText = [System.IO.File]::GetLastWriteTimeUtc($lockPath).ToString('yyyy-MM-ddTHH:mm:ssZ', [cultureinfo]::InvariantCulture)
            $before = Get-OutputSnapshot -Directory $outputDir

            $second = @{ Users = $users; Mailboxes = @{}; Rules = @{}; Traces = @() }
            $thrown = $null
            try { $null = Invoke-OfflineMonitorRun -Name 'busy' -Scenario $second -ExceptionTarget 'nobody@partner.example.com' }
            catch { $thrown = $_ }
            $after = Get-OutputSnapshot -Directory $outputDir

            # The same stop from a separate process, to see the exit code a scheduler gets.
            $runRoot = Join-Path $TestDrive 'busy'
            $childOutput = & ([System.Environment]::ProcessPath) -NoProfile -NonInteractive -File $monitorScript `
                -SettingsPath (Join-Path $runRoot 'settings.json') -ApprovedExceptionsPath (Join-Path $runRoot 'exceptions.csv') -SkipConnect 2>&1
            $childExit = $LASTEXITCODE

            # Then the holder is killed. The operating system lets go of its lock, and the next scan takes it at once.
            $holderWasRunning = -not $holder.HasExited
            $holder.Kill()
            $holder.WaitForExit()
            $holder.Dispose()
            $third = @{ Users = $users; Mailboxes = @{ 'alex.wilber@contoso.com' = 'smtp:records@partner.example.com' }; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com')) }
            $null = Invoke-OfflineMonitorRun -Name 'busy' -Scenario $third -ExceptionTarget 'nobody@partner.example.com'
        }

        It 'stops before it asks Microsoft for anything, with a message that names the folder and when the other scan started' {
            $holderWasRunning | Should -BeTrue
            $thrown | Should -Not -BeNullOrEmpty
            $thrown.Exception.Message.StartsWith("Another scan is running in $outputDir (started $startedText)") | Should -BeTrue
            [int]$second.GraphCalls | Should -Be 0
        }

        It 'leaves every output file as it was' {
            $after | Should -BeExactly $before
        }

        It 'exits with code 1 when run as its own process' {
            $childExit | Should -Be 1
            ($childOutput | Out-String) | Should -BeLike '*Another scan is running in*'
        }

        It 'takes the lock over at once when the process that held it is killed' {
            $third.ExitCode | Should -Be 0
            Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') -Raw | Should -BeLike '*Took over the scan lock*no longer running*'
            Test-ScanLockHeld -Directory $outputDir | Should -BeFalse
        }
    }

    Context 'when <Collector> reports no mailbox for every user' -ForEach @(
        @{ Collector = 'Exchange Online'; Folder = 'blind-exchange'; Fault = @{ AllNotFound = $true }
            Message = '*Exchange Online reported no mailbox for any of the 2 scanned users*wrong tenant*recipient scope*No output files were changed*' }
        # Graph always reads its own tenant, so its message must not blame the tenant.
        @{ Collector = 'Microsoft Graph'; Folder = 'blind-graph'; Fault = @{ RulesNoMailbox = @('alice.ng@contoso.com', 'bob.diaz@contoso.com') }
            Message = '*Microsoft Graph reported no mailbox for any of the 2 scanned users*No scanned account has a mailbox reachable through Graph*unlicensed or on-premises*stopped rather than publish an empty report*No output files were changed*' }
    ) {
        BeforeAll {
            # The reviewer's scenario A: a session in the wrong tenant, or without recipient scope, sees no mailbox at all.
            $users = @((Get-OfflineUser -Name 'alice.ng' -DisplayName 'Alice Ng'), (Get-OfflineUser -Name 'bob.diaz' -DisplayName 'Bob Diaz'))
            $mailboxes = @{ 'alice.ng@contoso.com' = 'smtp:alice.home@webmail.example.com' }
            $first = @{ Users = $users; Mailboxes = $mailboxes; Rules = @{}; Traces = @() }
            $outputDir = Invoke-OfflineMonitorRun -Name $Folder -Scenario $first -ExceptionTarget 'nobody@partner.example.com'
            $before = Get-OutputSnapshot -Directory $outputDir

            $second = @{ Users = $users; Mailboxes = $mailboxes; Rules = @{}; Traces = @() }
            foreach ($key in $Fault.Keys) { $second[$key] = $Fault[$key] }
            $thrown = $null
            try { $null = Invoke-OfflineMonitorRun -Name $Folder -Scenario $second -ExceptionTarget 'nobody@partner.example.com' }
            catch { $thrown = $_ }
        }

        It 'stops the run instead of reporting a tenant with no mailboxes, and says what that usually means' {
            $thrown | Should -Not -BeNullOrEmpty
            $thrown.Exception.Message | Should -BeLike $Message
            if ($Collector -eq 'Microsoft Graph') { $thrown.Exception.Message | Should -Not -BeLike '*wrong tenant*' }
        }

        It 'leaves every earlier output file untouched, so the known forward stays on the report' {
            Get-OutputSnapshot -Directory $outputDir | Should -BeExactly $before
        }

        It 'records the stop in errors.log' {
            Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') -Raw | Should -BeLike "*Invoke-ForwardingMonitor failed.*$Collector reported no mailbox*"
        }
    }

    Context 'when one collector says an account has no mailbox and the other read that mailbox in the same run' {
        BeforeAll {
            # The reviewer's scenario B: Graph answers ErrorItemNotFound for bob once, although Get-Mailbox read his
            # mailbox in the same run. The reverse for dana: Get-Mailbox finds nothing, Graph reads her inbox rules.
            $users = @(
                (Get-OfflineUser -Name 'alice.ng' -DisplayName 'Alice Ng')
                (Get-OfflineUser -Name 'bob.diaz' -DisplayName 'Bob Diaz')
                (Get-OfflineUser -Name 'dana.kim' -DisplayName 'Dana Kim')
            )
            $rules = @{ 'bob.diaz@contoso.com' = @((Get-OfflineRule -Name 'Forward all' -Target 'drop@webmail.example.com')) }
            $mailboxes = @{ 'dana.kim@contoso.com' = 'smtp:dana@webmail.example.com' }
            $first = @{ Users = $users; Mailboxes = $mailboxes; Rules = $rules; Traces = @() }
            $outputDir = Invoke-OfflineMonitorRun -Name 'one-collector-blind' -Scenario $first -ExceptionTarget 'nobody@partner.example.com'

            $second = @{ Users = $users; Mailboxes = $mailboxes; Rules = $rules; Traces = @()
                RulesItemNotFound = @('bob.diaz@contoso.com'); NoMailbox = @('dana.kim@contoso.com') }
            $null = Invoke-OfflineMonitorRun -Name 'one-collector-blind' -Scenario $second -ExceptionTarget 'nobody@partner.example.com'
            $summary = Get-Content -LiteralPath (Join-Path $outputDir 'summary.json') -Raw | ConvertFrom-Json
            $findings = @(Get-Content -LiteralPath (Join-Path $outputDir 'forwarding-findings.json') -Raw | ConvertFrom-Json)
        }

        It 'counts both as failed reads, not as accounts without a mailbox, and exits 2' {
            $second.ExitCode | Should -Be 2
            $summary.UsersWithoutMailbox.Count | Should -Be 0
            @($summary.CollectionFailures.InboxRules.UserPrincipalNames) | Should -Be @('bob.diaz@contoso.com')
            @($summary.CollectionFailures.MailboxForwarding.UserPrincipalNames) | Should -Be @('dana.kim@contoso.com')
        }

        It 'keeps the forwards the last scan found for them, marked not re-checked' {
            $bob = @($findings | Where-Object UserPrincipalName -eq 'bob.diaz@contoso.com')
            $dana = @($findings | Where-Object UserPrincipalName -eq 'dana.kim@contoso.com')

            $bob.Count | Should -Be 1
            $bob[0].ForwardingType | Should -BeExactly 'InboxRuleForward'
            $bob[0].NotRechecked | Should -BeTrue
            $bob[0].RiskLevel | Should -BeExactly 'Critical'
            $dana.Count | Should -Be 1
            $dana[0].ForwardingType | Should -BeExactly 'MailboxForwarding'
            $dana[0].NotRechecked | Should -BeTrue
        }

        It 'says why in errors.log' {
            $log = Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') -Raw

            $log | Should -BeLike '*Inbox rules for bob.diaz@contoso.com*Get-Mailbox read the mailbox in this run*counted as a failed read*'
            $log | Should -BeLike '*Mailbox forwarding for dana.kim@contoso.com*Microsoft Graph read the inbox rules in this run*counted as a failed read*'
        }
    }

    Context 'when the exceptions or the domain lists change while a forward is kept from an earlier scan' {
        BeforeAll {
            # The reviewer's scenario C: alex's approved exception expires during a run in which his mailbox cannot be read.
            $users = @(
                (Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber')
                (Get-OfflineUser -Name 'sam.okafor' -DisplayName 'Sam Okafor')
                (Get-OfflineUser -Name 'priya.nair' -DisplayName 'Priya Nair')
            )
            $mailboxes = @{ 'alex.wilber@contoso.com' = 'smtp:alex.home@webmail.example.com'; 'sam.okafor@contoso.com' = 'smtp:records@partner.example.com' }
            $first = @{ Users = $users; Mailboxes = $mailboxes; Rules = @{}; Traces = @() }
            $outputDir = Invoke-OfflineMonitorRun -Name 'rescore' -Scenario $first -ExceptionTarget 'alex.home@webmail.example.com'
            $findingsOne = @(Get-Content -LiteralPath (Join-Path $outputDir 'forwarding-findings.json') -Raw | ConvertFrom-Json)

            # Run two: the exception expired yesterday and partner.example.com is now an internal domain.
            $second = @{ Users = $users; Mailboxes = $mailboxes; Rules = @{}; Traces = @(); MailboxErrors = @('alex.wilber@contoso.com', 'sam.okafor@contoso.com') }
            $null = Invoke-OfflineMonitorRun -Name 'rescore' -Scenario $second -ExceptionTarget 'alex.home@webmail.example.com' `
                -ExceptionExpiration (Get-TestDateText -OffsetDays -1) -SettingsOverride @{ InternalDomains = @('contoso.com', 'contoso.onmicrosoft.com', 'partner.example.com') }
            $findingsTwo = @(Get-Content -LiteralPath (Join-Path $outputDir 'forwarding-findings.json') -Raw | ConvertFrom-Json)
            $summaryTwo = Get-Content -LiteralPath (Join-Path $outputDir 'summary.json') -Raw | ConvertFrom-Json
        }

        It 'starts with alex approved and sam High' {
            ($findingsOne | Where-Object UserPrincipalName -eq 'alex.wilber@contoso.com').RiskLevel | Should -BeExactly 'Exception'
            ($findingsOne | Where-Object UserPrincipalName -eq 'sam.okafor@contoso.com').RiskLevel | Should -BeExactly 'High'
        }

        It 'scores alex''s kept forward again: the exception has expired, so it is Critical' {
            $alex = $findingsTwo | Where-Object UserPrincipalName -eq 'alex.wilber@contoso.com'

            $alex.NotRechecked | Should -BeTrue
            $alex.ApprovedException | Should -BeFalse
            $alex.IsPersonalDomain | Should -BeTrue
            $alex.RiskLevel | Should -BeExactly 'Critical'
        }

        It 'scores sam''s kept forward again: partner.example.com is internal now, so it is Low' {
            $sam = $findingsTwo | Where-Object UserPrincipalName -eq 'sam.okafor@contoso.com'

            $sam.NotRechecked | Should -BeTrue
            $sam.IsExternal | Should -BeFalse
            $sam.RiskLevel | Should -BeExactly 'Low'
        }

        It 'counts the new levels in the summary' {
            $summaryTwo.HighCriticalRiskCount | Should -Be 1
            $summaryTwo.ApprovedExceptionsCount | Should -Be 0
            $summaryTwo.ExternalForwardingCount | Should -Be 1
        }
    }

    Context 'when a scan on this computer was killed and left its lock behind' {
        BeforeAll {
            $scenario = @{ Users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber')); Mailboxes = @{}; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com')) }
            $outputDir = Invoke-OfflineMonitorRun -Name 'killed-scan' -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com'
            $runRoot = Join-Path $TestDrive 'killed-scan'
            $lockPath = Join-Path $outputDir '.scan.lock'
            $marker = Join-Path $TestDrive 'killed-scan-trace-reached'

            # The reviewer's kill: the real script in its own process, killed while it waits on the message trace.
            # A kill (or SIGTERM) skips the script's finally block; the operating system lets go of the lock anyway.
            $childScript = Join-Path $TestDrive 'scan-until-killed.ps1'
            Set-Content -LiteralPath $childScript -Encoding UTF8 -Value @'
param([string]$MonitorScript, [string]$RunRoot, [string]$Marker)
$global:TraceMarker = $Marker
function global:Invoke-MgGraphRequest {
    [CmdletBinding()]
    param($Method, $Uri)
    if ($Uri -match '/messageRules$') { return @{ value = @() } }
    return @{ value = @(@{ id = '00000000-0000-0000-0000-000000000000'; displayName = 'Alex Wilber'; userPrincipalName = 'alex.wilber@contoso.com'; mail = 'alex.wilber@contoso.com'; accountEnabled = $true; userType = 'Member' }) }
}
function global:Get-Mailbox {
    [CmdletBinding()]
    param($Identity)
    return [pscustomobject]@{ DisplayName = 'Alex Wilber'; UserPrincipalName = $Identity; PrimarySmtpAddress = $Identity; ForwardingAddress = $null; ForwardingSmtpAddress = $null; DeliverToMailboxAndForward = $false }
}
function global:Get-MessageTraceV2 {
    [CmdletBinding()]
    param($StartDate, $EndDate, $ResultSize)
    [System.IO.File]::WriteAllText($global:TraceMarker, 'reached')
    [System.Threading.Thread]::Sleep(120000)
}
& $MonitorScript -SettingsPath (Join-Path $RunRoot 'settings.json') -ApprovedExceptionsPath (Join-Path $RunRoot 'exceptions.csv') -SkipConnect
'@
            $startInfo = [System.Diagnostics.ProcessStartInfo]::new([System.Environment]::ProcessPath)
            foreach ($argument in '-NoProfile', '-NonInteractive', '-File', $childScript, $monitorScript, $runRoot, $marker) { $startInfo.ArgumentList.Add($argument) }
            $startInfo.UseShellExecute = $false
            $startInfo.RedirectStandardOutput = $true
            $startInfo.RedirectStandardError = $true
            $child = [System.Diagnostics.Process]::Start($startInfo)
            $deadline = [datetime]::UtcNow.AddSeconds(60)
            while (-not [System.IO.File]::Exists($marker) -and -not $child.HasExited -and [datetime]::UtcNow -lt $deadline) { [System.Threading.Thread]::Sleep(20) }
            $childExitedEarly = $child.HasExited
            $heldWhileRunning = Test-ScanLockHeld -Directory $outputDir
            if (-not $childExitedEarly) { $child.Kill() }
            $child.WaitForExit()
            $child.Dispose()
            $heldAfterKill = Test-ScanLockHeld -Directory $outputDir
            $lockText = [System.IO.File]::ReadAllText($lockPath)

            $null = Invoke-OfflineMonitorRun -Name 'killed-scan' -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com'
        }

        It 'held the lock while it ran, and the operating system let go of it when the process was killed' {
            $childExitedEarly | Should -BeFalse
            $heldWhileRunning | Should -BeTrue
            $heldAfterKill | Should -BeFalse
            $lockText | Should -BeLike "*ProcessId: *MachineName: $([System.Environment]::MachineName)*StartedAt: *"
        }

        It 'lets the next scan take the lock over at once' {
            $scenario.ExitCode | Should -Be 0
            Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') -Raw | Should -BeLike '*Took over the scan lock*no longer running*'
            Test-ScanLockHeld -Directory $outputDir | Should -BeFalse
        }
    }

    Context 'when the lock file cannot be opened, and it was last written <Age> ago' -ForEach @(
        @{ Age = 'ten minutes'; Minutes = 10; TakenOver = $false; Folder = 'lock-read-only-fresh' }
        @{ Age = 'seven hours'; Minutes = 420; TakenOver = $true; Folder = 'lock-read-only-old' }
    ) {
        BeforeAll {
            # A lock that cannot be opened for another reason than a scan holding it (here it is read-only) says nothing
            # about whether a scan runs, so the six-hour rule decides.
            $scenario = @{ Users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber')); Mailboxes = @{}; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com')) }
            $outputDir = Invoke-OfflineMonitorRun -Name $Folder -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com'
            $lockPath = Join-Path $outputDir '.scan.lock'
            [System.IO.File]::WriteAllText($lockPath, "ProcessId: 4242`nMachineName: other-host.example.com`nStartedAt: $([datetime]::UtcNow.AddMinutes(-$Minutes).ToString('o', [cultureinfo]::InvariantCulture))`n")
            [System.IO.File]::SetLastWriteTimeUtc($lockPath, [datetime]::UtcNow.AddMinutes(-$Minutes))
            Set-ItemProperty -LiteralPath $lockPath -Name IsReadOnly -Value $true
            $before = Get-OutputSnapshot -Directory $outputDir

            $thrown = $null
            $scenario.ExitCode = $null
            try { $null = Invoke-OfflineMonitorRun -Name $Folder -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com' }
            catch { $thrown = $_ }
        }

        AfterAll {
            if ([System.IO.File]::Exists($lockPath)) { Set-ItemProperty -LiteralPath $lockPath -Name IsReadOnly -Value $false }
        }

        It 'stops while the lock is less than six hours old, and takes it over after that, saying why' {
            if ($TakenOver) {
                $thrown | Should -BeNullOrEmpty
                $scenario.ExitCode | Should -Be 0
                Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') -Raw | Should -BeLike '*Took over the scan lock*could not be opened*more than six hours*'
                Test-ScanLockHeld -Directory $outputDir | Should -BeFalse
            }
            else {
                $thrown.Exception.Message | Should -BeLike '*scan lock*cannot be opened*less than six hours*'
                Get-OutputSnapshot -Directory $outputDir | Should -BeExactly $before
            }
        }
    }

    Context 'when a mailbox is removed on purpose and stays gone' {
        BeforeAll {
            # The reviewer's r1: the account keeps its forward for one run, marked, then is an account without a mailbox.
            $users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber'), (Get-OfflineUser -Name 'bob.diaz' -DisplayName 'Bob Diaz'))
            $first = @{ Users = $users; Mailboxes = @{ 'alex.wilber@contoso.com' = 'smtp:alex.home@webmail.example.com' }; Rules = @{}; Traces = @() }
            $outputDir = Invoke-OfflineMonitorRun -Name 'mailbox-removed' -Scenario $first -ExceptionTarget 'nobody@partner.example.com'
            $runs = @{}
            foreach ($run in 2, 3, 4) {
                $gone = @{ Users = $users; Mailboxes = @{}; Rules = @{}; Traces = @()
                    NoMailbox = @('alex.wilber@contoso.com'); RulesNoMailbox = @('alex.wilber@contoso.com') }
                $null = Invoke-OfflineMonitorRun -Name 'mailbox-removed' -Scenario $gone -ExceptionTarget 'nobody@partner.example.com'
                $runs[$run] = @{
                    ExitCode = $gone.ExitCode
                    Findings = @(Get-Content -LiteralPath (Join-Path $outputDir 'forwarding-findings.json') -Raw | ConvertFrom-Json)
                    Summary  = Get-Content -LiteralPath (Join-Path $outputDir 'summary.json') -Raw | ConvertFrom-Json
                    Dropped  = @(Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') | Where-Object { $_ -like '*Dropped the earlier forwards for alex.wilber@contoso.com*' }).Count
                }
            }
        }

        It 'run 1 finds the Critical forward' {
            $first.ExitCode | Should -Be 0
        }

        It 'run 2 keeps the forward, marked not re-checked, and exits 2' {
            $runs[2].ExitCode | Should -Be 2
            @($runs[2].Findings).Count | Should -Be 1
            $runs[2].Findings[0].NotRechecked | Should -BeTrue
            $runs[2].Findings[0].KeptBecause | Should -BeExactly 'NoMailbox'
            $runs[2].Summary.UsersWithoutMailbox.Count | Should -Be 0
        }

        It 'run 3 drops it, lists the account under UsersWithoutMailbox, says why once in errors.log and exits 0' {
            $runs[3].ExitCode | Should -Be 0
            @($runs[3].Findings).Count | Should -Be 0
            @($runs[3].Summary.UsersWithoutMailbox.UserPrincipalNames) | Should -Be @('alex.wilber@contoso.com')
            $runs[3].Summary.CollectionFailures.MailboxForwarding.Count | Should -Be 0
            $runs[3].Dropped | Should -Be 1
            Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') -Raw | Should -BeLike '*Dropped the earlier forwards for alex.wilber@contoso.com*no mailbox for two runs*'
        }

        It 'run 4 treats it as an account without a mailbox and logs nothing more about it' {
            $runs[4].ExitCode | Should -Be 0
            @($runs[4].Findings).Count | Should -Be 0
            @($runs[4].Summary.UsersWithoutMailbox.UserPrincipalNames) | Should -Be @('alex.wilber@contoso.com')
            $runs[4].Dropped | Should -Be 1
        }
    }

    Context 'when the previous report cannot be read' {
        BeforeAll {
            # The reviewer's r6: with the last report cut short, an account that says "no mailbox" would drop its
            # forward without a trace.
            $users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber'), (Get-OfflineUser -Name 'bob.diaz' -DisplayName 'Bob Diaz'))
            $first = @{ Users = $users; Mailboxes = @{ 'alex.wilber@contoso.com' = 'smtp:alex.home@webmail.example.com' }; Rules = @{}; Traces = @() }
            $outputDir = Invoke-OfflineMonitorRun -Name 'report-unreadable' -Scenario $first -ExceptionTarget 'nobody@partner.example.com'
            $reportPath = Join-Path $outputDir 'forwarding-findings.json'
            $text = [System.IO.File]::ReadAllText($reportPath)
            [System.IO.File]::WriteAllText($reportPath, $text.Substring(0, [int]($text.Length / 2)))

            $gone = @{ Users = $users; Mailboxes = @{}; Rules = @{}; Traces = @()
                NoMailbox = @('alex.wilber@contoso.com'); RulesNoMailbox = @('alex.wilber@contoso.com') }
            $null = Invoke-OfflineMonitorRun -Name 'report-unreadable' -Scenario $gone -ExceptionTarget 'nobody@partner.example.com'
            $exitTwo = $gone.ExitCode
            $summaryTwo = Get-Content -LiteralPath (Join-Path $outputDir 'summary.json') -Raw | ConvertFrom-Json
            $htmlTwo = Get-Content -LiteralPath (Join-Path $outputDir 'dashboard.html') -Raw

            $null = Invoke-OfflineMonitorRun -Name 'report-unreadable' -Scenario $gone -ExceptionTarget 'nobody@partner.example.com'
            $exitThree = $gone.ExitCode
            $summaryThree = Get-Content -LiteralPath (Join-Path $outputDir 'summary.json') -Raw | ConvertFrom-Json
        }

        It 'says so: PreviousReportUnreadable in summary.json, a line in the dashboard warning, and exit 2' {
            $exitTwo | Should -Be 2
            $summaryTwo.PreviousReportUnreadable | Should -BeTrue
            $htmlTwo | Should -BeLike '*Incomplete scan*'
            $htmlTwo | Should -BeLike '*previous forwarding-findings.json could not be read*'
            Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') -Raw | Should -BeLike '*Could not read the previous forwarding-findings.json*'
        }

        It 'counts an account that says "no mailbox" as a failed read for that run, so it is named rather than dropped' {
            @($summaryTwo.CollectionFailures.MailboxForwarding.UserPrincipalNames) | Should -Be @('alex.wilber@contoso.com')
            @($summaryTwo.CollectionFailures.InboxRules.UserPrincipalNames) | Should -Be @('alex.wilber@contoso.com')
            $summaryTwo.UsersWithoutMailbox.Count | Should -Be 0
        }

        It 'clears on the next run, which reads the report that run wrote' {
            $exitThree | Should -Be 0
            $summaryThree.PreviousReportUnreadable | Should -BeFalse
            @($summaryThree.UsersWithoutMailbox.UserPrincipalNames) | Should -Be @('alex.wilber@contoso.com')
        }
    }

    Context 'with a guest member whose user name holds #EXT#' {
        BeforeAll {
            # The reviewer's r7: an unencoded # in the Graph URL starts a fragment, so the rules read failed every run.
            $guest = 'jane_fabrikam.com#EXT#@contoso.onmicrosoft.com'
            $guestId = '00000000-0000-0000-0000-000000000000'
            $scenario = @{
                Users     = @(
                    @{ id = $guestId; displayName = 'Jane (Fabrikam)'; userPrincipalName = $guest; mail = 'jane@fabrikam.example.com'; accountEnabled = $true; userType = 'Member' }
                    (Get-OfflineUser -Name 'bob.diaz' -DisplayName 'Bob Diaz')
                )
                Mailboxes = @{}
                Rules     = @{ $guest = @((Get-OfflineRule -Name 'Copy home' -Target 'jane.home@webmail.example.com')) }
                Traces    = @()
            }
            $outputDir = Invoke-OfflineMonitorRun -Name 'guest-member' -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com'
        }

        It 'reads the guest''s inbox rules and finds the forward' {
            $scenario.ExitCode | Should -Be 0
            @($scenario.RuleCalls | Where-Object { $_ -eq $guest }).Count | Should -Be 1
            $finding = @(Get-Content -LiteralPath (Join-Path $outputDir 'forwarding-findings.json') -Raw | ConvertFrom-Json) | Where-Object UserPrincipalName -eq $guest
            $finding.RiskLevel | Should -BeExactly 'Critical'
        }

        It 'reads inbox rules by object id, so no user name goes into the URL' {
            @($scenario.RuleUris) | Should -Contain "https://graph.microsoft.com/v1.0/users/$guestId/mailFolders/inbox/messageRules"
            @($scenario.RuleUris | Where-Object { $_ -like '*contoso.*' -or $_ -like '*EXT*' }).Count | Should -Be 0
        }
    }

    Context 'when Exchange keeps saying no mailbox while the Graph read keeps failing' {
        BeforeAll {
            # Each collector's own rows decide its grace. The mailbox row, kept once because Exchange said "no mailbox",
            # goes on the second such answer even though the inbox rule rows are still kept because Graph fails.
            $users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber'), (Get-OfflineUser -Name 'bob.diaz' -DisplayName 'Bob Diaz'))
            $live = @{ Users = $users; Traces = @(); Mailboxes = @{ 'alex.wilber@contoso.com' = 'smtp:alex.home@webmail.example.com' }
                Rules = @{ 'alex.wilber@contoso.com' = @((Get-OfflineRule -Name 'Copy home' -Target 'alex.copy@webmail.example.com')) } }
            $outputDir = Invoke-OfflineMonitorRun -Name 'exchange-gone-graph-failing' -Scenario $live -ExceptionTarget 'nobody@partner.example.com'
            $runs = @{}
            foreach ($run in 2..6) {
                $scenario = @{ Users = $users; Traces = @(); Mailboxes = @{}; Rules = @{}; NoMailbox = @('alex.wilber@contoso.com'); RuleErrors = @('alex.wilber@contoso.com') }
                $null = Invoke-OfflineMonitorRun -Name 'exchange-gone-graph-failing' -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com'
                $findings = @(Get-Content -LiteralPath (Join-Path $outputDir 'forwarding-findings.json') -Raw | ConvertFrom-Json)
                $runs[$run] = @{
                    ExitCode = $scenario.ExitCode
                    Mailbox  = @($findings | Where-Object ForwardingType -eq 'MailboxForwarding')
                    Rules    = @($findings | Where-Object ForwardingType -eq 'InboxRuleForward')
                    Dropped  = @(Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') | Where-Object { $_ -like '*Dropped the earlier forwards for alex.wilber@contoso.com*' })
                }
            }
        }

        It 'run 2 keeps both: the mailbox row because of no mailbox, the inbox rule row because its read failed' {
            $runs[2].ExitCode | Should -Be 2
            $runs[2].Mailbox.Count | Should -Be 1
            $runs[2].Mailbox[0].KeptBecause | Should -BeExactly 'NoMailbox'
            $runs[2].Rules[0].KeptBecause | Should -BeExactly 'Failed'
            $runs[2].Dropped.Count | Should -Be 0
        }

        It 'run 3 drops the mailbox row, with one line in errors.log, and keeps the inbox rule row' {
            $runs[3].ExitCode | Should -Be 2
            $runs[3].Mailbox.Count | Should -Be 0
            $runs[3].Rules.Count | Should -Be 1
            $runs[3].Rules[0].KeptBecause | Should -BeExactly 'Failed'
            $runs[3].Dropped.Count | Should -Be 1
            $runs[3].Dropped[0] | Should -BeLike '*(mailbox forwarding): Get-Mailbox has reported no mailbox for two runs*'
        }

        It 'runs 4 to 6 keep only the inbox rule row, and drop nothing more' {
            foreach ($run in 4..6) {
                $runs[$run].ExitCode | Should -Be 2 -Because "run $run"
                $runs[$run].Mailbox.Count | Should -Be 0 -Because "run $run"
                $runs[$run].Rules.Count | Should -Be 1 -Because "run $run"
                $runs[$run].Rules[0].KeptBecause | Should -BeExactly 'Failed' -Because "run $run"
                $runs[$run].Dropped.Count | Should -Be 1 -Because "run $run"
            }
        }
    }

    Context 'when a mailbox that could not be read then says it has none' {
        BeforeAll {
            # The reviewer's s1: the forwards are kept after the failed read, kept once more after the first "no mailbox"
            # answer, and dropped only after the second one.
            $users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber'), (Get-OfflineUser -Name 'bob.diaz' -DisplayName 'Bob Diaz'))
            $live = @{ Users = $users; Traces = @(); Mailboxes = @{ 'alex.wilber@contoso.com' = 'smtp:alex.home@webmail.example.com' }
                Rules = @{ 'alex.wilber@contoso.com' = @((Get-OfflineRule -Name 'Copy home' -Target 'alex.copy@webmail.example.com')) } }
            $outputDir = Invoke-OfflineMonitorRun -Name 'failed-then-gone' -Scenario $live -ExceptionTarget 'nobody@partner.example.com'
            $runs = @{}
            foreach ($run in 2, 3, 4) {
                $scenario = if ($run -eq 2) {
                    @{ Users = $users; Traces = @(); Mailboxes = @{}; Rules = @{}; MailboxErrors = @('alex.wilber@contoso.com'); RuleErrors = @('alex.wilber@contoso.com') }
                }
                else {
                    @{ Users = $users; Traces = @(); Mailboxes = @{}; Rules = @{}; NoMailbox = @('alex.wilber@contoso.com'); RulesNoMailbox = @('alex.wilber@contoso.com') }
                }
                $null = Invoke-OfflineMonitorRun -Name 'failed-then-gone' -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com'
                $runs[$run] = @{
                    ExitCode = $scenario.ExitCode
                    Findings = @(Get-Content -LiteralPath (Join-Path $outputDir 'forwarding-findings.json') -Raw | ConvertFrom-Json)
                    Summary  = Get-Content -LiteralPath (Join-Path $outputDir 'summary.json') -Raw | ConvertFrom-Json
                    Dropped  = @(Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') | Where-Object { $_ -like '*Dropped the earlier forwards for alex.wilber@contoso.com*' })
                }
            }
        }

        It 'run 2 keeps both forwards, marked as kept because the reads failed' {
            $runs[2].ExitCode | Should -Be 2
            @($runs[2].Findings).Count | Should -Be 2
            @($runs[2].Findings | Where-Object { $_.NotRechecked -eq $true -and $_.KeptBecause -eq 'Failed' }).Count | Should -Be 2
        }

        It 'run 3 keeps them once more, now because of no mailbox, and drops nothing' {
            $runs[3].ExitCode | Should -Be 2
            @($runs[3].Findings | Where-Object { $_.NotRechecked -eq $true -and $_.KeptBecause -eq 'NoMailbox' }).Count | Should -Be 2
            $runs[3].Summary.UsersWithoutMailbox.Count | Should -Be 0
            $runs[3].Dropped.Count | Should -Be 0
        }

        It 'run 4 drops them, lists the account as having no mailbox, and says so in words that match what happened' {
            $runs[4].ExitCode | Should -Be 0
            @($runs[4].Findings).Count | Should -Be 0
            @($runs[4].Summary.UsersWithoutMailbox.UserPrincipalNames) | Should -Be @('alex.wilber@contoso.com')
            $runs[4].Dropped.Count | Should -Be 2
            $runs[4].Dropped | Should -BeLike '*Dropped the earlier forwards for alex.wilber@contoso.com*has reported no mailbox for two runs*'
        }
    }

    Context 'when Exchange says no mailbox again while the Graph read fails' {
        BeforeAll {
            # The reviewer's s2 scenario B: only the forward whose collector said "no mailbox" twice may go. The inbox
            # rule forward was not read this time, so it is kept.
            $users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber'), (Get-OfflineUser -Name 'bob.diaz' -DisplayName 'Bob Diaz'))
            $live = @{ Users = $users; Traces = @(); Mailboxes = @{ 'alex.wilber@contoso.com' = 'smtp:alex.home@webmail.example.com' }
                Rules = @{ 'alex.wilber@contoso.com' = @((Get-OfflineRule -Name 'Copy home' -Target 'alex.copy@webmail.example.com')) } }
            $outputDir = Invoke-OfflineMonitorRun -Name 'exchange-gone-graph-failed' -Scenario $live -ExceptionTarget 'nobody@partner.example.com'
            $gone = @{ Users = $users; Traces = @(); Mailboxes = @{}; Rules = @{}; NoMailbox = @('alex.wilber@contoso.com'); RulesNoMailbox = @('alex.wilber@contoso.com') }
            $null = Invoke-OfflineMonitorRun -Name 'exchange-gone-graph-failed' -Scenario $gone -ExceptionTarget 'nobody@partner.example.com'
            $mixed = @{ Users = $users; Traces = @(); Mailboxes = @{}; Rules = @{}; NoMailbox = @('alex.wilber@contoso.com'); RuleErrors = @('alex.wilber@contoso.com') }
            $null = Invoke-OfflineMonitorRun -Name 'exchange-gone-graph-failed' -Scenario $mixed -ExceptionTarget 'nobody@partner.example.com'
            $findingsThree = @(Get-Content -LiteralPath (Join-Path $outputDir 'forwarding-findings.json') -Raw | ConvertFrom-Json)
            $droppedThree = @(Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') | Where-Object { $_ -like '*Dropped the earlier forwards*' })
            $back = @{ Users = $users; Traces = @(); Mailboxes = $live.Mailboxes; Rules = $live.Rules }
            $null = Invoke-OfflineMonitorRun -Name 'exchange-gone-graph-failed' -Scenario $back -ExceptionTarget 'nobody@partner.example.com'
            $findingsFour = @(Get-Content -LiteralPath (Join-Path $outputDir 'forwarding-findings.json') -Raw | ConvertFrom-Json)
        }

        It 'drops only the mailbox forward, which Exchange has now said twice has no mailbox, and keeps the inbox rule forward' {
            $mixed.ExitCode | Should -Be 2
            @($findingsThree | Where-Object ForwardingType -eq 'MailboxForwarding').Count | Should -Be 0
            $rule = @($findingsThree | Where-Object ForwardingType -eq 'InboxRuleForward')
            $rule.Count | Should -Be 1
            $rule[0].NotRechecked | Should -BeTrue
            $rule[0].KeptBecause | Should -BeExactly 'Failed'
            $droppedThree.Count | Should -Be 1
            $droppedThree[0] | Should -BeLike '*(mailbox forwarding): Get-Mailbox has reported no mailbox for two runs*'
        }

        It 'reports both forwards as read again once the mailbox is back' {
            $back.ExitCode | Should -Be 0
            @($findingsFour | Where-Object { $_.NotRechecked -eq $false -and $_.KeptBecause -eq '' }).Count | Should -Be 2
        }
    }

    Context 'when the previous report holds <Case>' -ForEach @(
        @{ Case = 'null'; Content = 'null'; Folder = 'report-null' }
        @{ Case = 'a number'; Content = '42'; Folder = 'report-number' }
        @{ Case = 'an object that is not a finding'; Content = '{"value":[{"UserPrincipalName":"alex.wilber@contoso.com"}]}'; Folder = 'report-object' }
    ) {
        BeforeAll {
            # The reviewer's s3 scenario G: valid JSON that is not a report must not read as "no findings".
            $users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber'), (Get-OfflineUser -Name 'bob.diaz' -DisplayName 'Bob Diaz'))
            $first = @{ Users = $users; Traces = @(); Rules = @{}; Mailboxes = @{ 'alex.wilber@contoso.com' = 'smtp:alex.home@webmail.example.com' } }
            $outputDir = Invoke-OfflineMonitorRun -Name $Folder -Scenario $first -ExceptionTarget 'nobody@partner.example.com'
            [System.IO.File]::WriteAllText((Join-Path $outputDir 'forwarding-findings.json'), $Content)
            $gone = @{ Users = $users; Traces = @(); Rules = @{}; Mailboxes = @{}; NoMailbox = @('alex.wilber@contoso.com'); RulesNoMailbox = @('alex.wilber@contoso.com') }
            $null = Invoke-OfflineMonitorRun -Name $Folder -Scenario $gone -ExceptionTarget 'nobody@partner.example.com'
            $summary = Get-Content -LiteralPath (Join-Path $outputDir 'summary.json') -Raw | ConvertFrom-Json
        }

        It 'treats it as unreadable: PreviousReportUnreadable, the account counted as a failed read, and exit 2' {
            $gone.ExitCode | Should -Be 2
            $summary.PreviousReportUnreadable | Should -BeTrue
            @($summary.CollectionFailures.MailboxForwarding.UserPrincipalNames) | Should -Be @('alex.wilber@contoso.com')
            $summary.UsersWithoutMailbox.Count | Should -Be 0
        }
    }

    Context 'when the previous report is missing although summary.json shows a run completed' {
        BeforeAll {
            # The reviewer's s4.
            $users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber'), (Get-OfflineUser -Name 'bob.diaz' -DisplayName 'Bob Diaz'))
            $first = @{ Users = $users; Traces = @(); Rules = @{}; Mailboxes = @{ 'alex.wilber@contoso.com' = 'smtp:alex.home@webmail.example.com' } }
            $outputDir = Invoke-OfflineMonitorRun -Name 'report-missing' -Scenario $first -ExceptionTarget 'nobody@partner.example.com'
            Remove-Item -LiteralPath (Join-Path $outputDir 'forwarding-findings.json')
            $gone = @{ Users = $users; Traces = @(); Rules = @{}; Mailboxes = @{}; NoMailbox = @('alex.wilber@contoso.com'); RulesNoMailbox = @('alex.wilber@contoso.com') }
            $null = Invoke-OfflineMonitorRun -Name 'report-missing' -Scenario $gone -ExceptionTarget 'nobody@partner.example.com'
            $summary = Get-Content -LiteralPath (Join-Path $outputDir 'summary.json') -Raw | ConvertFrom-Json
        }

        It 'treats it as unreadable rather than as a first run, and exits 2' {
            $gone.ExitCode | Should -Be 2
            $summary.PreviousReportUnreadable | Should -BeTrue
            @($summary.CollectionFailures.MailboxForwarding.UserPrincipalNames) | Should -Be @('alex.wilber@contoso.com')
            Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') -Raw | Should -BeLike '*forwarding-findings.json is missing*summary.json*'
        }
    }

    Context 'when a scan is stopped part way, as Ctrl+C stops it' {
        BeforeAll {
            # The reviewer's r5: a stopped scan exited 0, so a scheduler took it for a clean run.
            $scenario = @{ Users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber')); Mailboxes = @{}; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com')) }
            $outputDir = Invoke-OfflineMonitorRun -Name 'stopped-scan' -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com'
            $before = Get-OutputSnapshot -Directory $outputDir
            $runRoot = Join-Path $TestDrive 'stopped-scan'

            # The scan runs in its own runspace, which is stopped the way Ctrl+C stops a script: its finally blocks run.
            $signal = [hashtable]::Synchronized(@{ Waiting = $false })
            $runner = [powershell]::Create()
            $null = $runner.AddScript({
                    param($MonitorScript, $RunRoot, $Signal)
                    $global:StopSignal = $Signal
                    function global:Invoke-MgGraphRequest {
                        [CmdletBinding()]
                        param($Method, $Uri)
                        if ($Uri -match '/messageRules$') { return @{ value = @() } }
                        return @{ value = @(@{ id = '00000000-0000-0000-0000-000000000000'; displayName = 'Alex Wilber'; userPrincipalName = 'alex.wilber@contoso.com'; mail = 'alex.wilber@contoso.com'; accountEnabled = $true; userType = 'Member' }) }
                    }
                    function global:Get-Mailbox {
                        [CmdletBinding()]
                        param($Identity)
                        return [pscustomobject]@{ DisplayName = 'Alex Wilber'; UserPrincipalName = $Identity; PrimarySmtpAddress = $Identity; ForwardingAddress = $null; ForwardingSmtpAddress = $null; DeliverToMailboxAndForward = $false }
                    }
                    function global:Get-MessageTraceV2 {
                        [CmdletBinding()]
                        param($StartDate, $EndDate, $ResultSize)
                        $global:StopSignal.Waiting = $true
                        Microsoft.PowerShell.Utility\Start-Sleep -Seconds 60
                    }
                    & $MonitorScript -SettingsPath (Join-Path $RunRoot 'settings.json') -ApprovedExceptionsPath (Join-Path $RunRoot 'exceptions.csv') -SkipConnect 6>$null 3>$null
                }).AddArgument($monitorScript).AddArgument($runRoot).AddArgument($signal)
            $handle = $runner.BeginInvoke()
            $deadline = [datetime]::UtcNow.AddSeconds(60)
            while (-not $signal.Waiting -and -not $handle.IsCompleted -and [datetime]::UtcNow -lt $deadline) { [System.Threading.Thread]::Sleep(20) }
            $runner.Stop()
            $stoppedExitCode = $runner.Runspace.SessionStateProxy.GetVariable('LASTEXITCODE')
            $runner.Dispose()
            $after = Get-OutputSnapshot -Directory $outputDir
        }

        It 'was stopped while it waited on the message trace' {
            $signal.Waiting | Should -BeTrue
            $stoppedExitCode | Should -Be 1
        }

        It 'says so in errors.log' {
            Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') -Raw | Should -BeLike "*Scan did not complete*previous run's files*"
        }

        It 'lets go of the lock and leaves the previous run''s files as they were' {
            $after | Should -BeExactly $before
            Test-ScanLockHeld -Directory $outputDir | Should -BeFalse
        }
    }

    Context 'when a scan is stopped after its files were put in place' {
        BeforeAll {
            $scenario = @{ Users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber')); Mailboxes = @{}; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com')) }
            $outputDir = Invoke-OfflineMonitorRun -Name 'stopped-late' -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com'
            $summaryBefore = [System.IO.File]::ReadAllText((Join-Path $outputDir 'summary.json'))
            $runRoot = Join-Path $TestDrive 'stopped-late'

            # The stop lands on the console output that follows the put-in-place step.
            $signal = [hashtable]::Synchronized(@{ Waiting = $false })
            $runner = [powershell]::Create()
            $null = $runner.AddScript({
                    param($MonitorScript, $RunRoot, $Signal)
                    $global:StopSignal = $Signal
                    function global:Invoke-MgGraphRequest {
                        [CmdletBinding()]
                        param($Method, $Uri)
                        if ($Uri -match '/messageRules$') { return @{ value = @() } }
                        return @{ value = @(@{ id = '00000000-0000-0000-0000-000000000000'; displayName = 'Alex Wilber'; userPrincipalName = 'alex.wilber@contoso.com'; mail = 'alex.wilber@contoso.com'; accountEnabled = $true; userType = 'Member' }) }
                    }
                    function global:Get-Mailbox {
                        [CmdletBinding()]
                        param($Identity)
                        return [pscustomobject]@{ DisplayName = 'Alex Wilber'; UserPrincipalName = $Identity; PrimarySmtpAddress = $Identity; ForwardingAddress = $null; ForwardingSmtpAddress = $null; DeliverToMailboxAndForward = $false }
                    }
                    function global:Get-MessageTraceV2 {
                        [CmdletBinding()]
                        param($StartDate, $EndDate, $ResultSize)
                        return @()
                    }
                    function global:Write-Host {
                        [CmdletBinding()]
                        param([Parameter(Position = 0)][object]$Object, [switch]$NoNewline, [object]$ForegroundColor)
                        if ("$Object" -like 'M365 Forwarding Monitor complete*') {
                            $global:StopSignal.Waiting = $true
                            Microsoft.PowerShell.Utility\Start-Sleep -Seconds 60
                        }
                    }
                    & $MonitorScript -SettingsPath (Join-Path $RunRoot 'settings.json') -ApprovedExceptionsPath (Join-Path $RunRoot 'exceptions.csv') -SkipConnect 3>$null
                }).AddArgument($monitorScript).AddArgument($runRoot).AddArgument($signal)
            $handle = $runner.BeginInvoke()
            $deadline = [datetime]::UtcNow.AddSeconds(60)
            while (-not $signal.Waiting -and -not $handle.IsCompleted -and [datetime]::UtcNow -lt $deadline) { [System.Threading.Thread]::Sleep(20) }
            $runner.Stop()
            $runner.Dispose()
        }

        It 'says in errors.log that this run''s files were put in place' {
            $signal.Waiting | Should -BeTrue
            $log = Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') -Raw
            $log | Should -BeLike "*Scan did not complete*this run's files were put in place*"
            $log | Should -Not -BeLike "*previous run's files were left*"
        }

        It 'leaves this run''s files in place and lets go of the lock' {
            [System.IO.File]::ReadAllText((Join-Path $outputDir 'summary.json')) | Should -Not -BeExactly $summaryBefore
            Test-ScanLockHeld -Directory $outputDir | Should -BeFalse
        }
    }

    Context 'when a scan started in its own pwsh process gets Ctrl+C' {
        BeforeAll {
            # The stubs come from a PowerShell profile in a made-up home folder, so the script itself can be what pwsh is
            # started to run. Global functions in a profile win over any Graph or Exchange module on the machine.
            $fakeHome = Join-Path $TestDrive 'sigint-home'
            New-Item -ItemType Directory -Path (Join-Path $fakeHome '.config/powershell') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $fakeHome '.config/powershell/profile.ps1') -Encoding UTF8 -Value @'
function global:Invoke-MgGraphRequest {
    [CmdletBinding()]
    param($Method, $Uri)
    if ($Uri -match '/messageRules$') { return @{ value = @() } }
    return @{ value = @(@{ id = '00000000-0000-0000-0000-000000000000'; displayName = 'Alex Wilber'; userPrincipalName = 'alex.wilber@contoso.com'; mail = 'alex.wilber@contoso.com'; accountEnabled = $true; userType = 'Member' }) }
}
function global:Get-Mailbox {
    [CmdletBinding()]
    param($Identity)
    return [pscustomobject]@{ DisplayName = 'Alex Wilber'; UserPrincipalName = $Identity; PrimarySmtpAddress = $Identity; ForwardingAddress = $null; ForwardingSmtpAddress = $null; DeliverToMailboxAndForward = $false }
}
function global:Get-MessageTraceV2 {
    [CmdletBinding()]
    param($StartDate, $EndDate, $ResultSize)
    [System.IO.File]::WriteAllText($env:SCAN_TRACE_MARKER, 'reached')
    Microsoft.PowerShell.Utility\Start-Sleep -Seconds 60
}
'@

            function Start-ScanChild {
                param([string[]]$PwshArguments, [string]$Marker)
                # perl puts SIGINT back to its default first, in case the test runner was started with SIGINT ignored.
                if ([System.IO.File]::Exists('/usr/bin/perl')) {
                    $startInfo = [System.Diagnostics.ProcessStartInfo]::new('/usr/bin/perl')
                    foreach ($argument in @('-e', '$SIG{INT} = "DEFAULT"; exec @ARGV', [System.Environment]::ProcessPath) + $PwshArguments) { $startInfo.ArgumentList.Add($argument) }
                }
                else {
                    $startInfo = [System.Diagnostics.ProcessStartInfo]::new([System.Environment]::ProcessPath)
                    foreach ($argument in $PwshArguments) { $startInfo.ArgumentList.Add($argument) }
                }
                $startInfo.Environment['HOME'] = $fakeHome
                $startInfo.Environment['XDG_CONFIG_HOME'] = Join-Path $fakeHome '.config'
                $startInfo.Environment['SCAN_TRACE_MARKER'] = $Marker
                $startInfo.UseShellExecute = $false
                $startInfo.RedirectStandardInput = $true
                $startInfo.RedirectStandardOutput = $true
                $startInfo.RedirectStandardError = $true
                return [System.Diagnostics.Process]::Start($startInfo)
            }

            function Send-CtrlCDuringTrace {
                param([System.Diagnostics.Process]$Child, [string]$Marker)
                $deadline = [datetime]::UtcNow.AddSeconds(60)
                while (-not [System.IO.File]::Exists($Marker) -and -not $Child.HasExited -and [datetime]::UtcNow -lt $deadline) { [System.Threading.Thread]::Sleep(20) }
                [System.Threading.Thread]::Sleep(300)
                & /bin/kill -INT $Child.Id
            }
        }

        It 'exits 1 when pwsh was started with -File to run the script, the exit code a scheduler sees' {
            if ($IsWindows) {
                Set-ItResult -Skipped -Because 'Windows has no portable way to send Ctrl+C to another process'
                return
            }

            $scenario = @{ Users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber')); Mailboxes = @{}; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com')) }
            $outputDir = Invoke-OfflineMonitorRun -Name 'sigint-file' -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com'
            $before = Get-OutputSnapshot -Directory $outputDir
            $runRoot = Join-Path $TestDrive 'sigint-file'
            $marker = Join-Path $TestDrive 'sigint-file-trace-reached'

            $child = Start-ScanChild -Marker $marker -PwshArguments @('-NonInteractive', '-File', $monitorScript,
                '-SettingsPath', (Join-Path $runRoot 'settings.json'), '-ApprovedExceptionsPath', (Join-Path $runRoot 'exceptions.csv'), '-SkipConnect')
            Send-CtrlCDuringTrace -Child $child -Marker $marker
            $exited = $child.WaitForExit(60000)
            $exitCode = if ($exited) { $child.ExitCode } else { $child.Kill(); 'still running' }
            $child.Dispose()

            [System.IO.File]::Exists($marker) | Should -BeTrue
            $exitCode | Should -Be 1
            Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') -Raw | Should -BeLike "*Scan did not complete*previous run's files*"
            Get-OutputSnapshot -Directory $outputDir | Should -BeExactly $before
            Test-ScanLockHeld -Directory $outputDir | Should -BeFalse
        }

        It 'leaves the session running when the script was called from a pwsh session, as an administrator runs it' {
            if ($IsWindows) {
                Set-ItResult -Skipped -Because 'Windows has no portable way to send Ctrl+C to another process'
                return
            }

            $scenario = @{ Users = @((Get-OfflineUser -Name 'alex.wilber' -DisplayName 'Alex Wilber')); Mailboxes = @{}; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'alex.wilber@contoso.com' -Recipient 'a@vendor.example.com')) }
            $outputDir = Invoke-OfflineMonitorRun -Name 'sigint-command' -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com'
            $runRoot = Join-Path $TestDrive 'sigint-command'
            $marker = Join-Path $TestDrive 'sigint-command-trace-reached'
            $call = "& '$monitorScript' -SettingsPath '$(Join-Path $runRoot 'settings.json')' -ApprovedExceptionsPath '$(Join-Path $runRoot 'exceptions.csv')' -SkipConnect"

            $child = Start-ScanChild -Marker $marker -PwshArguments @('-NoExit', '-Command', $call)
            Send-CtrlCDuringTrace -Child $child -Marker $marker
            [System.Threading.Thread]::Sleep(3000)
            $runningAfterCtrlC = -not $child.HasExited
            if ($runningAfterCtrlC) {
                # The session is still at its prompt; ask it to finish with a code of its own.
                $child.StandardInput.WriteLine('exit 7')
                $child.StandardInput.Close()
            }
            $exited = $child.WaitForExit(30000)
            $exitCode = if ($exited) { $child.ExitCode } else { $child.Kill(); 'still running' }
            $child.Dispose()

            [System.IO.File]::Exists($marker) | Should -BeTrue
            $runningAfterCtrlC | Should -BeTrue
            $exitCode | Should -Be 7
            Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') -Raw | Should -BeLike '*Scan did not complete*'
        }
    }

    Context 'when an interrupted run of an older version left the history only in its temporary file' {
        BeforeAll {
            # The reviewer's scenario V: the older version deleted the history and was killed before it renamed the new one in.
            $seed = {
                param($Dir)
                $records = foreach ($day in 1..30) {
                    [pscustomobject]@{ Date = (Get-Date).AddDays(-$day).ToString('yyyy-MM-dd'); SenderAddress = 'bob.diaz@contoso.com'; ExternalSentCount = 4
                        UniqueExternalRecipientCount = 1; TopExternalDomains = @('vendor.example.com:4'); AfterHoursCount = 0; DetectedAt = (Get-Date).AddDays(-$day).ToString('o') }
                }
                $orphan = Join-Path $Dir ('.outbound-baseline-history.json.{0}.tmp' -f [guid]::NewGuid().ToString('N'))
                [System.IO.File]::WriteAllText($orphan, (ConvertTo-Json -InputObject @($records) -Depth 4))
                [System.IO.File]::SetLastWriteTimeUtc($orphan, [datetime]::UtcNow.AddHours(-1))
                $otherOrphan = Join-Path $Dir ('.summary.json.{0}.tmp' -f [guid]::NewGuid().ToString('N'))
                [System.IO.File]::WriteAllText($otherOrphan, '{"GeneratedAt":')
                [System.IO.File]::SetLastWriteTimeUtc($otherOrphan, [datetime]::UtcNow.AddHours(-1))
            }
            $scenario = @{ Users = @((Get-OfflineUser -Name 'bob.diaz' -DisplayName 'Bob Diaz')); Mailboxes = @{}; Rules = @{}
                Traces = @((Get-OfflineTrace -SenderAddress 'bob.diaz@contoso.com' -Recipient 'a@vendor.example.com')) }
            $outputDir = Invoke-OfflineMonitorRun -Name 'orphan-history' -Scenario $scenario -ExceptionTarget 'nobody@partner.example.com' -Seed $seed
        }

        It 'makes the temporary file the history again and says so in errors.log' {
            $scenario.ExitCode | Should -Be 0
            @(Get-Content -LiteralPath (Join-Path $outputDir 'outbound-baseline-history.json') -Raw | ConvertFrom-Json).Count | Should -Be 31
            Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') -Raw | Should -BeLike '*put back outbound-baseline-history.json from .outbound-baseline-history.json.*.tmp*'
        }

        It 'compares this run with that history' {
            @(Get-Content -LiteralPath (Join-Path $outputDir 'outbound-metadata-counts.json') -Raw | ConvertFrom-Json)[0].BaselineSampleCount | Should -Be 30
        }

        It 'still removes any other leftover' {
            @(Get-ChildItem -LiteralPath $outputDir -Force | Where-Object Name -match '\.(tmp|prev)$').Count | Should -Be 0
            Get-Content -LiteralPath (Join-Path $outputDir 'errors.log') -Raw | Should -BeLike '*removed 1 leftover file(s): .summary.json.*'
        }
    }
}

Describe 'Putting the staged output files in place' {
    BeforeAll {
        $monitorScript = Join-Path (Join-Path $PSScriptRoot '..') 'src/Invoke-ForwardingMonitor.ps1'
        $publishFunctions = @('Remove-M365File', 'New-M365RunId', 'Move-M365File', 'Test-M365TransientFileError', 'Move-M365FileWithRetry',
            'Add-M365StagedFile', 'Publish-M365StagedFile', 'Clear-M365StagedFile', 'Read-M365JsonFile', 'Test-M365IsoTimestamp', 'Read-M365HistoryFile',
            'Repair-M365OutputFolder')
        foreach ($functionName in $publishFunctions) {
            . ([scriptblock]::Create((Get-FunctionTextFromFile -Path $monitorScript -Name $functionName)))
        }

        # The eight files a run writes, in the order the script stages them.
        $leaves = @('forwarding-findings.json', 'outbound-metadata-counts.json', 'summary.json', 'forwarding-findings.csv',
            'outbound-metadata-counts.csv', 'summary.csv', 'outbound-baseline-history.json', 'dashboard.html')

        function New-TestFolder {
            param([string]$Name, [switch]$Empty)
            $folder = Join-Path $TestDrive $Name
            New-Item -ItemType Directory -Path $folder -Force | Out-Null
            if (-not $Empty) {
                foreach ($leaf in $leaves) { [System.IO.File]::WriteAllText((Join-Path $folder $leaf), "previous run: $leaf") }
            }
            return $folder
        }

        function New-TestStagedSet {
            param([string]$Folder, [string]$Version = 'this run')
            $runId = New-M365RunId -StartedUtc ([datetime]::UtcNow)
            $staged = [System.Collections.Generic.List[object]]::new()
            foreach ($leaf in $leaves) {
                $content = "${Version}: $leaf"
                Add-M365StagedFile -Staged $staged -RunId $runId -Path (Join-Path $Folder $leaf) -Write ({ param($TempPath) [System.IO.File]::WriteAllText($TempPath, $content) }.GetNewClosure())
            }
            return , $staged
        }

        function Get-FolderState {
            param([string]$Folder)
            # Every entry, hidden ones included: a file by the SHA-256 of its bytes, a folder by its name alone.
            $state = [ordered]@{}
            foreach ($entry in Get-ChildItem -LiteralPath $Folder -Force | Sort-Object Name) {
                $state[$entry.Name] = if ($entry.PSIsContainer) { 'folder' } else { (Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256).Hash }
            }
            return ($state | ConvertTo-Json -Compress)
        }
    }

    It 'replaces every file in the order staged, dashboard last, and leaves no temporary file or backup' {
        $folder = New-TestFolder -Name 'in-order'
        $staged = New-TestStagedSet -Folder $folder

        $messages = @(Publish-M365StagedFile -Staged $staged -Verbose 4>&1 | ForEach-Object { $_.Message })

        $messages | Should -Be @($leaves | ForEach-Object { "Put $_ in place." })
        foreach ($leaf in $leaves) {
            [System.IO.File]::ReadAllText((Join-Path $folder $leaf)) | Should -BeExactly "this run: $leaf"
        }
        @(Get-ChildItem -LiteralPath $folder -Force).Count | Should -Be 8
    }

    It 'stops before any file changes when a folder sits at file <Position> of 8' -ForEach @(
        @{ Position = 2 }
        @{ Position = 5 }
        @{ Position = 8 }
    ) {
        $folder = New-TestFolder -Name "folder-at-$Position"
        $leaf = $leaves[$Position - 1]
        Remove-Item -LiteralPath (Join-Path $folder $leaf)
        New-Item -ItemType Directory -Path (Join-Path $folder $leaf) | Out-Null
        $before = Get-FolderState -Folder $folder
        $staged = New-TestStagedSet -Folder $folder

        { Publish-M365StagedFile -Staged $staged } | Should -Throw "*$leaf*not a plain file*No output files were changed*"
        Get-FolderState -Folder $folder | Should -BeExactly $before
    }

    It 'stops before any file changes when a link to a folder sits where dashboard.html goes' {
        $folder = New-TestFolder -Name 'link-in-the-way'
        $elsewhere = Join-Path $TestDrive 'link-target'
        New-Item -ItemType Directory -Path $elsewhere -Force | Out-Null
        Remove-Item -LiteralPath (Join-Path $folder 'dashboard.html')
        New-Item -ItemType SymbolicLink -Path (Join-Path $folder 'dashboard.html') -Target $elsewhere | Out-Null
        $before = Get-FolderState -Folder $folder
        $staged = New-TestStagedSet -Folder $folder

        { Publish-M365StagedFile -Staged $staged } | Should -Throw '*dashboard.html*not a plain file*'
        Get-FolderState -Folder $folder | Should -BeExactly $before
        @(Get-ChildItem -LiteralPath $elsewhere -Force).Count | Should -Be 0
    }

    It 'puts back every file already replaced when the swap of file <Position> of 8 fails' -ForEach @(
        @{ Position = 2 }
        @{ Position = 5 }
        @{ Position = 8 }
    ) {
        $folder = New-TestFolder -Name "swap-fails-at-$Position"
        $before = Get-FolderState -Folder $folder
        $staged = New-TestStagedSet -Folder $folder
        # The temporary file of this one vanishes after staging, so its swap fails after the ones before it were made.
        Remove-Item -LiteralPath $staged[$Position - 1].TempPath -Force

        $thrown = $null
        try { Publish-M365StagedFile -Staged $staged } catch { $thrown = $_ }

        $thrown.Exception.Message | Should -BeLike "Could not put *$($leaves[$Position - 1]) in place.*The previous run's files were put back*"
        Get-FolderState -Folder $folder | Should -BeExactly $before
    }

    It 'tries a move three times, two seconds apart, then puts everything back, when another program holds the file: <Name>' -ForEach @(
        @{ Name = 'a Windows sharing violation'; Message = 'The process cannot access the file because it is being used by another process.'; HResult = -2147024864 }
        @{ Name = 'a Windows lock violation'; Message = 'The process cannot access the file because another process has locked a portion of the file.'; HResult = -2147024863 }
        @{ Name = 'EBUSY on Linux or macOS'; Message = 'Resource busy'; HResult = 16 }
        @{ Name = 'ETXTBSY on Linux or macOS'; Message = 'Text file busy'; HResult = 26 }
    ) {
        Mock Start-Sleep {}
        $calls = @{ Count = 0 }
        Mock Move-M365File { $calls.Count++; throw [System.IO.IOException]::new($Message, $HResult) } -ParameterFilter { $Source -like '*.summary.json.*.tmp' }
        $folder = New-TestFolder -Name "held-$HResult"
        $before = Get-FolderState -Folder $folder
        $staged = New-TestStagedSet -Folder $folder

        { Publish-M365StagedFile -Staged $staged } | Should -Throw "*summary.json in place*The previous run's files were put back*"
        $calls.Count | Should -Be 3
        Should -Invoke Start-Sleep -Times 2 -Exactly -ParameterFilter { $Seconds -eq 2 }
        Get-FolderState -Folder $folder | Should -BeExactly $before
    }

    It 'tries a move that fails with access denied three times on Windows, where an indexer or OneDrive holds files that way, and once elsewhere' {
        Mock Start-Sleep {}
        $calls = @{ Count = 0 }
        Mock Move-M365File { $calls.Count++; throw [System.UnauthorizedAccessException]::new('Access to the path is denied.') } -ParameterFilter { $Source -like '*.summary.json.*.tmp' }
        $folder = New-TestFolder -Name 'access-denied'
        $before = Get-FolderState -Folder $folder
        $staged = New-TestStagedSet -Folder $folder

        { Publish-M365StagedFile -Staged $staged } | Should -Throw "*summary.json in place*The previous run's files were put back*"
        $calls.Count | Should -Be $(if ($IsWindows) { 3 } else { 1 })
        Get-FolderState -Folder $folder | Should -BeExactly $before
    }

    It 'goes by the error code, not the message: an error that only says busy is not tried again' {
        Mock Start-Sleep {}
        $calls = @{ Count = 0 }
        Mock Move-M365File { $calls.Count++; throw [System.IO.IOException]::new('Could not write to /srv/busy-reports/summary.json.') } -ParameterFilter { $Source -like '*.summary.json.*.tmp' }
        $folder = New-TestFolder -Name 'busy-in-message'
        $staged = New-TestStagedSet -Folder $folder

        { Publish-M365StagedFile -Staged $staged } | Should -Throw '*summary.json in place*'
        $calls.Count | Should -Be 1
    }

    It 'does not try again a move that fails with <Kind>, which waiting does not fix' -ForEach @(
        @{ Kind = 'System.IO.IOException' }
        @{ Kind = 'System.IO.PathTooLongException' }
        @{ Kind = 'System.IO.DirectoryNotFoundException' }
        @{ Kind = 'System.IO.DriveNotFoundException' }
        @{ Kind = 'System.IO.FileNotFoundException' }
    ) {
        Mock Start-Sleep {}
        $calls = @{ Count = 0 }
        Mock Move-M365File { $calls.Count++; throw (New-Object -TypeName $Kind -ArgumentList 'It did not work.') } -ParameterFilter { $Source -like '*.summary.json.*.tmp' }
        $folder = New-TestFolder -Name "not-held-$($Kind.Split('.')[-1])"
        $before = Get-FolderState -Folder $folder
        $staged = New-TestStagedSet -Folder $folder

        { Publish-M365StagedFile -Staged $staged } | Should -Throw "*summary.json in place*The previous run's files were put back*"
        $calls.Count | Should -Be 1
        Should -Invoke Start-Sleep -Times 0 -Exactly
        Get-FolderState -Folder $folder | Should -BeExactly $before
    }

    It 'goes on when a held file is let go before the third try' {
        Mock Start-Sleep {}
        $calls = @{ Count = 0 }
        Mock Move-M365File {
            $calls.Count++
            if ($calls.Count -lt 3) { throw [System.IO.IOException]::new('The process cannot access the file because it is being used by another process.', -2147024864) }
            [System.IO.File]::Move($Source, $Destination, $true)
        } -ParameterFilter { $Source -like '*.dashboard.html.*.tmp' }
        $folder = New-TestFolder -Name 'let-go'
        $staged = New-TestStagedSet -Folder $folder

        Publish-M365StagedFile -Staged $staged

        $calls.Count | Should -Be 3
        foreach ($leaf in $leaves) {
            [System.IO.File]::ReadAllText((Join-Path $folder $leaf)) | Should -BeExactly "this run: $leaf"
        }
        @(Get-ChildItem -LiteralPath $folder -Force).Count | Should -Be 8
    }

    It 'does not wait and try again when the temporary file is simply not there' {
        Mock Start-Sleep {}
        $folder = New-TestFolder -Name 'gone-temp'
        $staged = New-TestStagedSet -Folder $folder
        Remove-Item -LiteralPath $staged[2].TempPath -Force

        { Publish-M365StagedFile -Staged $staged } | Should -Throw '*summary.json in place*'
        Should -Invoke Start-Sleep -Times 0 -Exactly
    }

    It 'puts back a file whose move had just finished when the scan is stopped at that moment' {
        $folder = New-TestFolder -Name 'stopped'
        $before = Get-FolderState -Folder $folder
        $definitions = ($publishFunctions | ForEach-Object { Get-FunctionTextFromFile -Path $monitorScript -Name $_ }) -join [Environment]::NewLine
        $signal = [hashtable]::Synchronized(@{ Moved = $false })
        $runner = [powershell]::Create()
        $null = $runner.AddScript("param(`$Folder, `$Leaves, `$Signal)`n$definitions`n" + {
                # The real move, then a pause right after summary.json is in place: where a Ctrl+C lands between the
                # move and the next statement.
                function Move-M365File {
                    param($Source, $Destination)
                    [System.IO.File]::Move($Source, $Destination, $true)
                    if ($Source -like '*.summary.json.*.tmp') {
                        $Signal.Moved = $true
                        Start-Sleep -Seconds 60
                    }
                }
                $runId = New-M365RunId -StartedUtc ([datetime]::UtcNow)
                $staged = [System.Collections.Generic.List[object]]::new()
                foreach ($leaf in $Leaves) {
                    $content = "this run: $leaf"
                    Add-M365StagedFile -Staged $staged -RunId $runId -Path (Join-Path $Folder $leaf) -Write ({ param($TempPath) [System.IO.File]::WriteAllText($TempPath, $content) }.GetNewClosure())
                }
                Publish-M365StagedFile -Staged $staged
            }.ToString()).AddArgument($folder).AddArgument($leaves).AddArgument($signal)
        $handle = $runner.BeginInvoke()
        $deadline = [datetime]::UtcNow.AddSeconds(30)
        while (-not $signal.Moved -and [datetime]::UtcNow -lt $deadline) { [System.Threading.Thread]::Sleep(10) }
        $runner.Stop()
        $runner.Dispose()

        $signal.Moved | Should -BeTrue
        $handle.IsCompleted | Should -BeTrue
        Get-FolderState -Folder $folder | Should -BeExactly $before
    }

    It 'keeps the backup of a file it could not put back, names it, and lists it in .keep so later cleanups leave it' {
        Mock Start-Sleep {}
        # The swap of summary.json fails, and so does putting forwarding-findings.json back.
        Mock Move-M365File { throw [System.IO.IOException]::new('The file is in use by another program.') } -ParameterFilter {
            $Source -like '*.summary.json.*.tmp' -or $Source -like '*.forwarding-findings.json.*.prev'
        }
        $folder = New-TestFolder -Name 'not-put-back'
        $staged = New-TestStagedSet -Folder $folder
        $backupName = Split-Path -Leaf $staged[0].BackupPath

        $thrown = $null
        try { Publish-M365StagedFile -Staged $staged } catch { $thrown = $_ }

        $thrown.Exception.Message | Should -BeLike "*summary.json in place*forwarding-findings.json could not be put back*$backupName*.keep*"
        $thrown.Exception.Message | Should -Not -BeLike '*copy it out*'
        [System.IO.File]::ReadAllText($staged[0].BackupPath) | Should -BeExactly 'previous run: forwarding-findings.json'
        [System.IO.File]::ReadAllText((Join-Path $folder 'outbound-metadata-counts.json')) | Should -BeExactly 'previous run: outbound-metadata-counts.json'
        @([System.IO.File]::ReadAllLines((Join-Path $folder '.keep'))) | Should -Contain $backupName

        $later = [datetime]::UtcNow.AddMinutes(1)
        $result = Repair-M365OutputFolder -OutputPath $folder -RunId (New-M365RunId -StartedUtc $later) -RunStartedUtc $later

        [System.IO.File]::Exists($staged[0].BackupPath) | Should -BeTrue
        @($result.Removed) | Should -Not -Contain $backupName
        Get-Content -LiteralPath (Join-Path $folder 'errors.log') -Raw | Should -BeLike "*kept $backupName*.keep*"
    }

    It 'says plainly when a file this run created could not be removed again, with no backup to point to' {
        Mock Remove-M365File { $false } -ParameterFilter { $Path -match '[\\/]forwarding-findings\.json$' }
        $folder = New-TestFolder -Name 'created-not-removed' -Empty
        $staged = New-TestStagedSet -Folder $folder
        Remove-Item -LiteralPath $staged[2].TempPath -Force

        $thrown = $null
        try { Publish-M365StagedFile -Staged $staged } catch { $thrown = $_ }

        $thrown.Exception.Message | Should -BeLike '*forwarding-findings.json was created by this run and could not be removed*'
        $thrown.Exception.Message | Should -Not -BeLike '*.prev*'
        Join-Path $folder '.keep' | Should -Not -Exist
    }

    It 'removes again a file it created where there was none when a later swap fails' {
        $folder = New-TestFolder -Name 'first-run-fails' -Empty
        $staged = New-TestStagedSet -Folder $folder
        Remove-Item -LiteralPath $staged[4].TempPath -Force

        { Publish-M365StagedFile -Staged $staged } | Should -Throw "*$($leaves[4]) in place*The previous run's files were put back*"
        @(Get-ChildItem -LiteralPath $folder -Force).Count | Should -Be 0
    }

    It 'never lets a file go missing while it is replaced' {
        $folder = New-TestFolder -Name 'watched'
        $paths = [string[]]@($leaves | ForEach-Object { Join-Path $folder $_ })
        $watch = [hashtable]::Synchronized(@{ Stop = $false; Checks = 0; Missing = 0 })
        $poller = [powershell]::Create()
        $null = $poller.AddScript({
                param($Paths, $Watch)
                while (-not $Watch.Stop) {
                    foreach ($path in $Paths) {
                        $Watch.Checks++
                        if (-not [System.IO.File]::Exists($path)) { $Watch.Missing++ }
                    }
                }
            }).AddArgument($paths).AddArgument($watch)
        $handle = $poller.BeginInvoke()
        try {
            $deadline = [datetime]::UtcNow.AddSeconds(30)
            while ($watch.Checks -eq 0 -and [datetime]::UtcNow -lt $deadline) { [System.Threading.Thread]::Sleep(1) }
            for ($round = 1; $round -le 100; $round++) {
                Publish-M365StagedFile -Staged (New-TestStagedSet -Folder $folder -Version "round $round")
            }
        }
        finally {
            $watch.Stop = $true
            $null = $poller.EndInvoke($handle)
            $poller.Dispose()
        }

        $watch.Checks | Should -BeGreaterThan 0
        $watch.Missing | Should -Be 0
    }

    It 'cleans up after an interrupted run: puts back a backup whose file is missing, removes the other leftovers and leaves the rest alone' {
        $folder = New-TestFolder -Name 'interrupted'
        $runStartedUtc = [datetime]::UtcNow
        $thisRun = New-M365RunId -StartedUtc $runStartedUtc
        $earlier = New-M365RunId -StartedUtc $runStartedUtc.AddMinutes(-30)
        $later = New-M365RunId -StartedUtc $runStartedUtc.AddMinutes(5)
        $olderVersionTemp = '.summary.csv.0123456789abcdef0123456789abcdef.tmp'
        Remove-Item -LiteralPath (Join-Path $folder 'summary.json')
        $files = [ordered]@{
            ".summary.json.$earlier.prev"   = 'summary from the run before'
            ".dashboard.html.$earlier.prev" = 'dashboard from the run before'
            ".summary.csv.$earlier.tmp"     = 'half written'
            $olderVersionTemp               = 'left by an older version'
            ".dashboard.html.$thisRun.tmp"  = 'this run'
            ".dashboard.html.$later.tmp"    = 'a run that started later'
            '.scan.lock'                    = 'ProcessId: 4242'
            'notes.tmp'                     = 'not written by the scan'
        }
        foreach ($name in $files.Keys) { [System.IO.File]::WriteAllText((Join-Path $folder $name), $files[$name]) }
        [System.IO.File]::SetLastWriteTimeUtc((Join-Path $folder $olderVersionTemp), $runStartedUtc.AddHours(-2))

        $result = Repair-M365OutputFolder -OutputPath $folder -RunId $thisRun -RunStartedUtc $runStartedUtc

        [System.IO.File]::ReadAllText((Join-Path $folder 'summary.json')) | Should -BeExactly 'summary from the run before'
        [System.IO.File]::ReadAllText((Join-Path $folder 'dashboard.html')) | Should -BeExactly 'previous run: dashboard.html'
        @($result.Restored) | Should -Be @(".summary.json.$earlier.prev")
        @($result.Removed | Sort-Object) | Should -Be @(@(".dashboard.html.$earlier.prev", ".summary.csv.$earlier.tmp", $olderVersionTemp) | Sort-Object)
        foreach ($name in ".dashboard.html.$thisRun.tmp", ".dashboard.html.$later.tmp", '.scan.lock', 'notes.tmp') {
            Join-Path $folder $name | Should -Exist
        }
        $log = Get-Content -LiteralPath (Join-Path $folder 'errors.log') -Raw
        $log | Should -BeLike "*put back summary.json from .summary.json.$earlier.prev*"
        $log | Should -BeLike '*removed 3 leftover file(s)*'
    }

    It 'makes a whole temporary history the history when the history is missing, and removes one that is not whole' {
        $runStartedUtc = [datetime]::UtcNow
        $earlier = New-M365RunId -StartedUtc $runStartedUtc.AddMinutes(-30)
        $history = '[{"SenderAddress":"a@contoso.com","ExternalSentCount":5,"DetectedAt":"2026-01-05T09:00:00.0000000Z"}]'

        $whole = New-TestFolder -Name 'orphan-whole'
        Remove-Item -LiteralPath (Join-Path $whole 'outbound-baseline-history.json')
        [System.IO.File]::WriteAllText((Join-Path $whole ".outbound-baseline-history.json.$earlier.tmp"), $history)
        $result = Repair-M365OutputFolder -OutputPath $whole -RunId (New-M365RunId -StartedUtc $runStartedUtc) -RunStartedUtc $runStartedUtc

        [System.IO.File]::ReadAllText((Join-Path $whole 'outbound-baseline-history.json')) | Should -BeExactly $history
        @($result.Restored) | Should -Be @(".outbound-baseline-history.json.$earlier.tmp")

        $cut = New-TestFolder -Name 'orphan-cut'
        Remove-Item -LiteralPath (Join-Path $cut 'outbound-baseline-history.json')
        [System.IO.File]::WriteAllText((Join-Path $cut ".outbound-baseline-history.json.$earlier.tmp"), $history.Substring(0, 40))
        $result = Repair-M365OutputFolder -OutputPath $cut -RunId (New-M365RunId -StartedUtc $runStartedUtc) -RunStartedUtc $runStartedUtc

        Join-Path $cut 'outbound-baseline-history.json' | Should -Not -Exist
        @($result.Removed) | Should -Be @(".outbound-baseline-history.json.$earlier.tmp")
    }
}

Describe 'Releasing the scan lock' {
    BeforeAll {
        $monitorScript = Join-Path (Join-Path $PSScriptRoot '..') 'src/Invoke-ForwardingMonitor.ps1'
        foreach ($functionName in 'Remove-M365File', 'Test-M365LockConflict', 'ConvertFrom-M365ScanLockText', 'Enter-M365ScanLock', 'Exit-M365ScanLock', 'Test-M365ScriptIsEntryPoint') {
            . ([scriptblock]::Create((Get-FunctionTextFromFile -Path $monitorScript -Name $functionName)))
        }

        function New-LockFolder {
            $folder = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $folder | Out-Null
            return $folder
        }
    }

    It 'holds the lock for the run, writes the process id, the computer name and the start time into it, and empties it on the way out' {
        $folder = New-LockFolder
        $lock = Enter-M365ScanLock -OutputPath $folder -StartedUtc ([datetime]::UtcNow)
        $heldWhileRunning = $false
        try {
            ([System.IO.FileStream]::new((Join-Path $folder '.scan.lock'), [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)).Dispose()
        }
        catch {
            $heldWhileRunning = $true
        }
        Exit-M365ScanLock -Lock $lock

        $heldWhileRunning | Should -BeTrue
        $lock.Text | Should -BeLike "*ProcessId: $PID*"
        $lock.Text | Should -BeLike "*MachineName: $([System.Environment]::MachineName)*"
        $lock.Text | Should -BeLike '*StartedAt: 2*'
        [System.IO.File]::ReadAllText((Join-Path $folder '.scan.lock')) | Should -BeExactly ''
        Join-Path $folder 'errors.log' | Should -Not -Exist
    }

    It 'refuses while another handle holds the lock' {
        $folder = New-LockFolder
        $other = [System.IO.FileStream]::new((Join-Path $folder '.scan.lock'), [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            { Enter-M365ScanLock -OutputPath $folder -StartedUtc ([datetime]::UtcNow) } | Should -Throw "Another scan is running in $folder (started *"
        }
        finally {
            $other.Dispose()
        }
    }

    It 'takes over at once a lock file this computer wrote and no process holds, and logs what the file said' {
        $folder = New-LockFolder
        $fiveMinutesAgo = [datetime]::UtcNow.AddMinutes(-5).ToString('o', [cultureinfo]::InvariantCulture)
        [System.IO.File]::WriteAllText((Join-Path $folder '.scan.lock'), "ProcessId: 4242`nMachineName: $([System.Environment]::MachineName)`nStartedAt: $fiveMinutesAgo`n")

        $lock = Enter-M365ScanLock -OutputPath $folder -StartedUtc ([datetime]::UtcNow)
        Exit-M365ScanLock -Lock $lock

        Get-Content -LiteralPath (Join-Path $folder 'errors.log') -Raw | Should -BeLike "*Took over the scan lock*process 4242 on $([System.Environment]::MachineName)*no longer running*"
    }

    It 'respects a lock another computer wrote less than six hours ago, and leaves it as it was' {
        $folder = New-LockFolder
        $lockText = "ProcessId: 4242`nMachineName: other-host.example.com`nStartedAt: $([datetime]::UtcNow.AddHours(-5).ToString('o', [cultureinfo]::InvariantCulture))`n"
        [System.IO.File]::WriteAllText((Join-Path $folder '.scan.lock'), $lockText)

        { Enter-M365ScanLock -OutputPath $folder -StartedUtc ([datetime]::UtcNow) } | Should -Throw "Another scan is running in $folder (started *) on other-host.example.com.*"

        [System.IO.File]::ReadAllText((Join-Path $folder '.scan.lock')) | Should -BeExactly $lockText
        Join-Path $folder 'errors.log' | Should -Not -Exist
    }

    It 'refuses to run on Linux and macOS when DOTNET_SYSTEM_IO_DISABLEFILELOCKING turns file locking off' {
        $folder = New-LockFolder
        $saved = [System.Environment]::GetEnvironmentVariable('DOTNET_SYSTEM_IO_DISABLEFILELOCKING')
        try {
            [System.Environment]::SetEnvironmentVariable('DOTNET_SYSTEM_IO_DISABLEFILELOCKING', '1')
            if ($IsWindows) {
                # .NET reads the setting on Linux and macOS only; Windows always enforces the lock.
                $lock = Enter-M365ScanLock -OutputPath $folder -StartedUtc ([datetime]::UtcNow)
                Exit-M365ScanLock -Lock $lock
            }
            else {
                { Enter-M365ScanLock -OutputPath $folder -StartedUtc ([datetime]::UtcNow) } | Should -Throw '*DOTNET_SYSTEM_IO_DISABLEFILELOCKING*'
                Join-Path $folder '.scan.lock' | Should -Not -Exist
            }
        }
        finally {
            [System.Environment]::SetEnvironmentVariable('DOTNET_SYSTEM_IO_DISABLEFILELOCKING', $saved)
        }
    }

    It 'reads errno <Code> as a held lock only on <HeldOn>' -ForEach @(
        @{ Code = 11; HeldOn = 'Linux'; Name = 'EWOULDBLOCK on Linux, EDEADLK on macOS (iCloud returns it for a file it cannot download)' }
        @{ Code = 35; HeldOn = 'macOS'; Name = 'EWOULDBLOCK on macOS' }
    ) {
        $record = [System.Management.Automation.ErrorRecord]::new([System.IO.IOException]::new($Name, $Code), 'OpenFailed', [System.Management.Automation.ErrorCategory]::OpenError, $null)
        $expected = if ($HeldOn -eq 'Linux') { [bool]$IsLinux } else { [bool]$IsMacOS }

        Test-M365LockConflict -ErrorRecord $record | Should -Be $expected
    }

    It 'tells whether pwsh was started to run this script or the container entrypoint: <Case>' -ForEach @(
        @{ Case = '-File with the script'; Arguments = @('-NoProfile', '-File', '<script>', '-SkipConnect'); Expected = $true }
        @{ Case = '-f with the script'; Arguments = @('-NoProfile', '-f', '<script>'); Expected = $true }
        @{ Case = '-File with the entrypoint'; Arguments = @('-NoLogo', '-NoProfile', '-File', '<entrypoint>'); Expected = $true }
        @{ Case = '-Command that calls the script'; Arguments = @('-NoProfile', '-Command', "& '<script>'"); Expected = $false }
        @{ Case = '-File with another script'; Arguments = @('-NoProfile', '-File', '<other>'); Expected = $false }
        @{ Case = 'no file at all'; Arguments = @('-NoProfile'); Expected = $false }
    ) {
        $script = Join-Path $TestDrive 'app/src/Invoke-ForwardingMonitor.ps1'
        $entrypoint = Join-Path $TestDrive 'app/docker-entrypoint.ps1'
        $commandLine = @('/opt/powershell/pwsh.dll') + @($Arguments | ForEach-Object {
                $_.Replace('<script>', $script).Replace('<entrypoint>', $entrypoint).Replace('<other>', (Join-Path $TestDrive 'app/other.ps1'))
            })

        Test-M365ScriptIsEntryPoint -CommandLine $commandLine -ScriptPath @($script, $entrypoint) | Should -Be $Expected
    }

    It 'says so in errors.log when it cannot empty the lock on the way out' {
        $folder = New-LockFolder
        $lock = Enter-M365ScanLock -OutputPath $folder -StartedUtc ([datetime]::UtcNow)
        $lock.Stream.Dispose()

        Exit-M365ScanLock -Lock $lock 3>$null

        Get-Content -LiteralPath (Join-Path $folder 'errors.log') -Raw | Should -BeLike '*Could not empty the scan lock*'
    }
}

Describe 'Putting files in place while the writer is killed at random moments' {
    BeforeAll {
        $monitorScript = Join-Path (Join-Path $PSScriptRoot '..') 'src/Invoke-ForwardingMonitor.ps1'
        foreach ($functionName in 'Remove-M365File', 'New-M365RunId', 'Read-M365JsonFile', 'Test-M365IsoTimestamp', 'Read-M365HistoryFile', 'Repair-M365OutputFolder') {
            . ([scriptblock]::Create((Get-FunctionTextFromFile -Path $monitorScript -Name $functionName)))
        }

        $leaves = @('forwarding-findings.json', 'outbound-metadata-counts.json', 'summary.json', 'forwarding-findings.csv',
            'outbound-metadata-counts.csv', 'summary.csv', 'outbound-baseline-history.json', 'dashboard.html')
        $outputDir = Join-Path $TestDrive 'killed'
        New-Item -ItemType Directory -Path $outputDir | Out-Null
        $padding = 'x' * 65536
        $expected = @{}
        foreach ($leaf in $leaves) {
            $expected[$leaf] = @("$leaf version A`n$padding", "$leaf version B`n$padding")
            [System.IO.File]::WriteAllText((Join-Path $outputDir $leaf), $expected[$leaf][0])
        }

        # The child loads the real Add-M365StagedFile and Publish-M365StagedFile from the script and puts version B,
        # then A, then B again in place, as fast as it can, until it is killed.
        $childScript = Join-Path $TestDrive 'publish-until-killed.ps1'
        Set-Content -LiteralPath $childScript -Encoding UTF8 -Value @'
param([string]$MonitorScript, [string]$OutputDir, [string]$ReadyPath)
$ErrorActionPreference = 'Stop'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($MonitorScript, [ref]$null, [ref]$null)
foreach ($name in 'Remove-M365File', 'New-M365RunId', 'Move-M365File', 'Test-M365TransientFileError', 'Move-M365FileWithRetry', 'Add-M365StagedFile', 'Publish-M365StagedFile') {
    $definition = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    . ([scriptblock]::Create($definition.Extent.Text))
}
$leaves = @('forwarding-findings.json', 'outbound-metadata-counts.json', 'summary.json', 'forwarding-findings.csv',
    'outbound-metadata-counts.csv', 'summary.csv', 'outbound-baseline-history.json', 'dashboard.html')
$padding = 'x' * 65536
[System.IO.File]::WriteAllText($ReadyPath, 'ready')
for ($round = 1; $true; $round++) {
    $version = if ($round % 2) { 'B' } else { 'A' }
    $runId = New-M365RunId -StartedUtc ([datetime]::UtcNow)
    $staged = [System.Collections.Generic.List[object]]::new()
    foreach ($leaf in $leaves) {
        $content = "$leaf version $version`n$padding"
        Add-M365StagedFile -Staged $staged -RunId $runId -Path (Join-Path $OutputDir $leaf) -Write ({ param($TempPath) [System.IO.File]::WriteAllText($TempPath, $content) }.GetNewClosure())
    }
    Publish-M365StagedFile -Staged $staged
}
'@

        $kills = 0
        $interrupted = 0
        $duringSwap = 0
        $losses = 0
        $remaining = 0
        $childFailures = [System.Collections.Generic.List[string]]::new()
        for ($attempt = 1; $attempt -le 60; $attempt++) {
            $ready = Join-Path $TestDrive "ready-$attempt"
            $startInfo = [System.Diagnostics.ProcessStartInfo]::new([System.Environment]::ProcessPath)
            foreach ($argument in '-NoProfile', '-NonInteractive', '-File', $childScript, $monitorScript, $outputDir, $ready) { $startInfo.ArgumentList.Add($argument) }
            $startInfo.UseShellExecute = $false
            $startInfo.RedirectStandardOutput = $true
            $startInfo.RedirectStandardError = $true
            $child = [System.Diagnostics.Process]::Start($startInfo)
            $deadline = [datetime]::UtcNow.AddSeconds(60)
            while (-not [System.IO.File]::Exists($ready) -and -not $child.HasExited -and [datetime]::UtcNow -lt $deadline) {
                [System.Threading.Thread]::Sleep(5)
            }
            [System.Threading.Thread]::Sleep((Get-Random -Minimum 0 -Maximum 250))
            if ($child.HasExited) {
                $childFailures.Add($child.StandardError.ReadToEnd())
            }
            else {
                $child.Kill()
                $kills++
            }
            $child.WaitForExit()
            $child.Dispose()

            # What the next scan would find, then what it leaves after its cleanup. A backup is there only while
            # Publish-M365StagedFile is swapping files, so a kill that left one landed in the middle of the swaps.
            $leftBehind = @(Get-ChildItem -LiteralPath $outputDir -Force -File | Where-Object Name -match '\.(tmp|prev)$')
            if ($leftBehind.Count -gt 0) { $interrupted++ }
            if (@($leftBehind | Where-Object Name -like '*.prev').Count -gt 0) { $duringSwap++ }
            $now = [datetime]::UtcNow
            $null = Repair-M365OutputFolder -OutputPath $outputDir -RunId (New-M365RunId -StartedUtc $now) -RunStartedUtc $now
            foreach ($leaf in $leaves) {
                $path = Join-Path $outputDir $leaf
                if (-not [System.IO.File]::Exists($path) -or [System.IO.File]::ReadAllText($path) -cnotin $expected[$leaf]) { $losses++ }
            }
            $remaining += @(Get-ChildItem -LiteralPath $outputDir -Force -File | Where-Object Name -match '\.(tmp|prev)$').Count
        }
        Write-Host "Kill test: $kills kills, $interrupted left temporary files or backups behind ($duringSwap in the middle of the swaps), $losses files lost or damaged, $remaining leftovers after cleanup."
    }

    It 'killed the writer 60 times while it was writing, some of them in the middle of the swaps' {
        $childFailures.Count | Should -Be 0 -Because ($childFailures -join [Environment]::NewLine)
        $kills | Should -Be 60
        $interrupted | Should -BeGreaterThan 0
        $duringSwap | Should -BeGreaterThan 0
    }

    It 'lost no file: after each kill and cleanup every file is there and whole, with its old or its new content' {
        $losses | Should -Be 0
    }

    It 'left no temporary file or backup after each cleanup' {
        $remaining | Should -Be 0
    }
}
