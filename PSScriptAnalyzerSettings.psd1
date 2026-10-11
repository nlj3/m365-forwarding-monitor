# Settings for PSScriptAnalyzer, used by .github/workflows/ci.yml.
#
# These rules are switched off because the findings they raise in src/ were reviewed and
# left alone on purpose. Each one would change how the scripts behave or what they are
# called, which is outside what a lint pass should do. Remove a line to see its findings.
@{
    ExcludeRules = @(
        # The scripts are command-line tools and Write-Host is their console output.
        'PSAvoidUsingWriteHost'

        # Start-UiScan, Update-M365OutboundBaseline and New-M365ForwardingDashboard only write
        # local files. Adding SupportsShouldProcess would add -WhatIf and -Confirm to them.
        'PSUseShouldProcessForStateChangingFunctions'

        # Get-M365MonitorUsers and Get-M365OutboundMetadataCounts are called by name elsewhere.
        'PSUseSingularNouns'

        # False positive: Start-UiScan declares $Root, $LogPath and $StatusPath in the job's param().
        'PSUseUsingScopeModifierInNewRunspaces'

        # BaselineAverage is passed by callers but not read; UseDeviceAuthentication is read
        # inside a nested script block, which the rule does not see.
        'PSReviewUnusedParameter'

        # Update-M365OutboundBaseline compares ExternalSentCount -ne $null. Moving $null to the
        # left changes the result if the value is ever an array.
        'PSPossibleIncorrectComparisonWithNull'
    )
}
