# PSScriptAnalyzer settings, used by CI (.github/workflows/ci.yml).
# All default rules apply except the ones below, which conflict with how
# this tool is built.
@{
    ExcludeRules = @(
        # Interactive console tool launched from a .bat: Write-Host gives the
        # colored menus, prompts and progress output
        'PSAvoidUsingWriteHost',

        # Script-internal helper names (Log-Warning, Ensure-Directory,
        # Record-Manifest, ...). They are not exported cmdlets; renaming them
        # would touch every call site for no functional gain
        'PSUseApprovedVerbs',
        'PSUseSingularNouns',

        # Internal cleanup helpers (shadow copy, Defender exclusion) are not
        # user-facing cmdlets; -WhatIf/-Confirm would add nothing
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
