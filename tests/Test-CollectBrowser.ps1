# =============================================================
# Browser collection test (mounted-image mode)
# Builds a small fake Windows image in a temporary folder (Windows\System32
# plus one user's Chrome, Edge, Opera and Firefox profiles with synthetic
# files), maps it to a free drive letter with subst, runs
# triage-collector.ps1 -TargetDrive <letter> -Categories Browser
# -Unattended -NoCompress and checks the collection:
#   - collected: the existing profile files, Preferences / Secure
#     Preferences, Favicons, Sessions\Session_* and Tabs_* (and the older
#     Current Session), extension manifests with the messages.json of the
#     default locale (only when the manifest uses __MSG_ names), the Guest
#     profile, Local State, the history snapshots (Snapshots\<version>\
#     <profile>\History and Favicons), Opera's own folder, and Firefox's
#     extensions.json, addons.json, prefs.js and session files
#   - not collected: other locales, extension code, an oversized manifest,
#     session files over the 64 MB cap, other snapshot files, profile
#     folders that are not browser profiles
#   - every collected file has a manifest row with its original path and
#     the hash of the copy
#   - Local State, Preferences, Secure Preferences and prefs.js are copied
#     with their secret values (encrypted keys, password hashes, tokens)
#     blanked: a canary string in each must appear nowhere in the
#     collection, while the other settings are kept
# The image and the collection are removed afterwards and the drive letter
# is unmapped.
#
# Needs Administrator rights, like the collector (GitHub Actions Windows
# runners are elevated). For a local run without them, pass -CollectorPath
# with a copy of the collector that has no admin check, kept inside the
# repository (e.g. under the git-ignored reports\ folder).
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-CollectBrowser.ps1
# =============================================================
param(
    # Collector script to test (default: the repository's triage-collector.ps1)
    [string]$CollectorPath = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$collector = $CollectorPath
if (-not $collector) { $collector = Join-Path $repoRoot "triage-collector.ps1" }
$collector = (Resolve-Path -LiteralPath $collector).Path
# Written into every secret value of the settings files
$canary = "CANARY-SECRET-VALUE"
$script:failures = 0

# PASS/FAIL line; failures are counted and annotated on GitHub Actions
function Write-TestResult {
    param([bool]$Succeeded, [string]$Message)
    if ($Succeeded) {
        Write-Host "PASS: $Message" -ForegroundColor Green
        return
    }
    $script:failures++
    Write-Host "FAIL: $Message" -ForegroundColor Red
    if ($env:GITHUB_ACTIONS) { Write-Host "::error file=tests/Test-CollectBrowser.ps1::$Message" }
}

# The collector refuses to run without Administrator rights (a
# -CollectorPath copy may not)
if (-not $CollectorPath) {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-TestResult -Succeeded $false -Message "Administrator rights are required (the collector needs them). Run elevated, or pass -CollectorPath with a collector copy without the admin check."
        exit 1
    }
}

# Run the collector with the same PowerShell edition as this script
$powershellExe = (Get-Process -Id $PID).Path

# Writes a text file (UTF-8, no BOM)
function New-TestTextFile {
    param([string]$Path, [string]$Text)
    New-Item -ItemType Directory -Path (Split-Path $Path -Parent) -Force | Out-Null
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

# A file of -Size bytes that starts with -Text (the rest zeros), last
# written at -Time (newest-first ordering of session files)
function New-TestSizedFile {
    param([string]$Path, [string]$Text, [long]$Size, [datetime]$Time)
    New-TestTextFile -Path $Path -Text $Text
    $stream = [System.IO.File]::Open($Path, "Open", "ReadWrite", "None")
    try { $stream.SetLength($Size) } finally { $stream.Dispose() }
    if ($Time) { [System.IO.File]::SetLastWriteTimeUtc($Path, $Time) }
}

# Run a console tool and return its exit code (error action Continue: with
# Stop, Windows PowerShell 5.1 turns any stderr line into an error)
function Invoke-NativeTool {
    param([string]$FilePath, [string[]]$Arguments)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { $null = & $FilePath @Arguments 2>&1 }
    finally { $ErrorActionPreference = $previous }
    return $LASTEXITCODE
}

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("collect-browser-test-" + [guid]::NewGuid().ToString("N"))
$imageDir = Join-Path $workDir "image"
$outDir = Join-Path $workDir "collection"
$letter = $null
try {
    # --- Fake image ---
    New-Item -ItemType Directory -Path (Join-Path $imageDir "Windows\System32") -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $imageDir "Users\Public") -Force | Out-Null
    $user = Join-Path $imageDir "Users\alice"
    $chromeUserData = Join-Path $user "AppData\Local\Google\Chrome\User Data"
    $chromeDefault = Join-Path $chromeUserData "Default"
    $edgeUserData = Join-Path $user "AppData\Local\Microsoft\Edge\User Data"
    $operaDir = Join-Path $user "AppData\Roaming\Opera Software\Opera Stable"
    $firefoxProfile = Join-Path $user "AppData\Roaming\Mozilla\Firefox\Profiles\abcd1234.default-release"
    $sqliteHeader = "SQLite format 3" + [char]0

    # Settings files with secret values (the canary) next to ordinary ones
    $localState = '{"browser":{"enabled_labs_experiments":["enable-quic@2"]},"os_crypt":{"audit_enabled":true,"encrypted_key":"' + $canary + '-1",' +
        '"app_bound_encrypted_key":"' + $canary + '-2"},"private_key_encrypted_data":"' + $canary + '-3","profile":{"info_cache":{"Default":{"name":"Person 1"}}}}'
    $preferences = '{"download":{"default_directory":"D:\\Drop"},"homepage":"https://home.example.com/","password_hash_data_list":[{"hash":"' + $canary + '-4",' +
        '"salt":"' + $canary + '-5","username":"alice"}],"edge":{"services":{"signin_scoped_device_id":"device"}},"gcm":{"cached_target_token":"' + $canary + '-6"},' +
        '"media":{"device_id_salt":"' + $canary + '-7"},"counts":{"n_salt":5}}'
    $securePreferences = '{"extensions":{"settings":{"abcdefghijklmnopabcdefghijklmnop":{"location":1,"manifest":{"name":"__MSG_extName__"}}}},' +
        '"edge":{"policy_recovery_token":"' + $canary + '-8"},"protection":{"macs":{"homepage":"ABCDEF"}}}'

    # Chrome Default profile: the existing files, plus the new ones
    foreach ($name in @("History", "Bookmarks", "Shortcuts")) { New-TestTextFile -Path (Join-Path $chromeDefault $name) -Text $sqliteHeader }
    New-TestTextFile -Path (Join-Path $chromeDefault "Preferences") -Text $preferences
    New-TestTextFile -Path (Join-Path $chromeDefault "Secure Preferences") -Text $securePreferences
    New-TestTextFile -Path (Join-Path $chromeDefault "Favicons") -Text $sqliteHeader
    New-TestTextFile -Path (Join-Path $chromeDefault "Favicons-journal") -Text "journal"
    # Sessions: newest first within 64 MB -- Session_2 (30 MB) and Tabs_3
    # fit, the older Session_1 (40 MB) does not
    $now = [datetime]::UtcNow
    New-TestSizedFile -Path (Join-Path $chromeDefault "Sessions\Session_13418000000000001") -Text "SNSS" -Size 40MB -Time $now.AddHours(-3)
    New-TestSizedFile -Path (Join-Path $chromeDefault "Sessions\Session_13418000000000002") -Text "SNSS" -Size 30MB -Time $now.AddHours(-1)
    New-TestSizedFile -Path (Join-Path $chromeDefault "Sessions\Tabs_13418000000000003") -Text "SNSS" -Size 1KB -Time $now.AddHours(-2)
    New-TestTextFile -Path (Join-Path $chromeDefault "Sessions\notes.txt") -Text "not a session file"
    New-TestTextFile -Path (Join-Path $chromeDefault "Current Session") -Text "SNSS-legacy"
    # Extensions: a manifest with __MSG_ names (its default locale's
    # messages.json is collected, not the other locale or the code), one
    # without (no _locales), an oversized manifest, and a folder that is not
    # an extension id
    $extDir = Join-Path $chromeDefault "Extensions\abcdefghijklmnopabcdefghijklmnop\1.0_0"
    New-TestTextFile -Path (Join-Path $extDir "manifest.json") -Text '{"name":"__MSG_extName__","version":"1.0","default_locale":"en","manifest_version":3}'
    New-TestTextFile -Path (Join-Path $extDir "_locales\en\messages.json") -Text '{"extName":{"message":"Test Extension"}}'
    New-TestTextFile -Path (Join-Path $extDir "_locales\de\messages.json") -Text '{"extName":{"message":"Testerweiterung"}}'
    New-TestTextFile -Path (Join-Path $extDir "background.js") -Text "console.log('code');"
    $ext2Dir = Join-Path $chromeDefault "Extensions\bcdefghijklmnopabcdefghijklmnopa\2.0_0"
    New-TestTextFile -Path (Join-Path $ext2Dir "manifest.json") -Text '{"name":"Plain Name","version":"2.0","default_locale":"en","manifest_version":3}'
    New-TestTextFile -Path (Join-Path $ext2Dir "_locales\en\messages.json") -Text '{"x":{"message":"y"}}'
    $bigDir = Join-Path $chromeDefault "Extensions\cdefghijklmnopabcdefghijklmnopab\3.0_0"
    New-TestSizedFile -Path (Join-Path $bigDir "manifest.json") -Text '{"name":"Big"}' -Size (1MB + 1)
    New-TestTextFile -Path (Join-Path $chromeDefault "Extensions\Temp\manifest.json") -Text '{"name":"temp"}'
    # Guest profile (now collected) and a folder that is not a profile
    New-TestTextFile -Path (Join-Path $chromeUserData "Guest Profile\History") -Text $sqliteHeader
    New-TestTextFile -Path (Join-Path $chromeUserData "Guest Profile\Preferences") -Text '{"homepage":"https://guest.example.com/"}'
    New-TestTextFile -Path (Join-Path $chromeUserData "System Profile\Preferences") -Text '{}'
    # Local State and the history snapshots (only History and Favicons)
    New-TestTextFile -Path (Join-Path $chromeUserData "Local State") -Text $localState
    $snapshotDir = Join-Path $chromeUserData "Snapshots\120.0.6099.71"
    New-TestTextFile -Path (Join-Path $snapshotDir "Default\History") -Text $sqliteHeader
    New-TestTextFile -Path (Join-Path $snapshotDir "Default\History-journal") -Text "journal"
    New-TestTextFile -Path (Join-Path $snapshotDir "Default\Favicons") -Text $sqliteHeader
    New-TestTextFile -Path (Join-Path $snapshotDir "Default\Login Data") -Text $sqliteHeader
    New-TestTextFile -Path (Join-Path $snapshotDir "Default\Preferences") -Text '{}'
    New-TestTextFile -Path (Join-Path $snapshotDir "Local State") -Text '{}'

    # Edge: a numbered profile
    New-TestTextFile -Path (Join-Path $edgeUserData "Profile 1\History") -Text $sqliteHeader
    New-TestTextFile -Path (Join-Path $edgeUserData "Profile 1\Secure Preferences") -Text '{"extensions":{"settings":{}}}'
    New-TestTextFile -Path (Join-Path $edgeUserData "Local State") -Text '{"browser":{}}'
    # Opera: its folder is the profile and holds Local State
    New-TestTextFile -Path (Join-Path $operaDir "History") -Text $sqliteHeader
    New-TestTextFile -Path (Join-Path $operaDir "Preferences") -Text '{"homepage":"https://opera.example.com/"}'
    New-TestTextFile -Path (Join-Path $operaDir "Local State") -Text '{"browser":{}}'
    New-TestTextFile -Path (Join-Path $operaDir "Sessions\Session_13418000000000009") -Text "SNSS"

    # Firefox
    New-TestTextFile -Path (Join-Path $firefoxProfile "places.sqlite") -Text $sqliteHeader
    New-TestTextFile -Path (Join-Path $firefoxProfile "extensions.json") -Text '{"schemaVersion":36,"addons":[]}'
    New-TestTextFile -Path (Join-Path $firefoxProfile "addons.json") -Text '{"schema":6,"addons":[]}'
    New-TestTextFile -Path (Join-Path $firefoxProfile "prefs.js") -Text (@(
        '// Mozilla User Preferences',
        'user_pref("network.proxy.type", 1);',
        'user_pref("network.proxy.http", "10.0.0.5");',
        ('user_pref("services.sync.tokenserver.token", "' + $canary + '-9");'),
        ('user_pref("dom.push.userAgentID", "' + $canary + '-10");'),
        ('user_pref("extensions.example.secret", "' + $canary + '-11");')
    ) -join "`r`n")
    $mozLz4 = "mozLz40" + [char]0 + "data"
    New-TestTextFile -Path (Join-Path $firefoxProfile "sessionstore.jsonlz4") -Text $mozLz4
    foreach ($name in @("recovery.jsonlz4", "recovery.baklz4", "previous.jsonlz4", "upgrade.jsonlz4-20260101000000")) {
        New-TestTextFile -Path (Join-Path $firefoxProfile "sessionstore-backups\$name") -Text $mozLz4
    }
    New-TestTextFile -Path (Join-Path $firefoxProfile "sessionstore-backups\readme.txt") -Text "other"

    # --- Map the image to a free drive letter ---
    $used = @([System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name.Substring(0, 1).ToUpperInvariant() })
    $letter = @("T", "S", "R", "Q", "P", "O", "N", "M", "L", "K", "J", "I", "H") | Where-Object { $used -notcontains $_ } | Select-Object -First 1
    if (-not $letter) { throw "no free drive letter for subst" }
    if ((Invoke-NativeTool "subst.exe" @("$($letter):", $imageDir)) -ne 0 -or -not (Test-Path -LiteralPath "$($letter):\Windows\System32")) {
        $letter = $null
        throw "subst could not map the test image to a drive letter"
    }
    $root = "$($letter):\"

    # --- Run the collector on the image ---
    Write-Host "Running the collector ($powershellExe) on $root (image: $imageDir) ..."
    $ErrorActionPreference = "Continue"
    $collectorOutput = & $powershellExe -NoProfile -ExecutionPolicy Bypass -File $collector -TargetDrive $letter -Categories Browser -Unattended -NoCompress -OutputPath $outDir 2>&1 |
        ForEach-Object { "$_" }
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = "Stop"
    $manifestPath = Join-Path $outDir "collection_manifest.csv"
    if ($exitCode -ne 0 -or -not (Test-Path -LiteralPath $manifestPath)) {
        $collectorOutput | ForEach-Object { Write-Host "  | $_" }
        Write-TestResult -Succeeded $false -Message "the collector exited with code $exitCode or wrote no manifest"
        exit 1
    }
    $manifest = @(Import-Csv -LiteralPath $manifestPath)
    $logText = [System.IO.File]::ReadAllText((Join-Path $outDir "collection_log.txt"))
    Write-TestResult -Succeeded ($logText -match 'Mode: MOUNTED IMAGE') -Message "the collector ran in mounted-image mode"

    # --- Collected: a manifest row with the original path, the copy's hash ---
    $browser = "Browser\alice"
    $expected = [ordered]@{
        "$browser\Chrome\Default\History"                     = "Users\alice\AppData\Local\Google\Chrome\User Data\Default\History"
        "$browser\Chrome\Default\Bookmarks"                   = "Users\alice\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"
        "$browser\Chrome\Default\Preferences"                 = "Users\alice\AppData\Local\Google\Chrome\User Data\Default\Preferences"
        "$browser\Chrome\Default\Secure Preferences"          = "Users\alice\AppData\Local\Google\Chrome\User Data\Default\Secure Preferences"
        "$browser\Chrome\Default\Favicons"                    = "Users\alice\AppData\Local\Google\Chrome\User Data\Default\Favicons"
        "$browser\Chrome\Default\Favicons-journal"            = "Users\alice\AppData\Local\Google\Chrome\User Data\Default\Favicons-journal"
        "$browser\Chrome\Default\Sessions\Session_13418000000000002" = "Users\alice\AppData\Local\Google\Chrome\User Data\Default\Sessions\Session_13418000000000002"
        "$browser\Chrome\Default\Sessions\Tabs_13418000000000003"    = "Users\alice\AppData\Local\Google\Chrome\User Data\Default\Sessions\Tabs_13418000000000003"
        "$browser\Chrome\Default\Current Session"             = "Users\alice\AppData\Local\Google\Chrome\User Data\Default\Current Session"
        "$browser\Chrome\Default\Extensions\abcdefghijklmnopabcdefghijklmnop\1.0_0\manifest.json" = "Users\alice\AppData\Local\Google\Chrome\User Data\Default\Extensions\abcdefghijklmnopabcdefghijklmnop\1.0_0\manifest.json"
        "$browser\Chrome\Default\Extensions\abcdefghijklmnopabcdefghijklmnop\1.0_0\_locales\en\messages.json" = "Users\alice\AppData\Local\Google\Chrome\User Data\Default\Extensions\abcdefghijklmnopabcdefghijklmnop\1.0_0\_locales\en\messages.json"
        "$browser\Chrome\Default\Extensions\bcdefghijklmnopabcdefghijklmnopa\2.0_0\manifest.json" = "Users\alice\AppData\Local\Google\Chrome\User Data\Default\Extensions\bcdefghijklmnopabcdefghijklmnopa\2.0_0\manifest.json"
        "$browser\Chrome\Guest Profile\History"               = "Users\alice\AppData\Local\Google\Chrome\User Data\Guest Profile\History"
        "$browser\Chrome\Guest Profile\Preferences"           = "Users\alice\AppData\Local\Google\Chrome\User Data\Guest Profile\Preferences"
        "$browser\Chrome\Local State"                         = "Users\alice\AppData\Local\Google\Chrome\User Data\Local State"
        "$browser\Chrome\Snapshots\120.0.6099.71\Default\History"         = "Users\alice\AppData\Local\Google\Chrome\User Data\Snapshots\120.0.6099.71\Default\History"
        "$browser\Chrome\Snapshots\120.0.6099.71\Default\History-journal" = "Users\alice\AppData\Local\Google\Chrome\User Data\Snapshots\120.0.6099.71\Default\History-journal"
        "$browser\Chrome\Snapshots\120.0.6099.71\Default\Favicons"        = "Users\alice\AppData\Local\Google\Chrome\User Data\Snapshots\120.0.6099.71\Default\Favicons"
        "$browser\Edge\Profile 1\History"                     = "Users\alice\AppData\Local\Microsoft\Edge\User Data\Profile 1\History"
        "$browser\Edge\Profile 1\Secure Preferences"          = "Users\alice\AppData\Local\Microsoft\Edge\User Data\Profile 1\Secure Preferences"
        "$browser\Edge\Local State"                           = "Users\alice\AppData\Local\Microsoft\Edge\User Data\Local State"
        "$browser\Opera\History"                              = "Users\alice\AppData\Roaming\Opera Software\Opera Stable\History"
        "$browser\Opera\Preferences"                          = "Users\alice\AppData\Roaming\Opera Software\Opera Stable\Preferences"
        "$browser\Opera\Local State"                          = "Users\alice\AppData\Roaming\Opera Software\Opera Stable\Local State"
        "$browser\Opera\Sessions\Session_13418000000000009"   = "Users\alice\AppData\Roaming\Opera Software\Opera Stable\Sessions\Session_13418000000000009"
        "$browser\Firefox\abcd1234.default-release\places.sqlite"   = "Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\abcd1234.default-release\places.sqlite"
        "$browser\Firefox\abcd1234.default-release\extensions.json" = "Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\abcd1234.default-release\extensions.json"
        "$browser\Firefox\abcd1234.default-release\addons.json"     = "Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\abcd1234.default-release\addons.json"
        "$browser\Firefox\abcd1234.default-release\prefs.js"        = "Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\abcd1234.default-release\prefs.js"
        "$browser\Firefox\abcd1234.default-release\sessionstore.jsonlz4" = "Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\abcd1234.default-release\sessionstore.jsonlz4"
    }
    foreach ($name in @("recovery.jsonlz4", "recovery.baklz4", "previous.jsonlz4", "upgrade.jsonlz4-20260101000000")) {
        $expected["$browser\Firefox\abcd1234.default-release\sessionstore-backups\$name"] = "Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\abcd1234.default-release\sessionstore-backups\$name"
    }
    foreach ($rel in $expected.Keys) {
        $copy = Join-Path $outDir $rel
        $row = $manifest | Where-Object { $_.RelativePath -eq $rel } | Select-Object -First 1
        $problem = ""
        if (-not (Test-Path -LiteralPath $copy)) { $problem = "not in the collection" }
        elseif (-not $row) { $problem = "no manifest row" }
        elseif ($row.SourcePath -ne ($root + $expected[$rel])) { $problem = "manifest SourcePath is '$($row.SourcePath)'" }
        elseif ($row.SHA256 -ne (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash) { $problem = "manifest hash differs from the copy" }
        elseif (-not $row.SourceModifiedUtc) { $problem = "no original modified time in the manifest" }
        Write-TestResult -Succeeded (-not $problem) -Message "collected: $rel$(if ($problem) { " -- $problem" })"
    }

    # --- Not collected ---
    $notExpected = @(
        "$browser\Chrome\Default\Sessions\Session_13418000000000001",
        "$browser\Chrome\Default\Sessions\notes.txt",
        "$browser\Chrome\Default\Extensions\abcdefghijklmnopabcdefghijklmnop\1.0_0\_locales\de\messages.json",
        "$browser\Chrome\Default\Extensions\abcdefghijklmnopabcdefghijklmnop\1.0_0\background.js",
        "$browser\Chrome\Default\Extensions\bcdefghijklmnopabcdefghijklmnopa\2.0_0\_locales\en\messages.json",
        "$browser\Chrome\Default\Extensions\cdefghijklmnopabcdefghijklmnopab\3.0_0\manifest.json",
        "$browser\Chrome\Default\Extensions\Temp\manifest.json",
        "$browser\Chrome\System Profile",
        "$browser\Chrome\Snapshots\120.0.6099.71\Default\Login Data",
        "$browser\Chrome\Snapshots\120.0.6099.71\Default\Preferences",
        "$browser\Chrome\Snapshots\120.0.6099.71\Local State",
        "$browser\Firefox\abcd1234.default-release\sessionstore-backups\readme.txt"
    )
    foreach ($rel in $notExpected) {
        $present = (Test-Path -LiteralPath (Join-Path $outDir $rel)) -or @($manifest | Where-Object { $_.RelativePath -like "$rel*" }).Count -gt 0
        Write-TestResult -Succeeded (-not $present) -Message "not collected: $rel"
    }
    Write-TestResult -Succeeded ($logText -match 'Skipped \(larger than the 1 MB cap[^\r\n]*cdefghijklmnopabcdefghijklmnopab') -Message "the oversized manifest is logged as skipped"
    Write-TestResult -Succeeded ($logText -match 'Skipped 1 session file\(s\)[^\r\n]*64 MB total cap\): Session_13418000000000001') -Message "the session file over the 64 MB total cap is logged as skipped"

    # --- Secret values blanked, other settings kept ---
    $leaks = @(Get-ChildItem -LiteralPath $outDir -Recurse -File | Where-Object { [System.IO.File]::ReadAllText($_.FullName).Contains($canary) } | ForEach-Object { $_.Name })
    Write-TestResult -Succeeded ($leaks.Count -eq 0) -Message "no secret value (canary) anywhere in the collection$(if ($leaks.Count) { ': ' + ($leaks -join ', ') })"
    $checks = @(
        @{ Rel = "$browser\Chrome\Local State"; Has = @('"enabled_labs_experiments":["enable-quic@2"]', '"encrypted_key":""', '"app_bound_encrypted_key":""', '"audit_enabled":true', '"private_key_encrypted_data":""') }
        @{ Rel = "$browser\Chrome\Default\Preferences"; Has = @('"default_directory":"D:\\Drop"', '"password_hash_data_list":[]', '"cached_target_token":""', '"device_id_salt":""', '"n_salt":5', '"signin_scoped_device_id":"device"') }
        @{ Rel = "$browser\Chrome\Default\Secure Preferences"; Has = @('"policy_recovery_token":""', '"name":"__MSG_extName__"', '"homepage":"ABCDEF"') }
        @{ Rel = "$browser\Firefox\abcd1234.default-release\prefs.js"; Has = @('user_pref("network.proxy.type", 1);', 'user_pref("network.proxy.http", "10.0.0.5");', 'user_pref("services.sync.tokenserver.token", "");', 'user_pref("dom.push.userAgentID", "");') }
    )
    foreach ($check in $checks) {
        $path = Join-Path $outDir $check.Rel
        if (-not (Test-Path -LiteralPath $path)) { Write-TestResult -Succeeded $false -Message "blanked copy missing: $($check.Rel)"; continue }
        $text = [System.IO.File]::ReadAllText($path)
        $missing = @($check.Has | Where-Object { -not $text.Contains($_) })
        $valid = $true
        if ($check.Rel -notlike "*.js") {
            try { $null = $text | ConvertFrom-Json -ErrorAction Stop } catch { $valid = $false }
        }
        Write-TestResult -Succeeded ($missing.Count -eq 0 -and $valid) -Message "secret values blanked, settings kept: $($check.Rel)$(if ($missing.Count) { ' -- lacks ' + ($missing -join ' ') })$(if (-not $valid) { ' -- not valid JSON' })"
    }
    Write-TestResult -Succeeded ($logText -match 'Collected with 3 secret value\(s\) blanked[^\r\n]*Chrome\\User Data\\Local State') -Message "the log says which copies had secret values blanked"

    if ($script:failures -gt 0) {
        Write-Host "FAIL: $($script:failures) check(s) failed" -ForegroundColor Red
        exit 1
    }
    Write-Host "PASS: all browser collection checks passed" -ForegroundColor Green
    exit 0
}
catch {
    Write-TestResult -Succeeded $false -Message "test setup or run error: $($_.Exception.Message)"
    exit 1
}
finally {
    if ($letter) { $null = Invoke-NativeTool "subst.exe" @("$($letter):", "/d") }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}
