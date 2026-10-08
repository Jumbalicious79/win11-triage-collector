# =============================================================
# Secrets collection test (mounted-image mode)
# Builds a small fake Windows image in a temporary folder (Windows\System32
# plus one user's Chrome and Firefox settings / session files that hold
# canary secret values, DPAPI master key files Protect\<SID>\<GUID>
# (hidden + system), Preferred, CREDHIST, Credentials (roaming and local),
# Vault, and the system keys System32\Microsoft\Protect\S-1-5-18), maps it to
# a free drive letter with subst and runs triage-collector.ps1 twice:
#
#   WITHOUT -IncludeSecrets: the canary appears in no browser copy, there is
#     no Secrets folder, and collection_info.json has SecretsIncluded false.
#   WITH -IncludeSecrets: the browser copies are byte-for-byte the originals
#     (their manifest hash equals the original's), every credential file is
#     collected with a manifest row carrying the original path and times,
#     collection_info.json has SecretsIncluded true, and the warning is
#     logged. A junction inside a profile folder is not followed.
#
# The image and the collections are removed afterwards and the drive letter
# is unmapped.
#
# Needs Administrator rights, like the collector (GitHub Actions Windows
# runners are elevated). For a local run without them, pass -CollectorPath
# with a copy of the collector that has no admin check, kept inside the
# repository (e.g. under the git-ignored reports\ folder).
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-CollectSecrets.ps1
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
# Written into every secret value (browser files and credential files)
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
    if ($env:GITHUB_ACTIONS) { Write-Host "::error file=tests/Test-CollectSecrets.ps1::$Message" }
}

# The collector refuses to run without Administrator rights (a -CollectorPath
# copy may not)
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

# Writes a binary file, creating its parent folder first
function New-TestBinaryFile {
    param([string]$Path, [byte[]]$Bytes)
    New-Item -ItemType Directory -Path (Split-Path $Path -Parent) -Force | Out-Null
    [System.IO.File]::WriteAllBytes($Path, $Bytes)
}

# A credential file: -Text content, written at -Time, with the Hidden and
# System attributes when -Hidden is set (the DPAPI master key files carry them)
function New-TestSecretFile {
    param([string]$Path, [string]$Text, [datetime]$Time, [switch]$Hidden)
    New-TestTextFile -Path $Path -Text $Text
    if ($Time) { [System.IO.File]::SetLastWriteTimeUtc($Path, $Time) }
    if ($Hidden) {
        $fi = New-Object System.IO.FileInfo($Path)
        $fi.Attributes = $fi.Attributes -bor [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System
    }
}

# base::Pickle as Chromium writes it (see Test-CollectBrowser.ps1)
function New-TestPickle {
    param([object[]]$Fields)
    $stream = New-Object System.IO.MemoryStream
    $writer = New-Object System.IO.BinaryWriter($stream)
    $writer.Write([int32]0)
    foreach ($field in $Fields) {
        switch ($field[0]) {
            "int"   { $writer.Write([int32]$field[1]) }
            "int64" { $writer.Write([int64]$field[1]) }
            default {
                if ($field[0] -eq "str16") { $bytes = [System.Text.Encoding]::Unicode.GetBytes([string]$field[1]) }
                else { $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$field[1]) }
                $length = if ($field[0] -eq "str16") { ([string]$field[1]).Length } else { $bytes.Length }
                $writer.Write([int32]$length)
                $writer.Write($bytes)
                while (($stream.Length % 4) -ne 0) { $writer.Write([byte]0) }
            }
        }
    }
    $writer.Flush()
    $data = $stream.ToArray()
    [System.BitConverter]::GetBytes([int32]($data.Length - 4)).CopyTo($data, 0)
    return , $data
}

# SNSS file (version 3) with one navigation entry whose page state holds -PageState
function New-TestSnss {
    param([int]$CommandId, [string[]]$Urls, [string]$PageState)
    $stream = New-Object System.IO.MemoryStream
    $writer = New-Object System.IO.BinaryWriter($stream)
    $writer.Write([System.Text.Encoding]::ASCII.GetBytes("SNSS"))
    $writer.Write([int32]3)
    $index = 0
    foreach ($url in $Urls) {
        $payload = New-TestPickle @(@("int", 1), @("int", $index), @("str", $url), @("str16", "Title $index"), @("str", $PageState),
            @("int", 1), @("int", 0), @("str", ""), @("int", 1), @("str", $url), @("int", 0), @("int64", 13418000000000000), @("str16", ""), @("int", 200))
        $writer.Write([uint16]($payload.Length + 1))
        $writer.Write([byte]$CommandId)
        $writer.Write($payload)
        $index++
    }
    $writer.Flush()
    return , $stream.ToArray()
}

# mozLz4 file whose LZ4 block holds the text uncompressed (literals only)
function New-TestMozLz4 {
    param([string]$Text)
    $data = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $out = New-Object System.Collections.Generic.List[byte]
    $out.AddRange([System.Text.Encoding]::ASCII.GetBytes("mozLz40" + [char]0))
    $out.AddRange([System.BitConverter]::GetBytes([int32]$data.Length))
    $out.Add([byte]([Math]::Min($data.Length, 15) * 16))
    if ($data.Length -ge 15) {
        $rest = $data.Length - 15
        while ($rest -ge 255) { $out.Add([byte]255); $rest -= 255 }
        $out.Add([byte]$rest)
    }
    $out.AddRange($data)
    return , $out.ToArray()
}

# Run a console tool and return its exit code
function Invoke-NativeTool {
    param([string]$FilePath, [string[]]$Arguments)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { $null = & $FilePath @Arguments 2>&1 }
    finally { $ErrorActionPreference = $previous }
    return $LASTEXITCODE
}

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("collect-secrets-test-" + [guid]::NewGuid().ToString("N"))
$imageDir = Join-Path $workDir "image"
$outNoSecrets = Join-Path $workDir "collection-plain"
$outSecrets = Join-Path $workDir "collection-secrets"
$letter = $null
try {
    # --- Fake image ---
    New-Item -ItemType Directory -Path (Join-Path $imageDir "Windows\System32") -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $imageDir "Users\Public") -Force | Out-Null
    $user = Join-Path $imageDir "Users\alice"
    $chromeUserData = Join-Path $user "AppData\Local\Google\Chrome\User Data"
    $chromeDefault = Join-Path $chromeUserData "Default"
    $firefoxProfile = Join-Path $user "AppData\Roaming\Mozilla\Firefox\Profiles\abcd1234.default-release"
    $now = [datetime]::UtcNow

    # Browser settings / session files holding the canary in every blankable spot
    New-TestTextFile -Path (Join-Path $chromeUserData "Local State") -Text ('{"browser":{"enabled_labs_experiments":["enable-quic@2"]},' +
        '"os_crypt":{"encrypted_key":"' + $canary + '-1","app_bound_encrypted_key":"' + $canary + '-2"},' +
        '"private_key_encrypted_data":"' + $canary + '-3","sync":{"keystore_encryption_key_state":"' + $canary + '-4"},' +
        '"gcm":{"cached_target_token":"' + $canary + '-5"},"media":{"device_id_salt":"' + $canary + '-6"}}')
    New-TestTextFile -Path (Join-Path $chromeDefault "Preferences") -Text ('{"homepage":"https://home.example.com/",' +
        '"password_hash_data_list":[{"hash":"' + $canary + '-7","username":"alice"}]}')
    New-TestTextFile -Path (Join-Path $chromeDefault "Secure Preferences") -Text ('{"extensions":{"settings":{}},"edge":{"policy_recovery_token":"' + $canary + '-8"}}')
    New-TestTextFile -Path (Join-Path $chromeDefault "History") -Text ("SQLite format 3" + [char]0)
    New-TestBinaryFile -Path (Join-Path $chromeDefault "Sessions\Session_13418000000000002") -Bytes (New-TestSnss -CommandId 6 -Urls @("https://session.example.com/") -PageState "$canary-10 form contents")
    New-TestTextFile -Path (Join-Path $firefoxProfile "places.sqlite") -Text ("SQLite format 3" + [char]0)
    New-TestTextFile -Path (Join-Path $firefoxProfile "prefs.js") -Text (@(
        '// Mozilla User Preferences',
        'user_pref("network.proxy.type", 1);',
        ('user_pref("services.sync.tokenserver.token", "' + $canary + '-9");')
    ) -join "`r`n")
    New-TestBinaryFile -Path (Join-Path $firefoxProfile "sessionstore.jsonlz4") -Bytes (New-TestMozLz4 ('{"windows":[{"tabs":[{"entries":[{"url":"https://ff.example.org/","title":"FF",' +
            '"formdata":{"id":{"q":"' + $canary + '-11"}}}],"index":1}],"cookies":[{"host":".example.org","name":"sid","value":"' + $canary + '-12"}]}]}'))

    # --- Credential material ---
    $sid = "S-1-5-21-1111111111-2222222222-3333333333-1001"
    $masterGuid = "11111111-2222-3333-4444-555555555555"
    $vaultGuid = "4BF4C442-9B8A-41A0-B380-DD4A704DDB28"
    # Per-user DPAPI: master keys (Protect\<SID>\<GUID>, Preferred, CREDHIST),
    # Credentials (roaming and local), Vault
    $protect = Join-Path $user "AppData\Roaming\Microsoft\Protect"
    New-TestSecretFile -Path (Join-Path $protect "$sid\$masterGuid") -Text "$canary-masterkey" -Time $now.AddHours(-10) -Hidden
    New-TestSecretFile -Path (Join-Path $protect "$sid\Preferred") -Text "$canary-preferred" -Time $now.AddHours(-9) -Hidden
    New-TestSecretFile -Path (Join-Path $protect "CREDHIST") -Text "$canary-credhist" -Time $now.AddHours(-8) -Hidden
    New-TestSecretFile -Path (Join-Path $user "AppData\Roaming\Microsoft\Credentials\AABBCCDDEEFF00112233445566778899") -Text "$canary-cred-roaming" -Time $now.AddHours(-7)
    New-TestSecretFile -Path (Join-Path $user "AppData\Local\Microsoft\Credentials\99887766554433221100FFEEDDCCBBAA") -Text "$canary-cred-local" -Time $now.AddHours(-6)
    $vault = Join-Path $user "AppData\Local\Microsoft\Vault\$vaultGuid"
    New-TestSecretFile -Path (Join-Path $vault "Policy.vpol") -Text "$canary-vpol" -Time $now.AddHours(-5)
    New-TestSecretFile -Path (Join-Path $vault "0A0B0C0D.vcrd") -Text "$canary-vcrd" -Time $now.AddHours(-4)
    # System DPAPI: System32\Microsoft\Protect\S-1-5-18 and its User subfolder
    $sysProtect = Join-Path $imageDir "Windows\System32\Microsoft\Protect\S-1-5-18"
    New-TestSecretFile -Path (Join-Path $sysProtect $masterGuid) -Text "$canary-sys-masterkey" -Time $now.AddHours(-12) -Hidden
    New-TestSecretFile -Path (Join-Path $sysProtect "Preferred") -Text "$canary-sys-preferred" -Time $now.AddHours(-11) -Hidden
    New-TestSecretFile -Path (Join-Path $sysProtect "User\$masterGuid") -Text "$canary-sys-user-masterkey" -Time $now.AddHours(-13) -Hidden

    # A junction inside a profile folder must not be followed (its target's
    # file must never be collected). Created best-effort (mklink /J needs no
    # admin); the check is skipped if it could not be made.
    $escapedDir = Join-Path $workDir "escaped"
    New-TestTextFile -Path (Join-Path $escapedDir "escaped.txt") -Text "$canary-escaped"
    $junction = Join-Path $vault "LinkOut"
    $junctionMade = (Invoke-NativeTool "cmd.exe" @("/c", "mklink", "/J", $junction, $escapedDir)) -eq 0 -and (Test-Path -LiteralPath $junction)

    # --- Map the image to a free drive letter ---
    $used = @([System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name.Substring(0, 1).ToUpperInvariant() })
    $letter = @("T", "S", "R", "Q", "P", "O", "N", "M", "L", "K", "J", "I", "H") | Where-Object { $used -notcontains $_ } | Select-Object -First 1
    if (-not $letter) { throw "no free drive letter for subst" }
    if ((Invoke-NativeTool "subst.exe" @("$($letter):", $imageDir)) -ne 0 -or -not (Test-Path -LiteralPath "$($letter):\Windows\System32")) {
        $letter = $null
        throw "subst could not map the test image to a drive letter"
    }
    $root = "$($letter):\"

    # Runs the collector on the image; returns its combined output lines
    function Invoke-Collector {
        param([string]$OutPath, [switch]$IncludeSecrets)
        $arguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $collector, "-TargetDrive", $letter,
            "-Categories", "Browser", "-Unattended", "-NoCompress", "-OutputPath", $OutPath)
        if ($IncludeSecrets) { $arguments += "-IncludeSecrets" }
        $previous = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try { $out = & $powershellExe @arguments 2>&1 | ForEach-Object { "$_" } }
        finally { $ErrorActionPreference = $previous }
        return , @($out)
    }

    # ==========================================================
    # Run 1: WITHOUT -IncludeSecrets
    # ==========================================================
    Write-Host "Running the collector WITHOUT -IncludeSecrets on $root ..."
    $plainOut = Invoke-Collector -OutPath $outNoSecrets
    $plainManifest = Join-Path $outNoSecrets "collection_manifest.csv"
    if (-not (Test-Path -LiteralPath $plainManifest)) {
        $plainOut | ForEach-Object { Write-Host "  | $_" }
        Write-TestResult -Succeeded $false -Message "the collector (no switch) wrote no manifest"
        exit 1
    }
    # No canary in any browser copy
    $plainLeaks = @(Get-ChildItem -LiteralPath $outNoSecrets -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($_.FullName)).Contains($canary) } |
        ForEach-Object { $_.FullName.Substring($outNoSecrets.Length + 1) })
    Write-TestResult -Succeeded ($plainLeaks.Count -eq 0) -Message "no switch: the canary appears in no collected file$(if ($plainLeaks.Count) { ': ' + ($plainLeaks -join ', ') })"
    # No Secrets folder
    Write-TestResult -Succeeded (-not (Test-Path -LiteralPath (Join-Path $outNoSecrets "Secrets"))) -Message "no switch: there is no Secrets folder"
    # collection_info.json: SecretsIncluded false, ThunderbirdIndexIncluded false
    $plainInfo = Get-Content -LiteralPath (Join-Path $outNoSecrets "collection_info.json") -Raw | ConvertFrom-Json
    Write-TestResult -Succeeded ($plainInfo.SecretsIncluded -eq $false) -Message "no switch: collection_info.json SecretsIncluded is false"
    Write-TestResult -Succeeded ($plainInfo.PSObject.Properties["ThunderbirdIndexIncluded"] -and $plainInfo.ThunderbirdIndexIncluded -eq $false) -Message "no switch: collection_info.json ThunderbirdIndexIncluded is false"

    # ==========================================================
    # Run 2: WITH -IncludeSecrets
    # ==========================================================
    Write-Host "Running the collector WITH -IncludeSecrets on $root ..."
    $secretsOut = Invoke-Collector -OutPath $outSecrets -IncludeSecrets
    $secretsManifest = Join-Path $outSecrets "collection_manifest.csv"
    if (-not (Test-Path -LiteralPath $secretsManifest)) {
        $secretsOut | ForEach-Object { Write-Host "  | $_" }
        Write-TestResult -Succeeded $false -Message "the collector (-IncludeSecrets) wrote no manifest"
        exit 1
    }
    $manifest = @(Import-Csv -LiteralPath $secretsManifest)
    $logText = [System.IO.File]::ReadAllText((Join-Path $outSecrets "collection_log.txt"))

    # The warning is logged
    Write-TestResult -Succeeded ($logText -match '-IncludeSecrets is set') -Message "-IncludeSecrets: the credential-material warning is logged at the start"
    # collection_info.json: SecretsIncluded true
    $secretsInfo = Get-Content -LiteralPath (Join-Path $outSecrets "collection_info.json") -Raw | ConvertFrom-Json
    Write-TestResult -Succeeded ($secretsInfo.SecretsIncluded -eq $true) -Message "-IncludeSecrets: collection_info.json SecretsIncluded is true"

    # The browser copies are byte-for-byte the originals (hash matches)
    $browserCopies = @{
        "Browser\alice\Chrome\Local State"                 = "Users\alice\AppData\Local\Google\Chrome\User Data\Local State"
        "Browser\alice\Chrome\Default\Preferences"         = "Users\alice\AppData\Local\Google\Chrome\User Data\Default\Preferences"
        "Browser\alice\Chrome\Default\Secure Preferences"  = "Users\alice\AppData\Local\Google\Chrome\User Data\Default\Secure Preferences"
        "Browser\alice\Chrome\Default\Sessions\Session_13418000000000002" = "Users\alice\AppData\Local\Google\Chrome\User Data\Default\Sessions\Session_13418000000000002"
        "Browser\alice\Firefox\abcd1234.default-release\prefs.js"            = "Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\abcd1234.default-release\prefs.js"
        "Browser\alice\Firefox\abcd1234.default-release\sessionstore.jsonlz4" = "Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\abcd1234.default-release\sessionstore.jsonlz4"
    }
    foreach ($rel in $browserCopies.Keys) {
        $copy = Join-Path $outSecrets $rel
        $src = Join-Path $imageDir $browserCopies[$rel]
        $row = $manifest | Where-Object { $_.RelativePath -eq $rel } | Select-Object -First 1
        $problem = ""
        if (-not (Test-Path -LiteralPath $copy)) { $problem = "not collected" }
        else {
            $srcHash = (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash
            $copyHash = (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash
            if ($copyHash -ne $srcHash) { $problem = "copy hash differs from the original" }
            elseif (-not $row) { $problem = "no manifest row" }
            elseif ($row.SHA256 -ne $srcHash) { $problem = "manifest hash differs from the original" }
        }
        Write-TestResult -Succeeded (-not $problem) -Message "-IncludeSecrets: unredacted (hash-equal) browser copy: $rel$(if ($problem) { " -- $problem" })"
    }

    # Every credential file collected, with a manifest row and original times
    $credFiles = [ordered]@{
        "Secrets\alice\AppData\Roaming\Microsoft\Protect\$sid\$masterGuid"        = "Users\alice\AppData\Roaming\Microsoft\Protect\$sid\$masterGuid"
        "Secrets\alice\AppData\Roaming\Microsoft\Protect\$sid\Preferred"          = "Users\alice\AppData\Roaming\Microsoft\Protect\$sid\Preferred"
        "Secrets\alice\AppData\Roaming\Microsoft\Protect\CREDHIST"                = "Users\alice\AppData\Roaming\Microsoft\Protect\CREDHIST"
        "Secrets\alice\AppData\Roaming\Microsoft\Credentials\AABBCCDDEEFF00112233445566778899" = "Users\alice\AppData\Roaming\Microsoft\Credentials\AABBCCDDEEFF00112233445566778899"
        "Secrets\alice\AppData\Local\Microsoft\Credentials\99887766554433221100FFEEDDCCBBAA"   = "Users\alice\AppData\Local\Microsoft\Credentials\99887766554433221100FFEEDDCCBBAA"
        "Secrets\alice\AppData\Local\Microsoft\Vault\$vaultGuid\Policy.vpol"      = "Users\alice\AppData\Local\Microsoft\Vault\$vaultGuid\Policy.vpol"
        "Secrets\alice\AppData\Local\Microsoft\Vault\$vaultGuid\0A0B0C0D.vcrd"    = "Users\alice\AppData\Local\Microsoft\Vault\$vaultGuid\0A0B0C0D.vcrd"
        "Secrets\System\System32\Microsoft\Protect\S-1-5-18\$masterGuid"         = "Windows\System32\Microsoft\Protect\S-1-5-18\$masterGuid"
        "Secrets\System\System32\Microsoft\Protect\S-1-5-18\Preferred"           = "Windows\System32\Microsoft\Protect\S-1-5-18\Preferred"
        "Secrets\System\System32\Microsoft\Protect\S-1-5-18\User\$masterGuid"    = "Windows\System32\Microsoft\Protect\S-1-5-18\User\$masterGuid"
    }
    foreach ($rel in $credFiles.Keys) {
        $copy = Join-Path $outSecrets $rel
        $row = $manifest | Where-Object { $_.RelativePath -eq $rel } | Select-Object -First 1
        $problem = ""
        if (-not (Test-Path -LiteralPath $copy)) { $problem = "not collected" }
        elseif (-not $row) { $problem = "no manifest row" }
        elseif ($row.SourcePath -ne ($root + $credFiles[$rel])) { $problem = "manifest SourcePath is '$($row.SourcePath)'" }
        elseif ($row.SHA256 -ne (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash) { $problem = "manifest hash differs from the copy" }
        elseif (-not $row.SourceModifiedUtc) { $problem = "no original modified time in the manifest" }
        Write-TestResult -Succeeded (-not $problem) -Message "-IncludeSecrets: credential file collected: $rel$(if ($problem) { " -- $problem" })"
    }

    # The junction inside the profile was not followed
    if ($junctionMade) {
        $escapedPresent = @($manifest | Where-Object { $_.SourcePath -like "*escaped.txt" }).Count -gt 0 -or
            (Get-ChildItem -LiteralPath $outSecrets -Recurse -File -Filter "escaped.txt" -ErrorAction SilentlyContinue).Count -gt 0
        Write-TestResult -Succeeded (-not $escapedPresent) -Message "-IncludeSecrets: the junction out of the profile was not followed"
    }
    else {
        Write-Host "SKIP: junction could not be created (mklink /J unavailable); link-following not checked" -ForegroundColor Yellow
    }

    if ($script:failures -gt 0) {
        Write-Host "FAIL: $($script:failures) check(s) failed" -ForegroundColor Red
        exit 1
    }
    Write-Host "PASS: all secrets collection checks passed" -ForegroundColor Green
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
