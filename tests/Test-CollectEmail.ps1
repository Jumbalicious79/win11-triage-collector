# =============================================================
# Email collection test
# Part 1 (mounted image): builds a fake image -- a folder with
# Windows\System32 and user profiles holding synthetic classic Outlook, new
# Outlook, Thunderbird and Windows Mail data -- maps it to a free drive
# letter with subst, runs triage-collector.ps1 -TargetDrive <letter>
# -Categories Email -Unattended -NoCompress and checks the collected files,
# the listing CSVs and the manifest: attachments are copied within the caps
# (50 MB per file, 500 MB per user, newest first); OST/PST files, mailboxes
# and the new Outlook's mail data are listed but never copied; junctions are
# never followed. Needs about 1.1 GB of free space in %TEMP% for a moment.
# Part 2 (live system): sets OutlookSecureTempFolder of a made-up Office
# version (HKCU\Software\Microsoft\Office\99.0\Outlook\Security) to a folder
# outside Content.Outlook and checks that the collector lists and copies
# it. It writes to HKCU, so it runs only in GitHub Actions or with
# -AllowSystemChanges (otherwise SKIPPED); the key is removed afterwards.
#
# Needs Administrator rights, like the collector (GitHub Actions Windows
# runners are elevated). For a local run without them, pass -CollectorPath
# with a copy of the collector that has no admin check, kept inside the
# repository (e.g. under the git-ignored reports\ folder).
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-CollectEmail.ps1
#   ... -AllowSystemChanges   also run Part 2 outside GitHub Actions
# =============================================================
param(
    # Collector script to test (default: the repository's triage-collector.ps1)
    [string]$CollectorPath = "",
    [switch]$AllowSystemChanges
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$collector = $CollectorPath
if (-not $collector) { $collector = Join-Path $repoRoot "triage-collector.ps1" }
$collector = (Resolve-Path -LiteralPath $collector).Path
# Written into mail contents that must never be copied
$canary = "CANARY-MAIL-CONTENT"
$script:failures = 0
$runLive = [bool]$env:GITHUB_ACTIONS -or $AllowSystemChanges.IsPresent

# PASS/FAIL line; failures are counted and annotated on GitHub Actions
function Write-TestResult {
    param([bool]$Succeeded, [string]$Message)
    if ($Succeeded) {
        Write-Host "PASS: $Message" -ForegroundColor Green
        return
    }
    $script:failures++
    Write-Host "FAIL: $Message" -ForegroundColor Red
    if ($env:GITHUB_ACTIONS) { Write-Host "::error file=tests/Test-CollectEmail.ps1::$Message" }
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

# Runs the collector (Email category only, no prompts, no zip); returns its output
function Invoke-Collector {
    param([string[]]$Arguments)
    $ErrorActionPreference = "Continue"
    $output = & $powershellExe -NoProfile -ExecutionPolicy Bypass -File $collector -Categories Email -Unattended -NoCompress @Arguments 2>&1
    return , @($output | ForEach-Object { "$_" })
}

# Writes a file with the given text (ASCII) and times (UTC text)
function New-TestFile {
    param([string]$Path, [string]$Text = "", [string]$Created = "", [string]$Modified = "", [long]$Length = -1)
    New-Item -ItemType Directory -Path (Split-Path $Path -Parent) -Force | Out-Null
    if ($Length -ge 0) {
        # Allocated without writing (reads back as zeros)
        $stream = [System.IO.File]::Create($Path)
        try { $stream.SetLength($Length) } finally { $stream.Dispose() }
    } else {
        [System.IO.File]::WriteAllText($Path, $Text, [System.Text.Encoding]::ASCII)
    }
    if ($Created) { [System.IO.File]::SetCreationTimeUtc($Path, (ConvertTo-TestTime $Created)) }
    if ($Modified) { [System.IO.File]::SetLastWriteTimeUtc($Path, (ConvertTo-TestTime $Modified)) }
}

# "yyyy-MM-dd HH:mm:ss" UTC text -> UTC [datetime]
function ConvertTo-TestTime {
    param([string]$Text)
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    return [datetime]::ParseExact($Text, "yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture, $styles)
}

# Creates a junction (mklink /J needs no admin rights)
function New-TestJunction {
    param([string]$Link, [string]$Target)
    New-Item -ItemType Directory -Path (Split-Path $Link -Parent) -Force | Out-Null
    $null = cmd /c mklink /J "$Link" "$Target" 2>&1
    if (-not (Test-Path -LiteralPath $Link)) { throw "could not create the junction $Link" }
    $script:junctions += $Link
}

# Rows of a listing CSV by RelativePath, or an empty hashtable if it is missing
function Get-ListingRows {
    param([string]$Path)
    $rows = @{}
    if (Test-Path -LiteralPath $Path) {
        foreach ($row in (Import-Csv -LiteralPath $Path)) { $rows[$row.RelativePath] = $row }
    }
    return $rows
}

# Checks one listing row: present, Status, and CollectedAs (Copied rows)
function Test-ListingRow {
    param([hashtable]$Rows, [string]$RelativePath, [string]$Status, [string]$CollectedAs = "", [string]$Label)
    if (-not $Rows.ContainsKey($RelativePath)) {
        Write-TestResult -Succeeded $false -Message "${Label}: no listing row for $RelativePath"
        return
    }
    $row = $Rows[$RelativePath]
    $problems = @()
    if ($row.Status -ne $Status) { $problems += "Status is '$($row.Status)', expected '$Status'" }
    if ($row.CollectedAs -ne $CollectedAs) { $problems += "CollectedAs is '$($row.CollectedAs)', expected '$CollectedAs'" }
    if ($row.User -ne "alice") { $problems += "User is '$($row.User)'" }
    Write-TestResult -Succeeded ($problems.Count -eq 0) -Message "${Label}: $RelativePath -> $Status$(if ($problems) { ' -- ' + ($problems -join '; ') })"
}

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("email-collect-test-" + [guid]::NewGuid().ToString("N"))
$script:junctions = @()
$driveLetter = ""
$officeParentPath = "Software\Microsoft\Office"
$officeKeyPath = "$officeParentPath\99.0"
$officeKeyCreated = $false
$officeParentCreated = $false
New-Item -ItemType Directory -Path $workDir | Out-Null
try {
    # =========================================================
    # Part 1: mounted image
    # =========================================================
    $image = Join-Path $workDir "image"
    New-Item -ItemType Directory -Path (Join-Path $image "Windows\System32") -Force | Out-Null
    $alice = Join-Path $image "Users\alice"
    New-Item -ItemType Directory -Path (Join-Path $image "Users\bob\Documents"), (Join-Path $image "Users\Public\Documents") -Force | Out-Null

    # Classic Outlook temp folder: a small attachment (newest), an empty
    # file, one over the per-file cap, and 11 x 48 MB files of which the
    # oldest goes over the per-user cap (10 x 48 MB + the small ones fit)
    $contentOutlook = Join-Path $alice "AppData\Local\Microsoft\Windows\INetCache\Content.Outlook"
    New-TestFile -Path (Join-Path $contentOutlook "ABCD1234\invoice.docx") -Text "attachment one" -Created "2026-03-01 10:00:00" -Modified "2026-03-01 10:00:05"
    New-TestFile -Path (Join-Path $contentOutlook "ABCD1234\empty.txt") -Modified "2026-03-01 09:00:00"
    New-TestFile -Path (Join-Path $contentOutlook "EFGH5678\big.bin") -Length (51MB) -Modified "2026-03-01 11:00:00"
    for ($i = 1; $i -le 11; $i++) {
        New-TestFile -Path (Join-Path $contentOutlook ("EFGH5678\fill{0:D2}.bin" -f $i)) -Length (48MB) -Modified ("2026-02-{0:D2} 08:00:00" -f (28 - $i))
    }
    # "Temporary Internet Files" is a junction to INetCache (as on Windows
    # 8 and later): its files must not be listed twice
    New-TestJunction -Link (Join-Path $alice "AppData\Local\Microsoft\Windows\Temporary Internet Files") -Target (Join-Path $alice "AppData\Local\Microsoft\Windows\INetCache")

    # New Outlook: settings, an attachment, mail data (listed only) and a
    # junction to a folder outside the profile (never followed)
    $olk = Join-Path $alice "AppData\Local\Microsoft\Olk"
    New-TestFile -Path (Join-Path $olk "UserSettings.json") -Text '{"Identities":{"IdentityMap":{"alice@example.com":"11111111-2222-3333-4444-555555555555"}}}'
    New-TestFile -Path (Join-Path $olk "Attachments\0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\report.pdf") -Text "attachment two" -Created "2026-03-01 09:30:00" -Modified "2026-03-01 09:30:00"
    New-TestFile -Path (Join-Path $olk "EBWebView\Default\IndexedDB\https_outlook.office.com_0.indexeddb.leveldb\000003.log") -Text "$canary new outlook mail"
    $outside = Join-Path $workDir "outside"
    New-TestFile -Path (Join-Path $outside "outside-secret.txt") -Text "$canary outside"
    New-TestJunction -Link (Join-Path $olk "EBWebView\linked") -Target $outside

    # Classic Outlook data files: listed only (notes.txt is not a data file)
    New-TestFile -Path (Join-Path $alice "AppData\Local\Microsoft\Outlook\alice@example.com.ost") -Text "$canary ost" -Created "2025-11-01 08:00:00" -Modified "2026-03-01 12:00:00"
    New-TestFile -Path (Join-Path $alice "AppData\Local\Microsoft\Outlook\notes.txt") -Text "not a data file"
    New-TestFile -Path (Join-Path $alice "Documents\Outlook Files\archive.pst") -Text "$canary pst"
    New-TestFile -Path (Join-Path $alice "OneDrive - Contoso\Documents\Outlook Files\old.pst") -Text "$canary old pst"

    # Thunderbird: a relative profile and an absolute one (C:\... maps onto
    # the image's drive); mailboxes are listed only
    $thunderbird = Join-Path $alice "AppData\Roaming\Thunderbird"
    New-TestFile -Path (Join-Path $thunderbird "profiles.ini") -Text ("[Profile1]`r`nName=work`r`nIsRelative=0`r`nPath=C:\Users\alice\TBProfiles\work.profile`r`n`r`n" +
        "[Profile0]`r`nName=default-release`r`nIsRelative=1`r`nPath=Profiles/abcd1234.default-release`r`nDefault=1`r`n`r`n[General]`r`nStartWithLastProfile=1`r`n")
    $tbProfile = Join-Path $thunderbird "Profiles\abcd1234.default-release"
    New-TestFile -Path (Join-Path $tbProfile "prefs.js") -Text "user_pref(`"mail.server.server1.hostname`", `"imap.example.com`");`r`n"
    New-TestFile -Path (Join-Path $tbProfile "global-messages-db.sqlite") -Text ("SQLite format 3" + [char]0 + "gloda")
    New-TestFile -Path (Join-Path $tbProfile "global-messages-db.sqlite-wal") -Text "gloda wal"
    New-TestFile -Path (Join-Path $tbProfile "Mail\Local Folders\Inbox") -Text "From - Mon Mar  2 10:00:00 2026`r`n$canary mbox"
    New-TestFile -Path (Join-Path $tbProfile "Mail\Local Folders\Inbox.msf") -Text "// <!-- <mdb:mork:z v=`"1.4`"/> -->"
    New-TestFile -Path (Join-Path $tbProfile "ImapMail\imap.example.com\INBOX") -Text "$canary imap"
    New-TestFile -Path (Join-Path $tbProfile "ImapMail\imap.example.com\INBOX.msf") -Text "msf"
    New-TestFile -Path (Join-Path $tbProfile "ImapMail\imap.example.com\INBOX.sbd\Work") -Text "$canary work"
    New-TestFile -Path (Join-Path $tbProfile "ImapMail\imap.example.com\msgFilterRules.dat") -Text "version=`"9`""
    New-TestFile -Path (Join-Path $alice "TBProfiles\work.profile\prefs.js") -Text "user_pref(`"mail.server.server2.hostname`", `"pop.example.org`");`r`n"

    # Windows Mail: listed only
    $windowsMail = Join-Path $alice "AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe"
    New-TestFile -Path (Join-Path $windowsMail "LocalState\HxStore.hxd") -Text "$canary hx"
    New-TestFile -Path (Join-Path $windowsMail "LocalState\Files\S0\3\Attachments\quote[1].pdf") -Text "$canary quote"
    New-TestFile -Path (Join-Path $alice "AppData\Local\Comms\UnistoreDB\store.vol") -Text "$canary store"

    # Map the image to a free drive letter
    $used = @([System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name.Substring(0, 1).ToUpperInvariant() })
    foreach ($candidate in @("T", "R", "Q", "P", "O", "N", "M", "L", "K", "J", "I", "H")) {
        if ($used -notcontains $candidate) { $driveLetter = $candidate; break }
    }
    if (-not $driveLetter) { throw "no free drive letter for subst" }
    $null = cmd /c subst "${driveLetter}:" "$image" 2>&1
    if (-not (Test-Path -LiteralPath "${driveLetter}:\Windows\System32")) { throw "subst ${driveLetter}: $image failed" }

    $imageOut = Join-Path $workDir "image-collection"
    Write-Host "Running the collector ($powershellExe) on the fake image at ${driveLetter}: ..."
    $output = Invoke-Collector -Arguments @("-TargetDrive", $driveLetter, "-OutputPath", $imageOut)
    if (-not (Test-Path -LiteralPath (Join-Path $imageOut "collection_manifest.csv"))) {
        $output | ForEach-Object { Write-Host "  | $_" }
        throw "the collector wrote no collection to $imageOut"
    }
    $log = [System.IO.File]::ReadAllText((Join-Path $imageOut "collection_log.txt"))
    $manifest = @{}
    foreach ($row in (Import-Csv -LiteralPath (Join-Path $imageOut "collection_manifest.csv"))) { $manifest[$row.RelativePath] = $row }

    # --- Collected files: present, same bytes as the source, in the manifest
    # with the source's original modified time ---
    $userOut = "Email\alice"
    $copies = [ordered]@{
        "$userOut\Outlook\SecureTemp\INetCache\ABCD1234\invoice.docx" = Join-Path $contentOutlook "ABCD1234\invoice.docx"
        "$userOut\NewOutlook\UserSettings.json" = Join-Path $olk "UserSettings.json"
        "$userOut\NewOutlook\Attachments\0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\report.pdf" = Join-Path $olk "Attachments\0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\report.pdf"
        "$userOut\Thunderbird\profiles.ini" = Join-Path $thunderbird "profiles.ini"
        "$userOut\Thunderbird\abcd1234.default-release\prefs.js" = Join-Path $tbProfile "prefs.js"
        "$userOut\Thunderbird\abcd1234.default-release\global-messages-db.sqlite" = Join-Path $tbProfile "global-messages-db.sqlite"
        "$userOut\Thunderbird\abcd1234.default-release\global-messages-db.sqlite-wal" = Join-Path $tbProfile "global-messages-db.sqlite-wal"
        "$userOut\Thunderbird\work.profile\prefs.js" = Join-Path $alice "TBProfiles\work.profile\prefs.js"
    }
    for ($i = 1; $i -le 10; $i++) {
        $name = "fill{0:D2}.bin" -f $i
        $copies["$userOut\Outlook\SecureTemp\INetCache\EFGH5678\$name"] = Join-Path $contentOutlook "EFGH5678\$name"
    }
    foreach ($relative in $copies.Keys) {
        $source = $copies[$relative]
        $copy = Join-Path $imageOut $relative
        $problem = ""
        if (-not (Test-Path -LiteralPath $copy)) { $problem = "not collected" }
        elseif ((Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash) { $problem = "copy differs from the source" }
        elseif (-not $manifest.ContainsKey($relative)) { $problem = "no manifest row" }
        elseif ($manifest[$relative].SHA256 -ne (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash) { $problem = "manifest hash differs" }
        elseif ([datetime]::Parse($manifest[$relative].SourceModifiedUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal) -ne [System.IO.File]::GetLastWriteTimeUtc($source)) { $problem = "manifest SourceModifiedUtc differs from the source" }
        Write-TestResult -Succeeded (-not $problem) -Message "collected: $relative$(if ($problem) { " -- $problem" })"
    }

    # --- Never collected: over the caps, empty, mail contents, link targets ---
    $collectedNames = @(Get-ChildItem -LiteralPath $imageOut -Recurse -File -Force | ForEach-Object { $_.Name })
    foreach ($name in @("big.bin", "fill11.bin", "empty.txt", "alice@example.com.ost", "archive.pst", "old.pst", "Inbox", "INBOX", "Work",
                        "Inbox.msf", "msgFilterRules.dat", "000003.log", "HxStore.hxd", "quote[1].pdf", "store.vol", "outside-secret.txt", "notes.txt")) {
        Write-TestResult -Succeeded ($collectedNames -cnotcontains $name) -Message "not collected: $name"
    }
    # (the 48 MB copies are all zeros)
    $canaryFiles = @(Get-ChildItem -LiteralPath $imageOut -Recurse -File -Force | Where-Object { $_.Length -lt 1MB } |
        Where-Object { [System.IO.File]::ReadAllText($_.FullName).IndexOf($canary, [System.StringComparison]::Ordinal) -ge 0 } | ForEach-Object { $_.Name })
    Write-TestResult -Succeeded ($canaryFiles.Count -eq 0) -Message "no mail content (canary) in any collected file$(if ($canaryFiles) { ': ' + ($canaryFiles -join ', ') })"
    Write-TestResult -Succeeded (-not (Test-Path -LiteralPath (Join-Path $imageOut "Email\bob"))) -Message "no Email\bob folder for a profile without email data"
    Write-TestResult -Succeeded (-not (Test-Path -LiteralPath (Join-Path $imageOut "Email\Public"))) -Message "Public profile skipped"

    # --- Listing CSVs ---
    $tempRows = Get-ListingRows (Join-Path $imageOut "$userOut\Outlook\outlook_temp_files.csv")
    $label = "outlook_temp_files.csv"
    Test-ListingRow -Rows $tempRows -RelativePath "ABCD1234\invoice.docx" -Status "Copied" -CollectedAs "$userOut\Outlook\SecureTemp\INetCache\ABCD1234\invoice.docx" -Label $label
    Test-ListingRow -Rows $tempRows -RelativePath "ABCD1234\empty.txt" -Status "Skipped: empty file" -Label $label
    Test-ListingRow -Rows $tempRows -RelativePath "EFGH5678\big.bin" -Status "Skipped: over the 50 MB per-file cap" -Label $label
    for ($i = 1; $i -le 10; $i++) {
        $name = "fill{0:D2}.bin" -f $i
        Test-ListingRow -Rows $tempRows -RelativePath "EFGH5678\$name" -Status "Copied" -CollectedAs "$userOut\Outlook\SecureTemp\INetCache\EFGH5678\$name" -Label $label
    }
    Test-ListingRow -Rows $tempRows -RelativePath "EFGH5678\fill11.bin" -Status "Skipped: over the 500 MB per-user cap" -Label $label
    Write-TestResult -Succeeded ($tempRows.Count -eq 14) -Message "${label}: $($tempRows.Count) rows (14 expected; the Temporary Internet Files junction is not listed again)"
    $invoice = $tempRows["ABCD1234\invoice.docx"]
    if ($invoice) {
        $timesOk = $invoice.Program -eq "Classic Outlook" -and $invoice.Store -eq "SecureTemp" -and $invoice.SizeBytes -eq "14" -and
            $invoice.CreatedUtc -like "2026-03-01T10:00:00*Z" -and $invoice.ModifiedUtc -like "2026-03-01T10:00:05*Z" -and
            $invoice.Path -eq "${driveLetter}:\Users\alice\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\ABCD1234\invoice.docx"
        Write-TestResult -Succeeded $timesOk -Message "${label}: Program, Store, Path, SizeBytes and UTC times of invoice.docx ($($invoice.Program) | $($invoice.Store) | $($invoice.SizeBytes) | $($invoice.CreatedUtc) | $($invoice.ModifiedUtc))"
    }

    $olkRows = Get-ListingRows (Join-Path $imageOut "$userOut\NewOutlook\olk_files.csv")
    $label = "olk_files.csv"
    Test-ListingRow -Rows $olkRows -RelativePath "UserSettings.json" -Status "Copied" -CollectedAs "$userOut\NewOutlook\UserSettings.json" -Label $label
    Test-ListingRow -Rows $olkRows -RelativePath "Attachments\0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\report.pdf" -Status "Copied" -CollectedAs "$userOut\NewOutlook\Attachments\0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\report.pdf" -Label $label
    Test-ListingRow -Rows $olkRows -RelativePath "EBWebView\Default\IndexedDB\https_outlook.office.com_0.indexeddb.leveldb\000003.log" -Status "Listed" -Label $label
    Write-TestResult -Succeeded ($olkRows.Count -eq 3) -Message "${label}: $($olkRows.Count) rows (3 expected; the junction to a folder outside is not followed)"

    $dataRows = Get-ListingRows (Join-Path $imageOut "$userOut\Outlook\outlook_data_files.csv")
    $label = "outlook_data_files.csv"
    Test-ListingRow -Rows $dataRows -RelativePath "AppData\Local\Microsoft\Outlook\alice@example.com.ost" -Status "Listed" -Label $label
    Test-ListingRow -Rows $dataRows -RelativePath "Documents\Outlook Files\archive.pst" -Status "Listed" -Label $label
    Test-ListingRow -Rows $dataRows -RelativePath "OneDrive - Contoso\Documents\Outlook Files\old.pst" -Status "Listed" -Label $label
    Write-TestResult -Succeeded ($dataRows.Count -eq 3) -Message "${label}: $($dataRows.Count) rows (3 expected)"
    $ost = $dataRows["AppData\Local\Microsoft\Outlook\alice@example.com.ost"]
    if ($ost) {
        Write-TestResult -Succeeded ($ost.CreatedUtc -like "2025-11-01T08:00:00*Z" -and $ost.ModifiedUtc -like "2026-03-01T12:00:00*Z") -Message "${label}: OST times ($($ost.CreatedUtc) | $($ost.ModifiedUtc))"
    }

    $mailRows = Get-ListingRows (Join-Path $imageOut "$userOut\Thunderbird\thunderbird_mail_files.csv")
    $label = "thunderbird_mail_files.csv"
    foreach ($relative in @("Mail\Local Folders\Inbox", "Mail\Local Folders\Inbox.msf", "ImapMail\imap.example.com\INBOX", "ImapMail\imap.example.com\INBOX.msf",
                            "ImapMail\imap.example.com\INBOX.sbd\Work", "ImapMail\imap.example.com\msgFilterRules.dat")) {
        Test-ListingRow -Rows $mailRows -RelativePath $relative -Status "Listed" -Label $label
    }
    Write-TestResult -Succeeded ($mailRows.Count -eq 6) -Message "${label}: $($mailRows.Count) rows (6 expected)"
    $profileNames = @($mailRows.Values | ForEach-Object { $_.Profile } | Sort-Object -Unique)
    Write-TestResult -Succeeded (($profileNames -join ",") -eq "abcd1234.default-release") -Message "${label}: Profile column ($($profileNames -join ','))"

    $windowsMailRows = Get-ListingRows (Join-Path $imageOut "$userOut\WindowsMail\windows_mail_files.csv")
    $label = "windows_mail_files.csv"
    foreach ($relative in @("LocalState\HxStore.hxd", "LocalState\Files\S0\3\Attachments\quote[1].pdf", "UnistoreDB\store.vol")) {
        Test-ListingRow -Rows $windowsMailRows -RelativePath $relative -Status "Listed" -Label $label
    }
    Write-TestResult -Succeeded ($windowsMailRows.Count -eq 3) -Message "${label}: $($windowsMailRows.Count) rows (3 expected)"

    # The listing CSVs are in the manifest too
    foreach ($csv in @("Outlook\outlook_temp_files.csv", "Outlook\outlook_data_files.csv", "NewOutlook\olk_files.csv", "Thunderbird\thunderbird_mail_files.csv", "WindowsMail\windows_mail_files.csv")) {
        Write-TestResult -Succeeded ($manifest.ContainsKey("$userOut\$csv")) -Message "manifest row for $userOut\$csv"
    }

    # --- Log: skips with their reason, image mode, users without data ---
    $logChecks = [ordered]@{
        "per-file cap skip logged"       = "Skipped (over the 50 MB per-file cap): ${driveLetter}:\Users\alice\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\EFGH5678\big.bin"
        "per-user cap skip logged"       = "Skipped (over the 500 MB per-user cap): ${driveLetter}:\Users\alice\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\EFGH5678\fill11.bin"
        "registry lookup skipped (image)" = "Skipping the OutlookSecureTempFolder lookup (mounted image"
        "user without email data logged" = "No email artifacts for bob"
    }
    foreach ($check in $logChecks.Keys) {
        Write-TestResult -Succeeded ($log.Contains($logChecks[$check])) -Message $check
    }
    $logErrors = @($log -split "`r?`n" | Where-Object { $_ -match '\] (ERROR|WARNING): ' -and $_ -notmatch 'time zone could not be read' })
    Write-TestResult -Succeeded ($logErrors.Count -eq 0) -Message "no errors or warnings in the collection log$(if ($logErrors) { ': ' + ($logErrors[0]) })"

    # =========================================================
    # Part 2: live system, OutlookSecureTempFolder outside Content.Outlook
    # =========================================================
    if (-not $runLive) {
        Write-Host "SKIPPED: Part 2 (live system) writes HKCU\$officeKeyPath -- runs only in GitHub Actions or with -AllowSystemChanges" -ForegroundColor Yellow
    } else {
        $hkcu = [Microsoft.Win32.Registry]::CurrentUser
        $existing = $hkcu.OpenSubKey($officeKeyPath)
        if ($null -ne $existing) {
            $existing.Close()
            throw "HKCU\$officeKeyPath already exists -- not touching it"
        }
        $liveFolder = Join-Path $workDir "CustomSecureTemp\XY12"
        New-TestFile -Path (Join-Path $liveFolder "live-attachment.txt") -Text "live attachment" -Modified "2026-03-05 07:00:00"
        $officeParent = $hkcu.OpenSubKey($officeParentPath)
        $officeParentCreated = $null -eq $officeParent
        if ($officeParent) { $officeParent.Close() }
        $officeKeyCreated = $true
        $securityKey = $hkcu.CreateSubKey("$officeKeyPath\Outlook\Security")
        try { $securityKey.SetValue("OutlookSecureTempFolder", "$liveFolder\", [Microsoft.Win32.RegistryValueKind]::String) }
        finally { $securityKey.Close() }

        $liveOut = Join-Path $workDir "live-collection"
        Write-Host "Running the collector ($powershellExe) on the live system ..."
        $output = Invoke-Collector -Arguments @("-OutputPath", $liveOut)
        $liveLogPath = Join-Path $liveOut "collection_log.txt"
        if (-not (Test-Path -LiteralPath $liveLogPath)) {
            $output | ForEach-Object { Write-Host "  | $_" }
            throw "the live collector run wrote no collection to $liveOut"
        }
        $me = Split-Path $env:USERPROFILE -Leaf
        $liveLog = [System.IO.File]::ReadAllText($liveLogPath)
        Write-TestResult -Succeeded ($liveLog.Contains("OutlookSecureTempFolder of $me (Office 99.0): $liveFolder")) -Message "live: OutlookSecureTempFolder read from HKCU"
        $liveRows = Get-ListingRows (Join-Path $liveOut "Email\$me\Outlook\outlook_temp_files.csv")
        $expectedCopy = "Email\$me\Outlook\SecureTemp\Custom\XY12\live-attachment.txt"
        $liveRow = $liveRows["XY12\live-attachment.txt"]
        $liveOk = $liveRow -and $liveRow.Status -eq "Copied" -and $liveRow.CollectedAs -eq $expectedCopy -and $liveRow.ModifiedUtc -like "2026-03-05T07:00:00*Z" -and
            (Test-Path -LiteralPath (Join-Path $liveOut $expectedCopy))
        Write-TestResult -Succeeded $liveOk -Message "live: the folder from the registry is listed and its file copied to $expectedCopy"
    }
}
catch {
    Write-TestResult -Succeeded $false -Message "test setup or run error: $($_.Exception.Message)"
}
finally {
    if ($officeKeyCreated) {
        # The test's own Office version key, and the Office key if the test
        # created it and nothing else was added to it meanwhile
        $removeKey = $officeKeyPath
        try {
            [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($officeKeyPath, $false)
            if ($officeParentCreated) {
                $removeKey = $officeParentPath
                $officeParent = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($officeParentPath)
                $isEmpty = $officeParent -and $officeParent.SubKeyCount -eq 0 -and $officeParent.ValueCount -eq 0
                if ($officeParent) { $officeParent.Close() }
                if ($isEmpty) { [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKey($officeParentPath, $false) }
            }
        }
        catch { Write-Host "WARNING: could not remove HKCU\$removeKey -- remove it manually: $($_.Exception.Message)" -ForegroundColor Yellow }
    }
    if ($driveLetter) { $null = cmd /c subst "${driveLetter}:" /d 2>&1 }
    # Remove the junctions first (rmdir removes the link, not its target)
    foreach ($junction in $script:junctions) { $null = cmd /c rmdir "$junction" 2>&1 }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) {
    Write-Host "FAIL: $($script:failures) check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: all email collection checks passed" -ForegroundColor Green
exit 0
