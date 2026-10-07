# =============================================================
# Planted-activity test, step 3: check
# Checks a timeline from win11-timeline-builder for the activity planted by
# tests\Invoke-PlantedActivity.ps1 (see that script for the steps). Each
# planted action is looked up by its marker (TriageE2E_<id>) and source, and
# its time compared with the time it was planted.
#   Required    must be in the timeline -- a miss fails the test
#   Best effort recorded by Windows on its own schedule (or only at
#               shutdown); a miss is reported, not failed
# Exit code 0 = every required check passed, 1 = a required check failed.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-PlantedActivity.ps1
#   ... -PlantedFile <planted.json>  (default: newest one under Downloads)
#   ... -TimelinePath <timeline.csv> (default: newest timeline from a
#                                     win11-timeline-builder folder next to
#                                     this repository)
# =============================================================
param(
    [string]$PlantedFile = "",
    [string]$TimelinePath = "",
    # Allowed difference between a planted time and its timeline time
    [int]$ToleranceSeconds = 120
)

$ErrorActionPreference = "Stop"
$inv = [System.Globalization.CultureInfo]::InvariantCulture

function ConvertTo-UtcTime {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq "") { return $null }
    # PowerShell 7's ConvertFrom-Json already returns [datetime]
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    return [datetime]::Parse([string]$Value, $inv, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
}

# --- Inputs --------------------------------------------------
if (-not $PlantedFile) {
    $PlantedFile = Get-ChildItem -Path (Join-Path $env:USERPROFILE "Downloads\TriageE2E_*\planted.json") -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1 -ExpandProperty FullName
    if (-not $PlantedFile) {
        Write-Host "FAIL: no planted.json found under $env:USERPROFILE\Downloads\TriageE2E_* -- run tests\Invoke-PlantedActivity.ps1 first" -ForegroundColor Red
        exit 1
    }
}
$planted = Get-Content -LiteralPath $PlantedFile -Raw | ConvertFrom-Json
$plantedUtc = ConvertTo-UtcTime $planted.FinishedUtc

if (-not $TimelinePath) {
    $builderReports = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "win11-timeline-builder\reports"
    $TimelinePath = Get-ChildItem -Path (Join-Path $builderReports "timeline_*\timeline.csv") -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1 -ExpandProperty FullName
    if (-not $TimelinePath) {
        Write-Host "FAIL: no timeline found in $builderReports -- run the collector and the builder, or pass -TimelinePath" -ForegroundColor Red
        exit 1
    }
}
if ((Get-Item -LiteralPath $TimelinePath).LastWriteTimeUtc -lt $plantedUtc) {
    Write-Host "FAIL: $TimelinePath is older than the planted activity ($($planted.FinishedUtc)) -- collect and build a new timeline first" -ForegroundColor Red
    exit 1
}

Write-Host "Planted activity: $($planted.Base) (user $($planted.User), $PlantedFile)"
Write-Host "Timeline:         $TimelinePath"

# --- Timeline rows that mention the marker -----------------------
# The timeline can hold hundreds of thousands of rows: only lines with the
# marker (or EICAR) are parsed as CSV
$eicarPlanted = $planted.Steps.Eicar -and $planted.Steps.Eicar.Status -eq "Planted"
$keptLines = New-Object System.Collections.Generic.List[string]
$reader = New-Object System.IO.StreamReader($TimelinePath, [System.Text.Encoding]::UTF8)
try {
    $header = $reader.ReadLine()
    while ($null -ne ($line = $reader.ReadLine())) {
        if ($line.IndexOf($planted.Id, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            ($eicarPlanted -and $line.IndexOf("EICAR", [System.StringComparison]::OrdinalIgnoreCase) -ge 0)) {
            $keptLines.Add($line)
        }
    }
} finally { $reader.Dispose() }
$rows = @()
if ($keptLines.Count -gt 0) {
    $rows = @((@($header) + $keptLines) | ConvertFrom-Csv | ForEach-Object {
        $_ | Add-Member -NotePropertyName Utc -NotePropertyValue ([datetime]::ParseExact($_.Timestamp, "yyyy-MM-dd HH:mm:ss.fff", $inv,
            [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)) -PassThru
    })
}
Write-Host "Rows with the marker: $($rows.Count)"
Write-Host ""

# --- Expectations --------------------------------------------
# Step: planted action; Source/Text: regexes on Source and on
# "Description | Details"; Time: Near (within the tolerance of At), Exact
# (same second as At), After (not before At minus the tolerance) or Any;
# User: the row's User should be the planting user
$b = [regex]::Escape($planted.Base)
$s = $planted.Steps
function New-Expectation {
    param([string]$Step, [string]$Name, [string]$Level, [string]$Source, [string]$Text,
          [string]$Time, $At = $null, [switch]$User, [string]$Why = "", [string]$EventType = "")
    [PSCustomObject]@{ Step = $Step; Name = $Name; Level = $Level; Source = $Source; Text = $Text; Time = $Time
        At = (ConvertTo-UtcTime $At); User = $User.IsPresent; Why = $Why; EventType = $EventType }
}
$expectations = @(
    New-Expectation -Step Run -Name "MFT file created" -Level Required -Source '^MFT$' -Text "^File created: .*\\${b}_run\.exe " -Time Near -At $s.Run.CreatedUtc -User
    New-Expectation -Step Run -Name "USN file created" -Level Required -Source '^UsnJournal$' -Text "^USN created: ${b}_run\.exe " -Time Near -At $s.Run.CreatedUtc
    New-Expectation -Step Run -Name "Prefetch run" -Level Required -Source '^Prefetch$' -Text "^Prefetch execution: ${b}_run\.exe \(run" -Time Near -At $s.Run.TimeUtc
    New-Expectation -Step Run -Name "UserAssist" -Level BestEffort -Source '^Registry-UserAssist$' -Text "${b}_run\.exe" -Time Near -At $s.Run.TimeUtc -User -Why "Windows mainly records launches from Explorer"
    New-Expectation -Step Run -Name "BAM" -Level BestEffort -Source '^BAM$' -Text "${b}_run\.exe" -Time After -At $s.Run.TimeUtc -User -Why "BAM is saved on Windows' own schedule"
    New-Expectation -Step Run -Name "Amcache" -Level BestEffort -Source '^Amcache' -Text "${b}_run\.exe" -Time After -At $s.Run.TimeUtc -Why "Amcache is updated by a scheduled Windows task, not at each run"
    New-Expectation -Step Run -Name "ShimCache" -Level BestEffort -Source '^AppCompatCache$' -Text "${b}_run\.exe" -Time Any -At $s.Run.TimeUtc -Why "ShimCache is written to the registry at shutdown -- restart before collecting"
    New-Expectation -Step Stomp -Name "MFT timestomp flag" -Level Required -Source '^MFT$' -Text "^File created: .*\\${b}_stomp\.exe \[SI<FN\]" -Time Exact -At $s.Stomp.StompTimeUtc
    New-Expectation -Step Doc -Name "Recent shortcut (LNK)" -Level Required -Source '^RecentFiles$' -Text "${b}_doc\.txt" -Time Near -At $s.Doc.TimeUtc -User
    New-Expectation -Step Doc -Name "RecentDocs" -Level Required -Source '^Registry-RecentDocs$' -Text "^Recent document: ${b}_doc\.txt" -Time After -At $s.Doc.TimeUtc -User
    New-Expectation -Step Doc -Name "Jump list" -Level BestEffort -Source '^JumpLists$' -Text "${b}_doc\.txt" -Time After -At $s.Doc.TimeUtc -Why "only recorded when the app that handles the file type opens it"
    New-Expectation -Step Deleted -Name "USN file deleted" -Level Required -Source '^UsnJournal$' -Text "^USN deleted: ${b}_deleted\.txt " -Time Near -At $s.Deleted.DeletedUtc
    New-Expectation -Step Deleted -Name "MFT deleted record" -Level BestEffort -Source '^MFT$' -Text "^Deleted file (created|modified): .*\\${b}_deleted\.txt " -Time Near -At $s.Deleted.CreatedUtc -Why "a freed MFT record is often reused by new files before the collection reads the MFT"
    New-Expectation -Step RunKey -Name "Run key" -Level Required -Source '^(Persistence-RunKeys|Registry-UserRunKey)$' -Text $b -Time After -At $s.RunKey.TimeUtc
    New-Expectation -Step Task -Name "Scheduled task registered" -Level Required -Source '^ScheduledTasks(-XML)?$' -Text "^Scheduled task registered: .*$b" -Time Near -At $s.Task.RegisteredUtc
    New-Expectation -Step Browser -Name "Edge visit" -Level Required -Source 'Edge.*History' -Text "triage-e2e=$($planted.Id)" -Time Near -At $s.Browser.TimeUtc
    New-Expectation -Step Eicar -Name "Defender detection" -Level Required -Source '.' -EventType SecurityAlert -Text 'EICAR' -Time After -At $s.Eicar.TimeUtc
)

# --- Check ---------------------------------------------------
$tolerance = [TimeSpan]::FromSeconds($ToleranceSeconds)
$requiredTotal = 0; $requiredPassed = 0; $bestTotal = 0; $bestFound = 0; $userWarnings = 0
foreach ($e in $expectations) {
    $step = $s.($e.Step)
    $label = "{0,-26} {1,-8}" -f $e.Name, $e.Step
    if (-not $step -or $step.Status -ne "Planted") {
        $why = if ($step) { "$($step.Status): $($step.Message)" } else { "not in planted.json" }
        Write-Host "  SKIP  $label step not planted ($why)" -ForegroundColor DarkGray
        continue
    }
    if ($e.Level -eq "Required") { $requiredTotal++ } else { $bestTotal++ }

    $candidates = @($rows | Where-Object {
        $_.Source -match $e.Source -and ("$($_.Description) | $($_.Details)" -match $e.Text) -and
        (-not $e.EventType -or $_.EventType -eq $e.EventType)
    })
    $timeOk = {
        param($row)
        $delta = $row.Utc - $e.At
        switch ($e.Time) {
            "Near"  { return [Math]::Abs($delta.TotalSeconds) -le $tolerance.TotalSeconds }
            "Exact" { return [Math]::Abs($delta.TotalSeconds) -lt 1 }
            "After" { return $delta.TotalSeconds -ge -$tolerance.TotalSeconds }
            default { return $true }
        }
    }
    $match = $candidates | Where-Object { & $timeOk $_ } | Sort-Object { [Math]::Abs(($_.Utc - $e.At).TotalSeconds) } | Select-Object -First 1
    if ($match) {
        $delta = [Math]::Round(($match.Utc - $e.At).TotalSeconds)
        $deltaText = if ($e.Time -eq "Any") { "" } else { " ({0:+0;-0;0} s)" -f $delta }
        $text = $match.Description
        if ($text.Length -gt 90) { $text = $text.Substring(0, 87) + "..." }
        $note = ""
        if ($e.User -and $match.User -and $match.User -ne $planted.User) {
            $note = " [user '$($match.User)', expected '$($planted.User)']"
            $userWarnings++
        }
        Write-Host "  PASS  $label $($match.Timestamp)$deltaText  $text$note" -ForegroundColor $(if ($note) { "Yellow" } else { "Green" })
        if ($e.Level -eq "Required") { $requiredPassed++ } else { $bestFound++ }
        continue
    }

    if ($candidates.Count -gt 0) {
        $closest = $candidates | Sort-Object { [Math]::Abs(($_.Utc - $e.At).TotalSeconds) } | Select-Object -First 1
        $reason = "$($candidates.Count) row(s) found, none at the expected time ($($e.Time) $($e.At.ToString('yyyy-MM-dd HH:mm:ss', $inv)) UTC); closest $($closest.Timestamp)"
    } else {
        $reason = "not in the timeline"
    }
    if ($e.Level -eq "Required") {
        Write-Host "  FAIL  $label $reason" -ForegroundColor Red
        if ($env:GITHUB_ACTIONS) { Write-Host "::error::$($e.Name): $reason" }
    } else {
        Write-Host "  --    $label $reason (best effort: $($e.Why))" -ForegroundColor DarkYellow
    }
}

Write-Host ""
Write-Host "Required: $requiredPassed of $requiredTotal passed; best effort: $bestFound of $bestTotal found"
if ($userWarnings -gt 0) { Write-Host "$userWarnings row(s) attributed to a different user (see above)" -ForegroundColor Yellow }
if ($requiredPassed -lt $requiredTotal) {
    Write-Host "FAIL" -ForegroundColor Red
    exit 1
}
Write-Host "PASS" -ForegroundColor Green
Write-Host "Clean up with: powershell -ExecutionPolicy Bypass -File tests\Invoke-PlantedActivity.ps1 -Cleanup" -ForegroundColor DarkGray
exit 0
