<#
Exercises hkdfguard-v1-initialize.exe's own behavior - argument parsing,
base64/length validation, --group resolution, and the "don't touch an
existing file without --force" guarantee - none of which is covered by
test_roundtrip.exe (which only calls into hkdfguard.dll directly, never
spawns the CLI). Registered as ctest's "cli" test; see tests/CMakeLists.txt.

Every scenario below is reachable without ever creating a machine-wide KEK
(each one fails - by design - before Run() in hkdfguard-v1-initialize.cpp
ever calls hkdfguard_wrap_dek), so this test passes whether or not the
process is elevated. One additional scenario - a real wrap via the CLI,
plus a --force overwrite of that same file - does need the machine-wide KEK
and so only runs when this process happens to be elevated; it's skipped
(not failed) otherwise, consistent with this project's existing convention
that full wrap/unwrap coverage requires `ctest` to be run elevated.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$CliExePath
)

$ErrorActionPreference = "Stop"
$failures = 0
function Check($condition, $what) {
    if ($condition) {
        Write-Host "[PASS] $what" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $what" -ForegroundColor Red
        $script:failures++
    }
}

# Quotes a single argument for Win32's CreateProcess command-line convention
# (the same one hkdfguard-v1-initialize.exe's own wmain/CommandLineToArgvW
# parses): wrapped in double quotes, with any embedded double quote escaped
# as \" - whenever the argument is empty or contains a space or quote.
# ProcessStartInfo.ArgumentList (which would avoid needing this entirely) is
# unreliable on this Windows PowerShell 5.1 / .NET Framework combination -
# it can come back null - so this builds a single Arguments string instead.
function Format-CliArg([string]$arg) {
    if ($arg -eq "" -or $arg -match '[\s"]') {
        return '"' + ($arg -replace '"', '\"') + '"'
    }
    return $arg
}

# Runs the CLI with the given argv, returning its exit code and captured
# stdout/stderr.
function Invoke-Cli {
    param([string[]]$CliArgs)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $CliExePath
    $psi.Arguments = ($CliArgs | ForEach-Object { Format-CliArg $_ }) -join " "
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    return [PSCustomObject]@{ ExitCode = $proc.ExitCode; StdOut = $stdout; StdErr = $stderr }
}

$workDir = Join-Path $env:TEMP ("hkdfguard-cli-test-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

try {
    $validB64 = [Convert]::ToBase64String((New-Object byte[] 32)) # 32 zero bytes - valid shape, not used for a real wrap

    # ---- 1. --help exits 0. ----
    $r = Invoke-Cli @("--help")
    Check ($r.ExitCode -eq 0) "--help exits 0"

    # ---- 2. No arguments at all: missing required <key-file-path>. ----
    $r = Invoke-Cli @()
    Check ($r.ExitCode -eq 2) "no arguments exits 2 (usage error)"

    # ---- 3. Missing a required flag (--dek). ----
    $keyFile = Join-Path $workDir "missing-dek.key"
    $r = Invoke-Cli @($keyFile, "--material-identifier", "1", "--service-name", "svc", "--group", "Users")
    Check ($r.ExitCode -eq 2) "missing --dek exits 2"

    # ---- 4. An unrecognized argument. ----
    $r = Invoke-Cli @($keyFile, "--bogus-flag", "x")
    Check ($r.ExitCode -eq 2) "unrecognized argument exits 2"

    # ---- 5/6/7. --material-identifier range/type validation (valid range is 1-256). ----
    $r = Invoke-Cli @($keyFile, "--material-identifier", "0", "--service-name", "svc", "--dek", $validB64, "--group", "Users")
    Check ($r.ExitCode -eq 2) "material-identifier 0 (below the 1-256 range) exits 2"

    $r = Invoke-Cli @($keyFile, "--material-identifier", "257", "--service-name", "svc", "--dek", $validB64, "--group", "Users")
    Check ($r.ExitCode -eq 2) "material-identifier 257 (above the 1-256 range) exits 2"

    $r = Invoke-Cli @($keyFile, "--material-identifier", "abc", "--service-name", "svc", "--dek", $validB64, "--group", "Users")
    Check ($r.ExitCode -eq 2) "non-numeric material-identifier exits 2"

    # ---- 8. An unresolvable --group fails before any file is touched. ----
    $bogusGroupKeyFile = Join-Path $workDir "bogus-group.key"
    $r = Invoke-Cli @(
        $bogusGroupKeyFile, "--material-identifier", "1", "--service-name", "svc",
        "--dek", $validB64, "--group", "ThisGroupShouldNotExist12345")
    Check ($r.ExitCode -eq 1) "unresolvable --group exits 1"
    Check (-not (Test-Path $bogusGroupKeyFile)) "unresolvable --group does not create the key file"

    # ---- 9. Invalid base64 in --dek. ----
    $badB64KeyFile = Join-Path $workDir "bad-b64.key"
    $r = Invoke-Cli @(
        $badB64KeyFile, "--material-identifier", "1", "--service-name", "svc",
        "--dek", "not-valid-base64!!!", "--group", "Users")
    Check ($r.ExitCode -eq 1) "invalid base64 --dek exits 1"
    Check (-not (Test-Path $badB64KeyFile)) "invalid base64 --dek does not create the key file"

    # ---- 10. Valid base64 that decodes to the wrong length (16 bytes, not 32). ----
    $wrongLenKeyFile = Join-Path $workDir "wrong-len.key"
    $shortB64 = [Convert]::ToBase64String((New-Object byte[] 16))
    $r = Invoke-Cli @(
        $wrongLenKeyFile, "--material-identifier", "1", "--service-name", "svc",
        "--dek", $shortB64, "--group", "Users")
    Check ($r.ExitCode -eq 1) "wrong-length decoded DEK exits 1"
    Check (-not (Test-Path $wrongLenKeyFile)) "wrong-length decoded DEK does not create the key file"

    # ---- 11b. A --service-name containing a character other than an ASCII ----
    #           alphanumeric or '.' is rejected (the combined
    #           <service-name>.<material-identifier> string must match this
    #           project's macOS/Linux tools' charset restriction).
    $badCharsetKeyFile = Join-Path $workDir "bad-charset.key"
    $r = Invoke-Cli @(
        $badCharsetKeyFile, "--material-identifier", "1", "--service-name", "hkdfguard-cli-test",
        "--dek", $validB64, "--group", "Users")
    Check ($r.ExitCode -eq 1) "a service name containing a hyphen is rejected"
    Check (-not (Test-Path $badCharsetKeyFile)) "a rejected service name does not create the key file"

    # ---- 11. An existing file without --force is left completely untouched. ----
    $existingFile = Join-Path $workDir "existing.key"
    Set-Content -Path $existingFile -Value "pre-existing content" -NoNewline
    $r = Invoke-Cli @(
        $existingFile, "--material-identifier", "1", "--service-name", "svc",
        "--dek", $validB64, "--group", "Users")
    Check ($r.ExitCode -eq 1) "existing file without --force exits 1"
    Check ((Get-Content -Path $existingFile -Raw) -eq "pre-existing content") "existing file without --force is left untouched"

    # ---- 12. Full wrap via the CLI, plus a --force overwrite - needs a real ----
    #          machine-wide KEK, so only runs when elevated.
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        $happyKeyFile = Join-Path $workDir "happy.key"
        # Alphanumeric only - see the "service name containing a hyphen is
        # rejected" scenario above; the CLI's ValidateServiceCharset would
        # reject a hyphenated name like the other tests' "hkdfguard-*" ones.
        $serviceName = "hkdfguardclitest"
        $materialId = 1

        $dekBytes = New-Object byte[] 32
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($dekBytes)
        $dekB64 = [Convert]::ToBase64String($dekBytes)

        $r = Invoke-Cli @(
            $happyKeyFile, "--material-identifier", $materialId, "--service-name", $serviceName,
            "--dek", $dekB64, "--group", "Users", "--force")
        Check ($r.ExitCode -eq 0) "full wrap via the CLI succeeds (elevated)"
        if ($r.ExitCode -ne 0) {
            Write-Host "    exit code: $($r.ExitCode)"
            Write-Host "    stdout: $($r.StdOut)"
            Write-Host "    stderr: $($r.StdErr)"
        }

        $providerName = $null
        if ($r.ExitCode -eq 0) {
            $bytes = [System.IO.File]::ReadAllBytes($happyKeyFile)
            Check ($bytes.Length -eq 132) "CLI-produced wrapped file is 132 bytes"

            $dekBytes2 = New-Object byte[] 32
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($dekBytes2)
            $dekB64_2 = [Convert]::ToBase64String($dekBytes2)
            $r2 = Invoke-Cli @(
                $happyKeyFile, "--material-identifier", $materialId, "--service-name", $serviceName,
                "--dek", $dekB64_2, "--group", "Users", "--force")
            Check ($r2.ExitCode -eq 0) "--force overwrites an existing wrapped-key file"

            $providerType = $bytes[1]
            $providerName = switch ($providerType) {
                1 { "Microsoft Platform Crypto Provider" }
                2 { "Microsoft Software Key Storage Provider" }
                default { $null }
            }
        }

        # Clean up the KEK this test created, mirroring test_roundtrip.exe's
        # own cleanup, so repeated runs don't accumulate persisted keys. Full
        # path, not just "certutil" - this test's PATH is whatever ctest
        # baked into its ENVIRONMENT property at configure time (see
        # tests/CMakeLists.txt), which isn't guaranteed to still resolve
        # ordinary system tools.
        if ($providerName) {
            $keyName = "HkdfGuardWin_${serviceName}.${materialId}_v1"
            $certutilPath = Join-Path $env:SystemRoot "System32\certutil.exe"
            & $certutilPath -csp $providerName -delkey $keyName | Out-Null
        }
    } else {
        Write-Host "[INFO] skipping full-wrap/--force scenarios: not elevated (machine-wide KEK creation requires Administrator)"
    }
}
finally {
    Remove-Item -Recurse -Force $workDir -ErrorAction SilentlyContinue
}

if ($failures -eq 0) {
    Write-Host "`nAll CLI checks passed."
    exit 0
} else {
    Write-Host "`n$failures CLI check(s) failed."
    exit 1
}
