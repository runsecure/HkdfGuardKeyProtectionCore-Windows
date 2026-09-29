<#
Exercises hkdfguard-v1-initialize.exe's own behavior - subcommand dispatch,
argument parsing, base64/length validation, --group resolution, and the
"don't touch an existing file without --force" guarantee - none of which is
covered by test_roundtrip.exe (which only calls into hkdfguard.dll directly,
never spawns the CLI). Registered as ctest's "cli" test; see
tests/CMakeLists.txt.

The CLI has two subcommands: "provision" (calls hkdfguard_kek_exists /
hkdfguard_create_kek only) and "wrap" (calls hkdfguard_wrap_dek only, against
an already-provisioned KEK; the DEK is fed to it as base64 text on stdin via
--dek-stdin, never as a command-line argument).

Most scenarios below are reachable without ever creating a machine-wide KEK
(each one fails - by design - before RunWrap()/RunProvision() in
hkdfguard-v1-initialize.cpp ever calls into hkdfguard.dll), so this test
passes whether or not the process is elevated. This includes "wrap" against a
service that was never provisioned - opening a nonexistent key fails
(NTE_BAD_KEYSET -> HKDFGUARD_ERR_KEK_NOT_FOUND) regardless of privilege
level, so that scenario also runs unconditionally. The handful of scenarios
that need a real, persisted machine-wide KEK (an actual provision + wrap
round trip, and a --force overwrite of the resulting file) do need the
machine-wide KEK and so only run when this process happens to be elevated;
they're skipped (not failed) otherwise, consistent with this project's
existing convention that full wrap/unwrap coverage requires `ctest` to be
run elevated.
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
# stdout/stderr. When $StdIn is non-null, it's written to the child's stdin
# (as-is, no trailing newline added) and the pipe is closed - this is how
# "wrap --dek-stdin" scenarios below supply their base64 DEK text. $StdIn
# left as $null (the default) leaves stdin unredirected, for subcommands/
# scenarios that never read it.
function Invoke-Cli {
    param(
        [string[]]$CliArgs,
        [string]$StdIn = $null
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $CliExePath
    $psi.Arguments = ($CliArgs | ForEach-Object { Format-CliArg $_ }) -join " "
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    if ($null -ne $StdIn) {
        $psi.RedirectStandardInput = $true
    }
    $proc = [System.Diagnostics.Process]::Start($psi)
    if ($null -ne $StdIn) {
        $proc.StandardInput.Write($StdIn)
        $proc.StandardInput.Close()
    }
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    return [PSCustomObject]@{ ExitCode = $proc.ExitCode; StdOut = $stdout; StdErr = $stderr }
}

$workDir = Join-Path $env:TEMP ("hkdfguard-cli-test-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

try {
    $validB64 = [Convert]::ToBase64String((New-Object byte[] 32)) # 32 zero bytes - valid shape, not used for a real wrap

    # ---- 1. Top-level --help exits 0. ----
    $r = Invoke-Cli @("--help")
    Check ($r.ExitCode -eq 0) "--help exits 0"

    # ---- 2. No arguments at all: missing required subcommand. ----
    $r = Invoke-Cli @()
    Check ($r.ExitCode -eq 2) "no arguments exits 2 (usage error)"

    # ---- 3. An unrecognized top-level command. ----
    $r = Invoke-Cli @("frobnicate")
    Check ($r.ExitCode -eq 2) "unrecognized command exits 2"

    # ---- 4. wrap: missing a required flag (--dek-stdin). ----
    $keyFile = Join-Path $workDir "missing-dek.key"
    $r = Invoke-Cli @("wrap", "--key-file-path", $keyFile, "--service-name", "svc", "--group", "Users")
    Check ($r.ExitCode -eq 2) "wrap missing --dek-stdin exits 2"

    # ---- 5. wrap: an unrecognized argument. ----
    $r = Invoke-Cli @("wrap", "--key-file-path", $keyFile, "--bogus-flag", "x")
    Check ($r.ExitCode -eq 2) "wrap unrecognized argument exits 2"

    # ---- 6. provision: missing the required --service-name. ----
    $r = Invoke-Cli @("provision")
    Check ($r.ExitCode -eq 2) "provision missing --service-name exits 2"

    # ---- 7. wrap: an unresolvable --group fails before any file is touched. ----
    $bogusGroupKeyFile = Join-Path $workDir "bogus-group.key"
    $r = Invoke-Cli @(
        "wrap", "--key-file-path", $bogusGroupKeyFile, "--service-name", "svc", "--dek-stdin",
        "--group", "ThisGroupShouldNotExist12345") -StdIn $validB64
    Check ($r.ExitCode -eq 1) "wrap unresolvable --group exits 1"
    Check (-not (Test-Path $bogusGroupKeyFile)) "wrap unresolvable --group does not create the key file"

    # ---- 8. wrap: invalid base64 on stdin. ----
    $badB64KeyFile = Join-Path $workDir "bad-b64.key"
    $r = Invoke-Cli @(
        "wrap", "--key-file-path", $badB64KeyFile, "--service-name", "svc", "--dek-stdin",
        "--group", "Users") -StdIn "not-valid-base64!!!"
    Check ($r.ExitCode -eq 1) "wrap invalid base64 on stdin exits 1"
    Check (-not (Test-Path $badB64KeyFile)) "wrap invalid base64 on stdin does not create the key file"

    # ---- 9. wrap: valid base64 that decodes to the wrong length (16 bytes, not 32). ----
    $wrongLenKeyFile = Join-Path $workDir "wrong-len.key"
    $shortB64 = [Convert]::ToBase64String((New-Object byte[] 16))
    $r = Invoke-Cli @(
        "wrap", "--key-file-path", $wrongLenKeyFile, "--service-name", "svc", "--dek-stdin",
        "--group", "Users") -StdIn $shortB64
    Check ($r.ExitCode -eq 1) "wrap wrong-length decoded DEK exits 1"
    Check (-not (Test-Path $wrongLenKeyFile)) "wrap wrong-length decoded DEK does not create the key file"

    # ---- 10. wrap: a --service-name containing a character other than an ----
    #          ASCII alphanumeric or '.' is rejected.
    $badCharsetKeyFile = Join-Path $workDir "bad-charset.key"
    $r = Invoke-Cli @(
        "wrap", "--key-file-path", $badCharsetKeyFile, "--service-name", "hkdfguard-cli-test", "--dek-stdin",
        "--group", "Users") -StdIn $validB64
    Check ($r.ExitCode -eq 1) "wrap: a service name containing a hyphen is rejected"
    Check (-not (Test-Path $badCharsetKeyFile)) "wrap: a rejected service name does not create the key file"

    # ---- 11. wrap: an existing file without --force is left completely untouched. ----
    $existingFile = Join-Path $workDir "existing.key"
    Set-Content -Path $existingFile -Value "pre-existing content" -NoNewline
    $r = Invoke-Cli @(
        "wrap", "--key-file-path", $existingFile, "--service-name", "svc", "--dek-stdin",
        "--group", "Users") -StdIn $validB64
    Check ($r.ExitCode -eq 1) "wrap existing file without --force exits 1"
    Check ((Get-Content -Path $existingFile -Raw) -eq "pre-existing content") "wrap existing file without --force is left untouched"

    # ---- 12. wrap against a service that was never provisioned reports an ----
    #          error (HKDFGUARD_ERR_KEK_NOT_FOUND) rather than silently
    #          failing or creating a KEK. Opening a nonexistent key fails
    #          regardless of elevation, so this runs unconditionally.
    $neverProvisionedService = "hkdfguardnokek" + [Guid]::NewGuid().ToString("N")
    $noKekFile = Join-Path $workDir "no-kek.key"
    $r = Invoke-Cli @(
        "wrap", "--key-file-path", $noKekFile, "--service-name", $neverProvisionedService, "--dek-stdin",
        "--group", "Users") -StdIn $validB64
    Check ($r.ExitCode -eq 1) "wrap against a never-provisioned service exits 1"
    Check (-not (Test-Path $noKekFile)) "wrap against a never-provisioned service does not create the key file"
    Check ($r.StdErr -match "KEK|provision") "wrap against a never-provisioned service reports a KEK-not-found/provision error"

    # ---- 13. Full provision + wrap via the CLI, plus a --force overwrite - ----
    #          needs a real machine-wide KEK, so only runs when elevated.
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        $happyKeyFile = Join-Path $workDir "happy.key"
        # Alphanumeric only - see the "service name containing a hyphen is
        # rejected" scenario above; the CLI's ValidateServiceCharset would
        # reject a hyphenated name like the other tests' "hkdfguard-*" ones.
        $serviceName = "hkdfguardclitest"

        $pr = Invoke-Cli @("provision", "--service-name", $serviceName)
        Check ($pr.ExitCode -eq 0) "provision succeeds (elevated)"
        if ($pr.ExitCode -ne 0) {
            Write-Host "    exit code: $($pr.ExitCode)"
            Write-Host "    stdout: $($pr.StdOut)"
            Write-Host "    stderr: $($pr.StdErr)"
        }

        $dekBytes = New-Object byte[] 32
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($dekBytes)
        $dekB64 = [Convert]::ToBase64String($dekBytes)

        $r = Invoke-Cli @(
            "wrap", "--key-file-path", $happyKeyFile, "--service-name", $serviceName, "--dek-stdin",
            "--group", "Users", "--force") -StdIn $dekB64
        Check ($r.ExitCode -eq 0) "full wrap via the CLI succeeds against a provisioned KEK (elevated)"
        if ($r.ExitCode -ne 0) {
            Write-Host "    exit code: $($r.ExitCode)"
            Write-Host "    stdout: $($r.StdOut)"
            Write-Host "    stderr: $($r.StdErr)"
        }

        $providerName = $null
        if ($r.ExitCode -eq 0) {
            $bytes = [System.IO.File]::ReadAllBytes($happyKeyFile)
            Check ($bytes.Length -eq 164) "CLI-produced wrapped file is 164 bytes"

            $dekBytes2 = New-Object byte[] 32
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($dekBytes2)
            $dekB64_2 = [Convert]::ToBase64String($dekBytes2)
            $r2 = Invoke-Cli @(
                "wrap", "--key-file-path", $happyKeyFile, "--service-name", $serviceName, "--dek-stdin",
                "--group", "Users", "--force") -StdIn $dekB64_2
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
            # Matches kek_store.cpp's KeyName(): every piece is lowercase, and
            # $serviceName is already lowercase.
            $keyName = "hkdfguardwin_${serviceName}_v1"
            $certutilPath = Join-Path $env:SystemRoot "System32\certutil.exe"
            & $certutilPath -csp $providerName -delkey $keyName | Out-Null
        }
    } else {
        Write-Host "[INFO] skipping provision/full-wrap/--force scenarios: not elevated (machine-wide KEK creation requires Administrator)"
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
