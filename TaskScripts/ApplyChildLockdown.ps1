<#
.SYNOPSIS
Creates a local standard (non-Microsoft) user, ensures system-wide Google Chrome is installed, and applies hardening/lockdown.

.DESCRIPTION
GET THE LATEST VERSION FROM https://github.com/philliphall/Child-School-Account-Lockdown.git!!!
All per-deployment settings live in the $Config block at the top of this script (allowed
apps, autostart app, allowed sign-in emails, Chrome policy lists, debloat patterns). The
config block is the only thing you edit per deployment; rerun the script after editing so
the secure ProgramData copy used by the logon task is refreshed.

1) Prompts for a local child account name and creates a STANDARD local user.
2) Ensures Google Chrome is installed system-wide. If missing, downloads the official Enterprise MSI and installs silently.
2a) Optionally removes built-in distraction apps matching $Config.DebloatPatterns (best-effort, appx/provisioned).
3) Applies Chrome per-user policies (child user hive) to:
   - Disable Guest Mode
   - Disable Incognito
   - Disable adding new profiles
   - Force browser sign-in
   - Restrict sign-in to allowed email(s) ($Config.AllowedSigninEmails; prompts when empty)
   - Block dangerous downloads and force SafeSearch ($Config.Chrome)
   - Block extension installs except $Config.Chrome.ExtensionAllowlist
   - Block high-risk chrome:// pages
4) Applies Windows per-user lockdown policies ONLY to the target child user (not admins).
   If the child has never signed in (no profile hive yet), the script exits and instructs a sign-in/sign-out,
   then rerun, so policies are applied directly to the user hive.
4a) Applies machine policy to disable Widgets/Feeds, disable location, suppress OneDrive backup/sign-in prompts,
    and creates a child logon task for taskbar UI toggles.
5) Applies shell cleanup for the child:
   - Removes desktop and taskbar shortcuts that do not match $Config.AllowedApps
   - Sets $Config.AutostartApp (if configured) to auto-start at child sign-in
6) Blocks $Config.BlockedAppExeNames by name (Explorer DisallowRun), and applies
   execute-deny ACLs to child-writable folders (Desktop, Downloads, Documents, media
   folders, Temp, and both AppData trees) to reduce rename/copy bypasses. The ACLs are
   the load-bearing half of that pair - see BlockedAppExeNames for why.

SAFETY
- Does NOT modify Administrator account.
- Chrome and Windows lockdown policies are written only to the target child user profile hive.
- Per-user lockdown is applied ONLY to the specified child account SID.

USAGE (run as Administrator)
  .\ApplyChildLockdown.ps1

Rollback
  .\ApplyChildLockdown.ps1 -RemoveChromePolicies -UserName <name>
  .\ApplyChildLockdown.ps1 -RemoveUserLockdown -UserName <name>

NOTES
- RestrictSigninToPattern accepts a single pattern string. For multiple emails this script uses a regex OR pattern: ^(a@b.com|c@d.com)$
- Some Start/Search/Store policy behaviors vary across Windows versions. This script uses common registry-backed equivalents.
#>

[CmdletBinding()]
param(
  [switch]$RemoveChromePolicies,
  [switch]$RemoveUserLockdown,
  [string]$UserName,

  # Internal switches used by the scheduled task
  [switch]$InternalApplyUserLockdown,
  [string]$InternalUserSid,
  [string]$InternalRestrictSigninPatternRegexBase64
)

# =====================================================================================
# DEPLOYMENT CONFIG - this block is the only thing you edit per deployment.
# The child-logon task runs the copy under ProgramData\ChildLockdown\TaskScripts, which
# is refreshed each interactive run - rerun this script after editing the config.
# =====================================================================================
$Config = @{
  # Apps the child is meant to use. This drives which shortcuts and taskbar pins survive
  # the shell cleanup, and which app autostarts - it is NOT an execution allow list.
  # Blocking is done by name in BlockedAppExeNames.
  #   Name           - display name; AutostartApp refers to it.
  #   ExeNames       - executable leaf names matched against shortcut targets.
  #   ShortcutMatch  - regex matched against shortcut filenames kept during desktop/taskbar cleanup.
  #   AppxMatch      - regex for Store-packaged apps whose real executable names must be
  #                    read from the package manifest ($null for classic Win32 installs).
  #   PathCandidates - full-path globs used to resolve the executable for autostart.
  AllowedApps = @(
    @{
      Name           = 'Google Chrome'
      ExeNames       = @('chrome.exe')
      ShortcutMatch  = '(?i)chrome'
      AppxMatch      = $null
      PathCandidates = @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
      )
    },
    @{
      Name           = 'Alpha TimeBack'
      ExeNames       = @('TimeBack.exe', 'AlphaTimeBack.exe', 'Alpha TimeBack.exe')
      ShortcutMatch  = '(?i)(time\s*back|alpha\s*time\s*back)'
      AppxMatch      = '(?i)(timeback|alpha)'
      # Ships as an MSIX/Store package (AlphaSchool.AlphaTimeBack), so it lives under
      # C:\Program Files\WindowsApps and is activated by AUMID, not by a fixed path.
      # AppxMatch above is what resolves its real exe name from the package manifest.
      # Only the autostart app is ever launched by path, so leave this empty.
      PathCandidates = @()
    }
  )

  # Which allowed app launches at child sign-in ($null disables autostart).
  AutostartApp  = 'Google Chrome'
  AutostartArgs = '--no-first-run --start-maximized'

  # Google account(s) the child may sign into Chrome with. Empty = prompt interactively.
  AllowedSigninEmails = @()

  # Seconds of idle before the lock screen engages.
  IdleLockSeconds = 300

  # Executables the child is blocked from launching (Explorer DisallowRun).
  #
  # This is a deny list, and that is a deliberate reversal. An allow list (RestrictRun)
  # was tried first and had to be abandoned: it refuses every executable not named in
  # it, Windows' own components included, and each refusal raises "This operation has
  # been cancelled due to restrictions in effect on this computer" in the child's face.
  # Explorer, OneDrive, the Windows Security tray and the Realtek audio service each
  # produced their own storm of those dialogs and there was no end to the list.
  # The allow list also missed what mattered most: packaged (MSIX) apps are activated
  # by AUMID and never checked against it, and neither is a CreateProcess from an
  # already-running program - so Windows Terminal alone defeated the whole thing.
  #
  # What actually confines the child is not this list. It is: no administrator rights,
  # execute-deny ACLs on every folder they can write to, the packaged apps removed for
  # them in ChildOnlyAppxPatterns, Chrome policy, and Family Link. This list is the
  # last layer, and its only job is to stop a child opening something obvious that is
  # already installed machine-wide.
  #
  # DisallowRun matches on file name alone, so renaming defeats it. That is acceptable
  # precisely because the renamed copy has to be saved somewhere the child can write,
  # and every one of those folders is execute-denied.
  #
  # NEVER add explorer.exe here - it is the desktop, and blocking it crash-loops the
  # shell. Assert-LockdownConfig refuses that outright.
  BlockedAppExeNames = @(
    # Browsers. Chrome is the one they keep, because Family Link's content filtering
    # follows the Chrome profile and nothing else. Any other browser goes around it.
    'msedge.exe', 'iexplore.exe', 'firefox.exe', 'brave.exe', 'opera.exe',
    'opera_gx.exe', 'vivaldi.exe', 'chromium.exe', 'tor.exe', 'torbrowser.exe',
    'duckduckgo.exe', 'maxthon.exe', 'palemoon.exe', 'waterfox.exe',
    # Shells, terminals and script hosts. Any one of these can start anything else,
    # which would make every other entry in this list pointless.
    'cmd.exe', 'powershell.exe', 'powershell_ise.exe', 'pwsh.exe', 'wt.exe',
    'wscript.exe', 'cscript.exe', 'mshta.exe', 'bash.exe', 'wsl.exe', 'sh.exe',
    'python.exe', 'pythonw.exe', 'node.exe',
    # Administration tools. Most are already blocked by policy (DisableCMD,
    # DisableRegistryTools, DisableTaskMgr); these are the belt to that braces.
    'regedit.exe', 'regedt32.exe', 'mmc.exe', 'taskmgr.exe', 'msconfig.exe',
    'runas.exe', 'cmstp.exe',
    # Remote access - a child inviting someone else onto the machine.
    'mstsc.exe', 'teamviewer.exe', 'anydesk.exe', 'vncviewer.exe', 'quickassist.exe',
    # Games, game stores and chat. These are the ones that actually get installed.
    'steam.exe', 'epicgameslauncher.exe', 'robloxplayerbeta.exe',
    'robloxplayerlauncher.exe', 'discord.exe', 'minecraft.exe',
    'minecraftlauncher.exe', 'battle.net.exe', 'galaxyclient.exe', 'itch.exe',
    'xboxapp.exe', 'gamebar.exe',
    # Office. Installed machine-wide on this laptop and reachable from the Start menu.
    # The children's schoolwork is Alpha TimeBack and the web, so none of this is needed.
    # Blocking by name leaves the parent's own Office untouched - the policy is per-user.
    'powerpnt.exe', 'winword.exe', 'excel.exe', 'msaccess.exe', 'mspub.exe',
    'onenote.exe', 'outlook.exe', 'setlang.exe', 'lync.exe',
    # Third-party software already on the machine.
    'bootstrapper.exe',   # Google Play Games launcher
    'nordvpn.exe',        # a VPN would route straight around Family Link's filtering
    'mc-launch.exe',      # McAfee console
    'hostappservice.exe', # "App Explorer" - bundled adware
    'wmplayer.exe',
    # System tools reachable from the Start menu. The .msc consoles (Event Viewer,
    # Computer Management, Services, Task Scheduler, Firewall) all run through mmc.exe,
    # which is already blocked above, so they need no entries of their own.
    'control.exe',        # legacy Control Panel; the Settings app is unaffected
    'msinfo32.exe', 'perfmon.exe', 'cleanmgr.exe', 'dfrgui.exe', 'psr.exe',
    'charmap.exe', 'odbcad32.exe', 'iscsicpl.exe', 'mdsched.exe', 'recoverydrive.exe'
    # Deliberately NOT blocked: magnify.exe, narrator.exe, osk.exe, voiceaccess.exe,
    # LiveCaptions.exe. Those are accessibility tools and stay available to every child.
  )

  # Start menu entries the child keeps. Everything else in their Start menu is hidden.
  # This one is an allow list where BlockedAppExeNames is a deny list, and the asymmetry
  # is deliberate: hiding a shortcut produces no dialog, the entry simply is not there.
  # So the failure mode of too short a list here is a missing icon, not an error message
  # on a loop - which is exactly the trap the execution allow list fell into.
  ChildKeptShortcutPatterns = @(
    '(?i)chrome',                                   # the browser they use
    '(?i)(time\s*back|alpha)',                      # Alpha TimeBack
    '(?i)^settings', '(?i)file\s*explorer',         # the shell itself
    '(?i)(calculator|notepad|paint|camera|photos|snip)',  # ordinary schoolwork tools
    '(?i)(magnif|narrator|on-screen|voice\s*access|live\s*caption|accessibility)'
  )

  # Settings app pages visible to the child.
  SettingsPages = 'showonly:network-status;network-wifi;network-wifisettings;display;bluetooth;devices'

  # Built-in apps offered for removal during interactive setup.
  # Removed machine-wide (-AllUsers) AND from the system image, so this hits the parent
  # account and every future account too - not just the child. Weigh accordingly.
  # This is the main defence against Store apps: neither DisallowRun nor the allow list
  # before it ever sees a packaged app, because those are activated by AUMID rather than
  # by executable name - so anything left here is still launchable by the child.
  # Paint, WindowsCamera and Teams are deliberately NOT listed - they have genuine
  # schoolwork uses (Teams especially; many schools run classes through it). Do not
  # re-add them without asking.
  DebloatPatterns = @('*Outlook*','*MicrosoftSolitaireCollection*','*Xbox*',
                      '*GamingApp*','*LinkedIn*','*Copilot*',
                      '*WindowsFeedbackHub*','*Bing*','*Clipchamp*','*News*')

  # Packaged (MSIX/Store) apps removed for the CHILD ONLY - the parent account keeps them.
  # This list exists because name-based policy does not cover packaged apps: they are
  # activated by AUMID through the app model, not by executable name, so neither the
  # deny list nor the allow list before it ever sees them. Alpha TimeBack launching
  # under lockdown is the proof of that - and it is why removal is the only lever here.
  # WindowsTerminal and PowerAutomateDesktop are the important two - both can start
  # arbitrary processes via CreateProcess, which is not filtered by name-based policy
  # either, so either one is a complete escape.
  # WindowsStore is here because a standard user can install MSIX packages with no
  # elevation at all, and anything installed that way would run for the same reason.
  ChildOnlyAppxPatterns = @('*WindowsTerminal*','*PowerAutomateDesktop*',
                            '*WindowsStore*','*StorePurchaseApp*',
                            '*QuickAssist*','*RandomSaladGames*','*AmazingGames*',
                            '*YourPhone*','*ZuneMusic*','*DevHome*',
                            '*Client.WebExperience*','*MicrosoftOfficeHub*','*DropboxOEM*',
                            # Chat and social - the point of the machine is schoolwork.
                            '*WhatsApp*','*MSTeams*','*Teams*','*CrossDevice*',
                            # Distractions with no schoolwork use.
                            '*StickyNotes*','*Todos*','*WindowsAlarms*',
                            '*WindowsSoundRecorder*','*GetHelp*','*Xbox*','*GamingApp*',
                            # OEM and vendor bloat shipped on this Acer.
                            '*AcerRegistration*','*AcerPurifiedVoice*','*AcerSense*',
                            '*UserExperienceImprovementProgram*','*McAfee*',
                            '*AMDRadeonSoftware*','*RealtekAudioControl*')
  # Not listed, on purpose: '*DesktopAppInstaller*'. App Installer is what opens a
  # downloaded .msix on double-click, which is the one remaining way a packaged app
  # could reach the child without the Store. It is left in place because it is also
  # what installs Alpha TimeBack for a new child account. Add it here if a child ever
  # tries that route - by then TimeBack is already installed for them.
  # Note: removals show as 'Installed(pending removal)' while the child is signed in
  # and only finish at their next sign-out. That is normal, not a failure.

  # Profile-relative directories that get execute permission granted back after the
  # blanket AppData execute-deny. Each entry is a hole in the lockdown - a renamed
  # allowlisted exe could run from here - so keep this list as short as possible.
  # CreateIfMissing pre-creates the directory so it never inherits the deny later;
  # leave it $false for directories another installer owns.
  # If Alpha TimeBack misbehaves once locked down, add:
  #   @{ Path = 'AppData\Local\Packages\AlphaSchool.AlphaTimeBack_2cre1vc9g7k1j'; CreateIfMissing = $false }
  ExecuteCarveOuts = @(
    @{ Path = 'AppData\Local\Google'; CreateIfMissing = $true }
  )

  Chrome = @{
    # 2 = block dangerous file types only; 3 = block ALL downloads.
    DownloadRestrictions = 2
    ForceSafeSearch      = $true
    # 0 = off (defer to Family Link supervision of the signed-in account), 1 = moderate, 2 = strict.
    YouTubeRestrict      = 0
    URLAllowlist         = @('chrome://policy')
    URLBlocklist         = @()
    # Extension IDs allowed despite the block-all default (chrome://extensions shows IDs).
    ExtensionAllowlist   = @()
  }
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:TranscriptStartedByScript = $false
$script:AllowedAppExeNamesCache = $null

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This script must be run from an elevated PowerShell (Run as administrator).'
  }
}

function Assert-LockdownConfig {
  # Fail loudly on a malformed config: the logon task runs this script headlessly, so a
  # silent config error would otherwise only surface in the transcript log.
  if (-not $Config -or -not $Config.ContainsKey('AllowedApps') -or (@($Config.AllowedApps).Count -eq 0)) {
    throw 'Config error: $Config.AllowedApps must contain at least one app.'
  }
  foreach ($app in $Config.AllowedApps) {
    if (-not $app.ContainsKey('Name') -or [string]::IsNullOrWhiteSpace([string]$app.Name)) {
      throw 'Config error: every AllowedApps entry needs a non-empty Name.'
    }
    if (-not $app.ContainsKey('ExeNames') -or (@($app.ExeNames | Where-Object { $_ }).Count -eq 0)) {
      throw "Config error: AllowedApps entry '$($app.Name)' needs at least one ExeNames value."
    }
  }
  if ($Config.AutostartApp) {
    $appNames = @($Config.AllowedApps | ForEach-Object { $_.Name })
    if ($appNames -notcontains $Config.AutostartApp) {
      throw "Config error: AutostartApp '$($Config.AutostartApp)' does not match any AllowedApps Name."
    }
  }
  if (($Config.IdleLockSeconds -isnot [int]) -or ($Config.IdleLockSeconds -lt 0)) {
    throw 'Config error: IdleLockSeconds must be a non-negative integer.'
  }
  if (-not $Config.ContainsKey('BlockedAppExeNames') -or
      (@($Config.BlockedAppExeNames | Where-Object { $_ }).Count -eq 0)) {
    throw 'Config error: BlockedAppExeNames must contain at least one executable name.'
  }
  foreach ($exe in @($Config.BlockedAppExeNames)) {
    if ([string]::IsNullOrWhiteSpace([string]$exe)) {
      throw 'Config error: BlockedAppExeNames must not contain empty entries.'
    }
    if ([string]$exe -notmatch '(?i)\.(exe|com|scr|bat|cmd)$') {
      throw "Config error: BlockedAppExeNames entry '$exe' does not look like an executable name."
    }
    if ([string]$exe -match '[\\/]') {
      throw "Config error: BlockedAppExeNames entry '$exe' must be a bare file name - DisallowRun ignores paths."
    }
  }
  # explorer.exe is the desktop itself. Blocking it means Windows cannot relaunch the
  # shell, so it dies and respawns and the child gets a dialog every few seconds forever.
  if (@($Config.BlockedAppExeNames) -contains 'explorer.exe') {
    throw 'Config error: BlockedAppExeNames must not include explorer.exe, or the child''s desktop will crash-loop.'
  }

  if (-not $Config.ContainsKey('ChildKeptShortcutPatterns') -or
      (@($Config.ChildKeptShortcutPatterns | Where-Object { $_ }).Count -eq 0)) {
    throw 'Config error: ChildKeptShortcutPatterns must contain at least one pattern.'
  }
  foreach ($pat in @($Config.ChildKeptShortcutPatterns)) {
    try { [void]('probe' -match $pat) }
    catch { throw "Config error: ChildKeptShortcutPatterns entry '$pat' is not a valid regex." }
  }

  foreach ($pat in @($Config.ChildOnlyAppxPatterns)) {
    if ([string]::IsNullOrWhiteSpace([string]$pat)) {
      throw 'Config error: ChildOnlyAppxPatterns must not contain empty entries.'
    }
  }

  foreach ($carve in @($Config.ExecuteCarveOuts)) {
    if (-not $carve.ContainsKey('Path') -or [string]::IsNullOrWhiteSpace([string]$carve.Path)) {
      throw 'Config error: every ExecuteCarveOuts entry needs a non-empty Path.'
    }
    # A rooted path or a .. escape would grant execute outside the child profile.
    if ([System.IO.Path]::IsPathRooted([string]$carve.Path) -or ([string]$carve.Path -match '\.\.')) {
      throw "Config error: ExecuteCarveOuts Path '$($carve.Path)' must be relative to the user profile."
    }
  }
  if (-not $Config.ContainsKey('Chrome')) { throw 'Config error: Chrome section is missing.' }
  if (@(2, 3) -notcontains [int]$Config.Chrome.DownloadRestrictions) {
    # 0/1 would silently weaken the lockdown; require an explicit 2 or 3.
    throw 'Config error: Chrome.DownloadRestrictions must be 2 (dangerous only) or 3 (all downloads).'
  }
  if (@(0, 1, 2) -notcontains [int]$Config.Chrome.YouTubeRestrict) {
    throw 'Config error: Chrome.YouTubeRestrict must be 0 (off), 1 (moderate), or 2 (strict).'
  }
}

function Ensure-RegistryKey([string]$Path) {
  if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
}

function Ensure-Directory([string]$Path) {
  if (-not (Test-Path $Path)) { New-Item -Path $Path -ItemType Directory -Force | Out-Null }
}

function Ensure-SecureChildLockdownRoot {
  $root = Join-Path $env:ProgramData 'ChildLockdown'
  Ensure-Directory $root
  & icacls.exe $root /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" /C | Out-Null
  return $root
}

function Ensure-SecureTaskScriptDirectory {
  $root = Ensure-SecureChildLockdownRoot
  $dir = Join-Path $root 'TaskScripts'
  Ensure-Directory $dir
  # Task script copies stay admin/system only.
  & icacls.exe $dir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" /C | Out-Null
  return $dir
}

function Start-SecureTranscriptLogging {
  $root = Ensure-SecureChildLockdownRoot
  $logDir = Join-Path $root 'Logs'
  Ensure-Directory $logDir
  & icacls.exe $logDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" /C | Out-Null

  $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
  $mode = if ($InternalApplyUserLockdown) {
    'internal_lockdown'
  } elseif ($RemoveChromePolicies) {
    'remove_chrome_policies'
  } elseif ($RemoveUserLockdown) {
    'remove_user_lockdown'
  } else {
    'interactive'
  }
  $logPath = Join-Path $logDir ("Lockdown_{0}_{1}.log" -f $mode, $ts)

  try {
    Start-Transcript -Path $logPath -Append -Force | Out-Null
    $script:TranscriptStartedByScript = $true
    Write-Host "Transcript started: $logPath" -ForegroundColor DarkCyan
  } catch {
    Write-Host "Warning: could not start transcript logging: $($_.Exception.Message)" -ForegroundColor Yellow
  }
}

function Stop-SecureTranscriptLogging {
  if (-not $script:TranscriptStartedByScript) { return }
  try {
    Stop-Transcript | Out-Null
  } catch {
    Write-Host "Warning: could not stop transcript cleanly: $($_.Exception.Message)" -ForegroundColor Yellow
  } finally {
    $script:TranscriptStartedByScript = $false
  }
}

function Set-RegistryValue {
  param(
    [Parameter(Mandatory)] [string]$Path,
    [Parameter(Mandatory)] [string]$Name,
    [Parameter(Mandatory)] [AllowNull()] $Value,
    [Parameter(Mandatory)] [ValidateSet('String','DWord','QWord','MultiString','ExpandString')] [string]$Type
  )
  Ensure-RegistryKey $Path
  $t = switch ($Type) {
    'String'       { 'String' }
    'ExpandString' { 'ExpandString' }
    'MultiString'  { 'MultiString' }
    'DWord'        { 'DWord' }
    'QWord'        { 'QWord' }
  }
  New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $t -Force | Out-Null
}

function Ensure-CurrentUserExecutionPolicyBypass {
  try {
    $current = Get-ExecutionPolicy -Scope CurrentUser -ErrorAction Stop
  } catch {
    Write-Host "Warning: could not read CurrentUser execution policy: $($_.Exception.Message)" -ForegroundColor Yellow
    return
  }

  if ($current -eq 'Bypass') {
    Write-Host "ExecutionPolicy (CurrentUser) already set to Bypass." -ForegroundColor Green
    return
  }

  try {
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force -ErrorAction Stop
    Write-Host "Set ExecutionPolicy (CurrentUser) to Bypass." -ForegroundColor Green
  } catch {
    Write-Host "Warning: failed to set ExecutionPolicy (CurrentUser) to Bypass: $($_.Exception.Message)" -ForegroundColor Yellow
  }
}

function Get-LocalUserSid([string]$Name) {
  try {
    $nt  = New-Object System.Security.Principal.NTAccount($env:COMPUTERNAME, $Name)
    $sid = $nt.Translate([System.Security.Principal.SecurityIdentifier])
    return $sid.Value
  } catch {
    return $null
  }
}

function Test-LocalUserHasPasswordSet([string]$Name) {
  try {
    $u = Get-LocalUser -Name $Name -ErrorAction Stop
    return ($null -ne $u.PasswordLastSet)
  } catch {
    return $false
  }
}

function Read-ConfirmedSecurePassword([string]$Prompt1 = 'Enter password', [string]$Prompt2 = 'Confirm password') {
  $pw1 = Read-Host $Prompt1 -AsSecureString
  $pw2 = Read-Host $Prompt2 -AsSecureString

  # compare secure strings by converting to plain text briefly (in-memory)
  $b1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw1)
  $b2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw2)
  try {
    $s1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b1)
    $s2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b2)
    if ($s1 -ne $s2) { throw 'Passwords do not match.' }
  } finally {
    if ($b1 -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b1) }
    if ($b2 -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b2) }
  }

  return $pw1
}

function Ensure-ChildUserPasswordSettings([string]$Name, [switch]$PromptForPasswordUpdate) {
  if ($PromptForPasswordUpdate) {
    $defaultUpdate = $true
    if (Test-LocalUserHasPasswordSet -Name $Name) {
      $defaultUpdate = $false
    }
    $defaultChoiceText = if ($defaultUpdate) { 'Y' } else { 'N' }
    $pwChoice = Read-Host "Set or update password for '$Name' now? (Y/N, Enter = $defaultChoiceText)"
    $doUpdate = $defaultUpdate
    if (-not [string]::IsNullOrWhiteSpace($pwChoice)) {
      $doUpdate = ($pwChoice -match '^[Yy]')
    }

    if ($doUpdate) {
      $pw = Read-ConfirmedSecurePassword -Prompt1 'Enter password' -Prompt2 'Confirm password'
      Set-LocalUser -Name $Name -Password $pw -ErrorAction Stop
      Write-Host "Password updated for '$Name'." -ForegroundColor Green
    } else {
      Write-Host "Skipping password update for '$Name' at operator request." -ForegroundColor Yellow
    }
  }

  # Prevent forced reset prompts/expiry for this local child account.
  try { Set-LocalUser -Name $Name -PasswordNeverExpires $true -ErrorAction SilentlyContinue } catch {}
  try { & net.exe accounts /maxpwage:unlimited | Out-Null } catch {}
  try { & net.exe user $Name /logonpasswordchg:no | Out-Null } catch {}
  try { & net.exe user $Name /passwordchg:no | Out-Null } catch {}
}

function Create-LocalStandardUser([string]$Name) {
  $result = [PSCustomObject]@{
    Created            = $false
    PasswordConfigured = $false
  }

  $existing = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
  if ($existing) {
    Write-Host "Local user '$Name' already exists. Skipping creation." -ForegroundColor Yellow
    return $result
  }

  Write-Host "Creating local STANDARD user: $Name" -ForegroundColor Cyan

  $pwChoice = Read-Host "Set a password now? (Y/N)"
  if ($pwChoice -match '^[Yy]') {
    $pw = Read-ConfirmedSecurePassword -Prompt1 'Enter password' -Prompt2 'Confirm password'
    New-LocalUser -Name $Name -Password $pw -AccountNeverExpires:$true -PasswordNeverExpires:$true -UserMayNotChangePassword:$true | Out-Null
    $result.PasswordConfigured = $true
  } else {
    # Create without password only if local policy allows. If blocked, user will see a clear error.
    New-LocalUser -Name $Name -NoPassword -AccountNeverExpires:$true | Out-Null
  }

  # Ensure NOT an admin
  try { Remove-LocalGroupMember -Group 'Administrators' -Member $Name -ErrorAction SilentlyContinue } catch {}
  try { Add-LocalGroupMember -Group 'Users' -Member $Name -ErrorAction SilentlyContinue } catch {}

  Write-Host "User '$Name' created as a standard local user." -ForegroundColor Green
  $result.Created = $true
  return $result
}

function Get-LocalAdministratorsMemberSids {
  $adminSids = New-Object 'System.Collections.Generic.HashSet[string]'

  $adminGroup = $null
  try {
    $adminGroup = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
  } catch {
    $adminGroup = Get-LocalGroup -Name 'Administrators' -ErrorAction Stop
  }

  $members = @(Get-LocalGroupMember -Group $adminGroup.Name -ErrorAction SilentlyContinue)
  foreach ($m in $members) {
    if ($m.SID -and $m.SID.Value) {
      [void]$adminSids.Add($m.SID.Value)
    }
  }

  return $adminSids
}

function Test-LocalUserIsAdmin([string]$Name) {
  $sid = Get-LocalUserSid $Name
  if (-not $sid) { return $false }
  $adminSids = Get-LocalAdministratorsMemberSids
  return $adminSids.Contains($sid)
}

function Get-EligibleExistingChildUsers {
  $excluded = @('Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount')
  $adminSids = Get-LocalAdministratorsMemberSids

  $users = @(Get-LocalUser -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -and $_.Enabled -and ($excluded -notcontains $_.Name)
  } | Sort-Object Name)

  $result = @()
  foreach ($u in $users) {
    $sid = Get-LocalUserSid $u.Name
    if (-not $sid) { continue }
    if ($adminSids.Contains($sid)) { continue }
    $result += $u.Name
  }

  return $result
}

function Prompt-ChildUserSelection {
  Write-Host "`nChild account selection:" -ForegroundColor Cyan
  $existing = @(Get-EligibleExistingChildUsers)

  if ($existing.Count -gt 0) {
    Write-Host "Choose an existing non-admin local account to harden, or create a new one." -ForegroundColor Cyan
    for ($i = 0; $i -lt $existing.Count; $i++) {
      Write-Host ("{0}) {1}" -f ($i + 1), $existing[$i]) -ForegroundColor Cyan
    }
    $createIndex = $existing.Count + 1
    Write-Host ("{0}) Create new local standard user" -f $createIndex) -ForegroundColor Cyan

    while ($true) {
      $choice = Read-Host ("Select option (1-{0})" -f $createIndex)
      if ($choice -match '^\d+$') {
        $idx = [int]$choice
        if (($idx -ge 1) -and ($idx -le $existing.Count)) {
          return [PSCustomObject]@{
            UserName  = $existing[$idx - 1]
            CreateNew = $false
          }
        }
        if ($idx -eq $createIndex) { break }
      }
      Write-Host ("Invalid choice. Enter a number from 1 to {0}." -f $createIndex) -ForegroundColor Yellow
    }
  } else {
    Write-Host "No eligible existing non-admin local accounts were found. Creating a new account." -ForegroundColor Yellow
  }

  while ($true) {
    $name = Read-Host 'Enter LOCAL child account name to create (e.g., Student01)'
    if ([string]::IsNullOrWhiteSpace($name)) {
      Write-Host 'Username cannot be empty.' -ForegroundColor Yellow
      continue
    }

    $existingUser = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
    if ($existingUser) {
      if (Test-LocalUserIsAdmin -Name $name) {
        Write-Host "User '$name' is an administrator. Choose a different account name." -ForegroundColor Yellow
        continue
      }
      Write-Host "User '$name' already exists and is non-admin; selecting it." -ForegroundColor Yellow
      return [PSCustomObject]@{
        UserName  = $name
        CreateNew = $false
      }
    }

    return [PSCustomObject]@{
      UserName  = $name
      CreateNew = $true
    }
  }
}

function Test-ChromeSystemWideInstalled {
  $paths = @()
  $pf = $env:ProgramFiles
  $pf86 = ${env:ProgramFiles(x86)}
  if ($pf)  { $paths += Join-Path $pf  'Google\Chrome\Application\chrome.exe' }
  if ($pf86) { $paths += Join-Path $pf86 'Google\Chrome\Application\chrome.exe' }
  foreach ($p in $paths) {
    if ($p -and (Test-Path $p)) { return $true }
  }

  $uninstallRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
  )
  foreach ($root in $uninstallRoots) {
    if (-not (Test-Path $root)) { continue }
    foreach ($k in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
      try {
        $dn = (Get-ItemProperty $k.PSPath -ErrorAction Stop).DisplayName
        if ($dn -and $dn -eq 'Google Chrome') { return $true }
      } catch {}
    }
  }

  return $false
}

function Install-ChromeSystemWide {
  Write-Host "System-wide Chrome not detected. Downloading + installing..." -ForegroundColor Cyan

  # Official Google Enterprise MSI direct links (commonly used for managed deployments)
  # 64-bit: https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi
  # 32-bit: https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise.msi
  $is64 = [Environment]::Is64BitOperatingSystem
  $msiUrl = if ($is64) {
    'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi'
  } else {
    'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise.msi'
  }

  $tmp = Join-Path $env:TEMP ("chrome_enterprise_{0}.msi" -f ($(if ($is64) {'x64'} else {'x86'})))

  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
  } catch {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  }

  Write-Host "Downloading: $msiUrl" -ForegroundColor DarkCyan
  Invoke-WebRequest -Uri $msiUrl -OutFile $tmp -UseBasicParsing

  if (-not (Test-Path $tmp)) { throw 'Chrome MSI download failed.' }
  Assert-TrustedGoogleMsi -Path $tmp

  Write-Host "Installing MSI silently..." -ForegroundColor DarkCyan
  $cmdArgs = "/i `"$tmp`" /qn /norestart"
  $p = Start-Process -FilePath 'msiexec.exe' -ArgumentList $cmdArgs -Wait -PassThru
  if ($p.ExitCode -ne 0) {
    throw "Chrome MSI install failed. msiexec exit code: $($p.ExitCode)"
  }

  Remove-Item $tmp -Force -ErrorAction SilentlyContinue

  if (-not (Test-ChromeSystemWideInstalled)) {
    throw 'Chrome install completed but Chrome still not detected in standard locations.'
  }

  Write-Host "Chrome installed system-wide." -ForegroundColor Green
}

function Ensure-ChromeInstalled {
  if (Test-ChromeSystemWideInstalled) {
    Write-Host "Chrome is already installed system-wide." -ForegroundColor Green
    return
  }
  Install-ChromeSystemWide
}

function Ensure-WidgetsDisabledMachinePolicy {
  Write-Host "Applying machine-level Widgets/Feeds, Location, and OneDrive prompt suppression policies..." -ForegroundColor Cyan
  Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' -Name 'AllowNewsAndInterests' -Value 0 -Type DWord
  Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds' -Name 'EnableFeeds' -Value 0 -Type DWord

  # Disable Windows location feature at machine scope (Computer Configuration > Location and Sensors > Turn off location).
  Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableLocation' -Value 1 -Type DWord
  Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableLocationScripting' -Value 1 -Type DWord

  # Reduce OneDrive/backup enrollment prompts.
  # Source: IT Admins - Use OneDrive policies to control sync settings (Microsoft Learn).
  Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' -Name 'KFMBlockOptIn' -Value 1 -Type DWord
  Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' -Name 'DisableNewAccountDetection' -Value 1 -Type DWord
}

function Remove-AppxPackagesByPatterns {
  param(
    [Parameter(Mandatory)] [string[]]$Patterns
  )

  $pkgs = @(
    Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object {
      $name = $_.Name
      $family = $_.PackageFamilyName
      foreach ($pat in $Patterns) {
        if (($name -like $pat) -or ($family -like $pat)) { return $true }
      }
      return $false
    }
  )

  foreach ($pkg in $pkgs) {
    try {
      Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop | Out-Null
      Write-Host "Removed installed app package: $($pkg.Name)" -ForegroundColor Green
    } catch {
      try {
        # Fallback for older builds/cmdlets where -AllUsers behavior differs.
        Remove-AppxPackage -Package $pkg.PackageFullName -ErrorAction Stop | Out-Null
        Write-Host "Removed app package (fallback): $($pkg.Name)" -ForegroundColor Green
      } catch {
        Write-Host "Warning: could not remove app package '$($pkg.Name)': $($_.Exception.Message)" -ForegroundColor Yellow
      }
    }
  }
}

function Remove-ProvisionedPackagesByPatterns {
  param(
    [Parameter(Mandatory)] [string[]]$Patterns
  )

  $provPkgs = @(
    Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object {
      $display = $_.DisplayName
      foreach ($pat in $Patterns) {
        if ($display -like $pat) { return $true }
      }
      return $false
    }
  )

  foreach ($prov in $provPkgs) {
    try {
      Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction Stop | Out-Null
      Write-Host "Removed provisioned package: $($prov.DisplayName)" -ForegroundColor Green
    } catch {
      Write-Host "Warning: could not remove provisioned package '$($prov.DisplayName)': $($_.Exception.Message)" -ForegroundColor Yellow
    }
  }
}

function Remove-ChildOnlyAppxPackages([string]$Sid) {
  # Unregisters packaged apps for one user without touching anyone else's copy. The
  # package stays staged on disk, so this is reversible and the parent account is
  # unaffected - see ChildOnlyAppxPatterns for why the child needs this at all.
  if (-not $Sid) { return }
  $patterns = @($Config.ChildOnlyAppxPatterns | Where-Object { $_ })
  if ($patterns.Count -eq 0) { return }

  Write-Host "`nRemoving packaged apps for this child only..." -ForegroundColor Cyan
  $pkgs = @(Get-AppxPackage -User $Sid -ErrorAction SilentlyContinue | Where-Object {
    if ($_.IsFramework) { return $false }
    $name = $_.Name; $family = $_.PackageFamilyName
    foreach ($pat in $patterns) { if (($name -like $pat) -or ($family -like $pat)) { return $true } }
    return $false
  })

  if ($pkgs.Count -eq 0) {
    Write-Host "No matching packaged apps registered for this child." -ForegroundColor DarkCyan
    return
  }

  foreach ($pkg in $pkgs) {
    try {
      Remove-AppxPackage -Package $pkg.PackageFullName -User $Sid -ErrorAction Stop | Out-Null
      Write-Host "Unregistered for child: $($pkg.Name)" -ForegroundColor Green
    } catch {
      # Some packages are marked non-removable by the OS. Say so rather than failing the
      # whole run - the rest of the lockdown is still worth applying.
      Write-Host "Warning: could not unregister '$($pkg.Name)' for this child: $($_.Exception.Message)" -ForegroundColor Yellow
    }
  }
}

function Restore-ChildOnlyAppxPackages([string]$Sid) {
  if (-not $Sid) { return }
  $patterns = @($Config.ChildOnlyAppxPatterns | Where-Object { $_ })
  if ($patterns.Count -eq 0) { return }

  # Re-register from the copy still staged on disk. Nothing is downloaded.
  $registered = @(Get-AppxPackage -User $Sid -ErrorAction SilentlyContinue |
                  Select-Object -ExpandProperty PackageFamilyName)
  $staged = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object {
    if ($_.IsFramework) { return $false }
    if ($registered -contains $_.PackageFamilyName) { return $false }
    $name = $_.Name; $family = $_.PackageFamilyName
    foreach ($pat in $patterns) { if (($name -like $pat) -or ($family -like $pat)) { return $true } }
    return $false
  })

  foreach ($pkg in $staged) {
    try {
      Add-AppxPackage -RegisterByFamilyName -MainPackage $pkg.PackageFamilyName -User $Sid -ErrorAction Stop | Out-Null
      Write-Host "Re-registered for child: $($pkg.Name)" -ForegroundColor Green
    } catch {
      Write-Host "Warning: could not re-register '$($pkg.Name)': $($_.Exception.Message)" -ForegroundColor Yellow
    }
  }
}

function Remove-UnnecessaryBuiltInApps {
  Write-Host "`nBuilt-in app cleanup:" -ForegroundColor Cyan
  $choice = Read-Host "Remove unnecessary built-in apps now? (Y/N, Enter = Y)"
  if ($choice -match '^[Nn]') {
    Write-Host "Skipping built-in app cleanup at operator request." -ForegroundColor Yellow
    return
  }

  # Best-effort patterns for common appx/provisioned names across Windows 10/11 variants.
  $patterns = @($Config.DebloatPatterns | Where-Object { $_ })
  if ($patterns.Count -eq 0) {
    Write-Host "No DebloatPatterns configured; nothing to remove." -ForegroundColor Yellow
    return
  }

  Write-Host "Removing installed appx packages (all users)..." -ForegroundColor DarkCyan
  Remove-AppxPackagesByPatterns -Patterns $patterns

  Write-Host "Removing provisioned appx packages (new profiles)..." -ForegroundColor DarkCyan
  Remove-ProvisionedPackagesByPatterns -Patterns $patterns
}

function Ensure-ChildTaskbarUiLockTask([string]$ChildUserName, [string]$Sid) {
  # Applies taskbar distraction toggles at the child's next sign-in, when their hive is
  # mounted at HKU\<SID> and writable.
  #
  # This runs as SYSTEM, not as the child, and that is the whole point. An earlier
  # version ran as the child against HKCU and could never work: by the time it fires,
  # DisableCMD=2 is already in force for that user, so cmd.exe is
  # blocked and the task just fails with 0x1 on every sign-in. SYSTEM has neither
  # policy - both live in the child's own hive - so it can still write these values.
  # Deletes itself after successful execution.
  if (-not $Sid) {
    Write-Host "Warning: no SID supplied for taskbar UI task; skipping." -ForegroundColor Yellow
    return
  }
  $taskName = "ApplyChildTaskbarUi_$ChildUserName"
  $userId = "$env:COMPUTERNAME\$ChildUserName"
  $hk = "HKU\$Sid"
  $cmdParts = @(
    "reg add `"$hk\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`" /v TaskbarDa /t REG_DWORD /d 0 /f",
    "reg add `"$hk\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`" /v TaskbarMn /t REG_DWORD /d 0 /f",
    "reg add `"$hk\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`" /v ShowTaskViewButton /t REG_DWORD /d 0 /f",
    "reg add `"$hk\Software\Microsoft\Windows\CurrentVersion\Search`" /v SearchboxTaskbarMode /t REG_DWORD /d 0 /f",
    "reg add `"$hk\Software\Microsoft\Windows\CurrentVersion\Search`" /v IsDynamicSearchBoxEnabled /t REG_DWORD /d 0 /f",
    "reg add `"$hk\Software\Microsoft\Windows\CurrentVersion\Feeds`" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d 2 /f"
  )
  $cmdParts += "schtasks /Delete /TN `"$taskName`" /F"
  $cmd = $cmdParts -join ' & '
  $cmdArgs = "/c $cmd"

  if (Get-Command -Name Register-ScheduledTask -ErrorAction SilentlyContinue) {
    try {
      if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
      }
      $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument $cmdArgs
      $trigger = New-ScheduledTaskTrigger -AtLogOn -User $userId
      # The trigger fires slightly before the profile hive finishes mounting, so give it
      # a moment - writing to HKU\<SID> too early silently does nothing.
      $trigger.Delay = 'PT30S'
      $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
      Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force -ErrorAction Stop | Out-Null
      Write-Host "Created one-time child logon task '$taskName' for UI/taskbar lock settings." -ForegroundColor Green
      return
    } catch {
      Write-Host "Warning: failed to create child UI task with ScheduledTasks cmdlets: $($_.Exception.Message)" -ForegroundColor Yellow
    }
  }

  $schtasksPath = "$env:windir\System32\schtasks.exe"
  if (-not (Test-Path $schtasksPath)) { $schtasksPath = 'schtasks.exe' }
  try {
    Start-Process -FilePath $schtasksPath -ArgumentList '/Delete','/TN',$taskName,'/F' -NoNewWindow -Wait -PassThru -ErrorAction SilentlyContinue | Out-Null
    $trCmd = "cmd.exe $cmdArgs"
    $trArg = '"' + $trCmd + '"'
    $p = Start-Process -FilePath $schtasksPath -ArgumentList '/Create','/TN',$taskName,'/SC','ONLOGON','/RU','SYSTEM','/RL','HIGHEST','/TR',$trArg,'/F' -NoNewWindow -Wait -PassThru -ErrorAction Stop
    if ($p.ExitCode -eq 0) {
      Write-Host "Created one-time child logon task '$taskName' for UI/taskbar lock settings." -ForegroundColor Green
    } else {
      Write-Host "Warning: schtasks returned exit code $($p.ExitCode) while creating '$taskName'." -ForegroundColor Yellow
    }
  } catch {
    Write-Host "Warning: failed to create child UI task via schtasks.exe: $($_.Exception.Message)" -ForegroundColor Yellow
  }
}

function Remove-ChildTaskbarUiLockTask([string]$ChildUserName) {
  $taskName = "ApplyChildTaskbarUi_$ChildUserName"
  try {
    if (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue) {
      if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
      }
    } else {
      & schtasks.exe /Delete /TN $taskName /F | Out-Null
    }
  } catch {}
}

function Remove-LegacyInstallTasks([string]$ChildUserName) {
  # Cleans up scheduled tasks and payloads created by previous script versions
  # (StudyReel and Alpha TimeBack per-user install tasks).
  foreach ($taskName in @("InstallStudyReel_$ChildUserName", "InstallAlphaTimeBack_$ChildUserName")) {
    try {
      if (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue) {
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
          Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
      } else {
        & schtasks.exe /Delete /TN $taskName /F | Out-Null
      }
    } catch {}
  }

  # Remove the legacy StudyReel installer payload (it carried a child read/execute grant).
  $installerDir = Join-Path (Join-Path $env:ProgramData 'ChildLockdown') 'Installers'
  $legacyInstaller = Join-Path $installerDir 'StudyReel-Installer.exe'
  if (Test-Path -LiteralPath $legacyInstaller) {
    Remove-Item -LiteralPath $legacyInstaller -Force -ErrorAction SilentlyContinue
    Write-Host "Removed legacy StudyReel installer payload: $legacyInstaller" -ForegroundColor Yellow
  }
  if ((Test-Path -LiteralPath $installerDir) -and -not (Get-ChildItem -LiteralPath $installerDir -Force -ErrorAction SilentlyContinue)) {
    Remove-Item -LiteralPath $installerDir -Force -ErrorAction SilentlyContinue
  }
}

function Remove-FirstLogonTask([string]$ChildUserName) {
  $taskName = "ApplyChildLockdown_$ChildUserName"
  try {
    if (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue) {
      if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
      }
    } else {
      & schtasks.exe /Delete /TN $taskName /F | Out-Null
    }
  } catch {}
}

function Get-AllowedAppConfig([string]$AppName) {
  foreach ($app in $Config.AllowedApps) {
    if ([string]$app.Name -ieq $AppName) { return $app }
  }
  return $null
}

function Resolve-AllowedAppExecutablePath([string]$AppName) {
  $app = Get-AllowedAppConfig $AppName
  if (-not $app) { return $null }
  if (-not $app.ContainsKey('PathCandidates')) { return $null }
  foreach ($candidate in @($app.PathCandidates | Where-Object { $_ })) {
    $hit = Get-ChildItem -Path $candidate -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($hit) { return $hit.FullName }
  }
  return $null
}

function Get-AllowedAppExeNames {
  if ($script:AllowedAppExeNamesCache) { return @($script:AllowedAppExeNamesCache) }

  $names = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($app in $Config.AllowedApps) {
    foreach ($n in @($app.ExeNames)) {
      if ($n) { [void]$names.Add($n) }
    }
  }

  # Store-packaged apps may run under an executable name we do not know up front;
  # read it from the package manifest for config entries that declare AppxMatch.
  $appxApps = @($Config.AllowedApps | Where-Object { $_.ContainsKey('AppxMatch') -and $_.AppxMatch })
  if ($appxApps.Count -gt 0) {
    try {
      $pkgs = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object {
        $pkg = $_
        @($appxApps | Where-Object { $pkg.Name -match $_.AppxMatch -or $pkg.PackageFamilyName -match $_.AppxMatch }).Count -gt 0
      })
      foreach ($pkg in $pkgs) {
        if (-not $pkg.InstallLocation) { continue }
        $manifestPath = Join-Path $pkg.InstallLocation 'AppxManifest.xml'
        if (-not (Test-Path $manifestPath)) { continue }
        try {
          [xml]$manifest = Get-Content -Path $manifestPath -Raw -ErrorAction Stop
          $manifestApps = @($manifest.Package.Applications.Application)
          foreach ($manifestApp in $manifestApps) {
            $exe = $manifestApp.Executable
            if (-not $exe) { continue }
            $leaf = [IO.Path]::GetFileName($exe)
            if ($leaf -and ($leaf -like '*.exe')) {
              [void]$names.Add($leaf)
            }
          }
        } catch {}
      }
    } catch {}
  }

  $script:AllowedAppExeNamesCache = @($names)
  return @($names)
}

function Test-ShortcutLooksLikeApprovedApp([string]$ShortcutPath, [string[]]$ApprovedExeNames) {
  if (-not (Test-Path $ShortcutPath)) { return $false }

  $name = [IO.Path]::GetFileNameWithoutExtension($ShortcutPath)
  foreach ($app in $Config.AllowedApps) {
    if ($app.ContainsKey('ShortcutMatch') -and $app.ShortcutMatch -and ($name -match $app.ShortcutMatch)) { return $true }
  }

  if ($ShortcutPath -like '*.lnk') {
    try {
      $wsh = New-Object -ComObject WScript.Shell
      $sc = $wsh.CreateShortcut($ShortcutPath)
      if (-not $sc.TargetPath) { return $false }
      $leaf = [IO.Path]::GetFileName($sc.TargetPath)
      foreach ($exeName in @($ApprovedExeNames)) {
        if ($exeName -and ($leaf -ieq $exeName)) { return $true }
      }
    } catch {}
  }
  return $false
}

function Remove-NonApprovedDesktopShortcuts([string]$DesktopPath, [string[]]$ApprovedExeNames) {
  if (-not $DesktopPath -or -not (Test-Path $DesktopPath)) { return }

  $shortcutFiles = @(Get-ChildItem -Path $DesktopPath -File -ErrorAction SilentlyContinue | Where-Object {
    $_.Extension -in @('.lnk', '.url', '.appref-ms')
  })
  foreach ($f in $shortcutFiles) {
    if (Test-ShortcutLooksLikeApprovedApp -ShortcutPath $f.FullName -ApprovedExeNames $ApprovedExeNames) { continue }
    Remove-Item -Path $f.FullName -Force -ErrorAction SilentlyContinue
  }
}

function Remove-NonApprovedTaskbarPins([string]$ProfilePath, [string[]]$ApprovedExeNames) {
  # Best-effort: remove unapproved taskbar pinned shortcuts without creating new ones.
  if (-not $ProfilePath -or -not (Test-Path $ProfilePath)) { return }

  $taskbarPinned = Join-Path $ProfilePath 'AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar'
  if (-not (Test-Path $taskbarPinned)) { return }

  $shortcutFiles = @(Get-ChildItem -Path $taskbarPinned -File -ErrorAction SilentlyContinue | Where-Object {
    $_.Extension -in @('.lnk', '.url', '.appref-ms')
  })
  foreach ($f in $shortcutFiles) {
    if (Test-ShortcutLooksLikeApprovedApp -ShortcutPath $f.FullName -ApprovedExeNames $ApprovedExeNames) { continue }
    Remove-Item -Path $f.FullName -Force -ErrorAction SilentlyContinue
  }
}

function Get-RunEntryExeName([string]$Command) {
  # Run values look like '"C:\dir\app.exe" --flag', 'C:\dir\app.exe --flag' or just 'app.exe'.
  # Pull out the executable so it can be checked against the deny list.
  if ([string]::IsNullOrWhiteSpace($Command)) { return $null }
  $c = $Command.Trim()
  if ($c -match '^"([^"]+)"') { return [System.IO.Path]::GetFileName($matches[1]) }
  if ($c -match '^(\S+\.exe)') { return [System.IO.Path]::GetFileName($matches[1]) }
  return $null
}

function Remove-BlockedChildRunEntries([string]$HiveRoot, [string]$Sid) {
  # A startup entry that cannot launch still fires at every sign-in and puts an error
  # dialog in the child's face, so those entries have to go. Two kinds cannot launch:
  # an executable on the deny list, and anything living in a folder where the child is
  # denied execute (see Apply-ChildExecutionDenyAcls) - OneDrive installs itself into
  # AppData and is the usual example of the second kind. The two produce *different*
  # dialogs, which is worth knowing when diagnosing: the deny list gives "restrictions
  # in effect on this computer", the ACL gives "Windows cannot access the specified
  # device, path, or file".
  # Originals are copied to a backup key first so -RemoveUserLockdown can put them back.
  $runPath = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Run"
  if (-not (Test-Path $runPath)) { return }

  $backupPath = "$HiveRoot\Software\ChildLockdown\RunBackup"
  $blocked = @($Config.BlockedAppExeNames | Where-Object { $_ })
  $ours = @('ChildLockdownAutostart', 'ChildLockdownStartChrome')

  # The folders Apply-ChildExecutionDenyAcls stamps with an execute-deny for this child.
  # AppData\Local\Temp is covered by inheritance from AppData\Local, so it is not listed.
  $denied = @()
  $carved = @()
  $profilePath = if ($Sid) { Get-UserProfilePath $Sid } else { $null }
  if ($profilePath) {
    $denied = @('Desktop', 'Downloads', 'Documents', 'Pictures', 'Music', 'Videos',
                'AppData\Local', 'AppData\Roaming') |
              ForEach-Object { (Join-Path $profilePath $_).TrimEnd('\') + '\' }
    # Execute is granted back on these, so an entry pointing into one still works and
    # must not be pruned - Chrome's own AppData\Local\Google tree is the live case.
    $carved = @($Config.ExecuteCarveOuts | Where-Object { $_.Path } |
                ForEach-Object { (Join-Path $profilePath $_.Path).TrimEnd('\') + '\' })
  }

  $props = Get-ItemProperty -Path $runPath -ErrorAction SilentlyContinue
  if (-not $props) { return }

  foreach ($prop in $props.PSObject.Properties) {
    if ($prop.Name -like 'PS*') { continue }
    if ($ours -contains $prop.Name) { continue }

    $value = [string]$prop.Value
    $exe = Get-RunEntryExeName $value
    # An entry whose executable cannot be parsed is left alone rather than guessed at.
    if (-not $exe) { continue }

    $reason = $null
    if ($blocked -contains $exe) {
      $reason = 'it is on the block list'
    } else {
      $isCarved = $false
      foreach ($c in $carved) { if ($value -like "*$c*") { $isCarved = $true; break } }
      if (-not $isCarved) {
        foreach ($d in $denied) {
          if ($value -like "*$d*") { $reason = 'it sits in an execute-denied folder'; break }
        }
      }
    }
    if (-not $reason) { continue }

    Ensure-RegistryKey $backupPath
    Set-RegistryValue -Path $backupPath -Name $prop.Name -Value $value -Type String
    Remove-ItemProperty -Path $runPath -Name $prop.Name -Force -ErrorAction SilentlyContinue
    Write-Host "Removed startup entry '$($prop.Name)' ($exe) - $reason, so it could only ever show an error." -ForegroundColor Green
  }
}

function Restore-BlockedChildRunEntries([string]$HiveRoot) {
  $backupPath = "$HiveRoot\Software\ChildLockdown\RunBackup"
  if (-not (Test-Path $backupPath)) { return }
  $runPath = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Run"
  Ensure-RegistryKey $runPath

  $props = Get-ItemProperty -Path $backupPath -ErrorAction SilentlyContinue
  if ($props) {
    foreach ($prop in $props.PSObject.Properties) {
      if ($prop.Name -like 'PS*') { continue }
      Set-RegistryValue -Path $runPath -Name $prop.Name -Value ([string]$prop.Value) -Type String
      Write-Host "Restored startup entry '$($prop.Name)'." -ForegroundColor Green
    }
  }
  Remove-Item -Path $backupPath -Recurse -Force -ErrorAction SilentlyContinue
}

function Disable-ChildOneDriveIntegration([string]$HiveRoot, [string]$Sid) {
  # OneDrive installs per-user into AppData\Local, which this lockdown denies execute on.
  # The COM registrations survive that, so Explorer and DCOM keep trying to activate
  # around 35 servers that can never start - FileCoAuth.exe alone gets retried several
  # times a second while the child browses files, and every failure is an
  # access-denied dialog in their face. Blocking the executable is not enough; the
  # registrations have to go so nothing attempts the launch in the first place.
  #
  # Files are deliberately left on disk. Rollback restores the OneDrive Run entry, and
  # OneDrive re-registers all of this itself the next time it runs.
  if (-not $Sid) { return }

  $removed = 0
  foreach ($classRoot in @("$HiveRoot\Software\Classes\CLSID",
                           "$HiveRoot\Software\Classes\WOW6432Node\CLSID")) {
    if (-not (Test-Path $classRoot)) { continue }
    foreach ($clsid in @(Get-ChildItem $classRoot -ErrorAction SilentlyContinue)) {
      $isOneDrive = $false
      foreach ($server in @('LocalServer32', 'InProcServer32')) {
        $serverKey = Join-Path $clsid.PSPath $server
        $target = (Get-ItemProperty -Path $serverKey -ErrorAction SilentlyContinue).'(default)'
        if ($target -and $target -match '(?i)\\Microsoft\\OneDrive\\') { $isOneDrive = $true }
      }
      if (-not $isOneDrive) { continue }
      Remove-Item -Path $clsid.PSPath -Recurse -Force -ErrorAction SilentlyContinue
      $removed++
    }
  }

  # The sidebar entry is one of the CLSIDs above, but the Desktop namespace link to it is
  # separate and would be left pointing at nothing.
  $ns = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace"
  if (Test-Path $ns) {
    foreach ($entry in @(Get-ChildItem $ns -ErrorAction SilentlyContinue)) {
      $label = (Get-ItemProperty -Path $entry.PSPath -ErrorAction SilentlyContinue).'(default)'
      if ($label -and $label -match '(?i)onedrive') {
        Remove-Item -Path $entry.PSPath -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  if ($removed -gt 0) {
    Write-Host "Removed $removed OneDrive COM registrations that could only ever fail for this child." -ForegroundColor Green
  }
}

function Test-ShortcutIsKeptForChild([string]$Name) {
  foreach ($pat in @($Config.ChildKeptShortcutPatterns)) {
    if ($Name -match $pat) { return $true }
  }
  return $false
}

function Get-ChildStartMenuShortcuts([string]$Root) {
  if (-not (Test-Path $Root)) { return @() }
  return @(Get-ChildItem -Path $Root -Recurse -File -ErrorAction SilentlyContinue |
           Where-Object { @('.lnk', '.url') -contains $_.Extension })
}

function Hide-ChildStartMenuShortcuts([string]$Sid) {
  # Blocking an executable stops it running but leaves its entry sitting in the Start
  # menu, so the child still sees PowerPoint, Registry Editor and Remote Desktop and
  # only finds out they are blocked by clicking and getting a refusal dialog. Hiding
  # the shortcut is the better answer: nothing to click, so nothing to refuse.
  #
  # Machine-wide shortcuts are shared with the parent, so they are NOT deleted - the
  # child alone is denied read on them and the parent's Start menu is untouched.
  # Shortcuts inside the child's own profile are deleted instead, because the child
  # owns those files and an owner can simply take the deny ACE back off.
  if (-not $Sid) { return }
  $denied = 0; $deleted = 0

  foreach ($lnk in (Get-ChildStartMenuShortcuts (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'))) {
    if (Test-ShortcutIsKeptForChild $lnk.BaseName) { continue }
    & icacls.exe $lnk.FullName /deny "*${Sid}:(RX)" /C /Q | Out-Null
    $denied++
  }

  $profilePath = Get-UserProfilePath $Sid
  if ($profilePath) {
    $userMenu = Join-Path $profilePath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs'
    foreach ($lnk in (Get-ChildStartMenuShortcuts $userMenu)) {
      if (Test-ShortcutIsKeptForChild $lnk.BaseName) { continue }
      Remove-Item -Path $lnk.FullName -Force -ErrorAction SilentlyContinue
      $deleted++
    }
  }
  Write-Host "Hid $denied shared Start menu entries from this child; removed $deleted from their own profile." -ForegroundColor Green
}

function Show-ChildStartMenuShortcuts([string]$Sid) {
  # Strips the deny ACEs added above. Entries deleted from the child's own profile are
  # not recreated here - Windows rebuilds the ones it owns, and the rest were duplicates
  # of machine-wide entries that become visible again anyway.
  if (-not $Sid) { return }
  $restored = 0
  foreach ($lnk in (Get-ChildStartMenuShortcuts (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'))) {
    & icacls.exe $lnk.FullName /remove:d "*$Sid" /C /Q | Out-Null
    $restored++
  }
  Write-Host "Restored this child's view of $restored shared Start menu entries." -ForegroundColor Yellow
}

function Apply-ChildShellSurfaceLockdown([string]$HiveRoot, [string]$Sid) {
  if (-not $Sid) { return }

  # Autostart the configured allowed app for the child at each sign-in.
  $runPath = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Run"
  if (Test-Path $runPath) {
    # Value name used by previous script versions.
    Remove-ItemProperty -Path $runPath -Name 'ChildLockdownStartChrome' -Force -ErrorAction SilentlyContinue
  }
  if ($Config.AutostartApp) {
    $autostartExe = Resolve-AllowedAppExecutablePath $Config.AutostartApp
    if ($autostartExe) {
      $runCmd = "`"$autostartExe`""
      if ($Config.AutostartArgs) { $runCmd += " $($Config.AutostartArgs)" }
      Set-RegistryValue -Path $runPath -Name 'ChildLockdownAutostart' -Value $runCmd -Type String
    } else {
      Write-Host "Warning: could not resolve executable for AutostartApp '$($Config.AutostartApp)' from its PathCandidates; skipping autostart." -ForegroundColor Yellow
    }
  } elseif (Test-Path $runPath) {
    Remove-ItemProperty -Path $runPath -Name 'ChildLockdownAutostart' -Force -ErrorAction SilentlyContinue
  }

  # Runs after the autostart entry is written so our own value is never a candidate.
  Remove-BlockedChildRunEntries -HiveRoot $HiveRoot -Sid $Sid
  Disable-ChildOneDriveIntegration -HiveRoot $HiveRoot -Sid $Sid
  Hide-ChildStartMenuShortcuts -Sid $Sid

  $profilePath = Get-UserProfilePath $Sid
  if (-not $profilePath -or -not (Test-Path $profilePath)) {
    Write-Host "Profile path unavailable; shell cleanup will run on the next successful profile load." -ForegroundColor Yellow
    return
  }

  $childDesktop = Join-Path $profilePath 'Desktop'
  $publicDesktop = Join-Path $env:PUBLIC 'Desktop'
  $approvedExeNames = Get-AllowedAppExeNames

  # Remove public and per-user shortcuts except approved apps.
  Remove-NonApprovedDesktopShortcuts -DesktopPath $publicDesktop -ApprovedExeNames $approvedExeNames
  Remove-NonApprovedDesktopShortcuts -DesktopPath $childDesktop -ApprovedExeNames $approvedExeNames

  Remove-NonApprovedTaskbarPins -ProfilePath $profilePath -ApprovedExeNames $approvedExeNames
}

function Remove-ChildShellSurfaceLockdown([string]$HiveRoot, [string]$Sid) {
  $runPath = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Run"
  if (Test-Path $runPath) {
    Remove-ItemProperty -Path $runPath -Name 'ChildLockdownAutostart' -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $runPath -Name 'ChildLockdownStartChrome' -Force -ErrorAction SilentlyContinue
  }
  Restore-BlockedChildRunEntries -HiveRoot $HiveRoot
  Show-ChildStartMenuShortcuts -Sid $Sid
}

function Assert-TrustedGoogleMsi([string]$Path) {
  Write-Host "Verifying MSI digital signature..." -ForegroundColor DarkCyan
  $sig = Get-AuthenticodeSignature -FilePath $Path
  if ($sig.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw "Downloaded MSI signature is not valid. Status: $($sig.Status)"
  }
  if (-not $sig.SignerCertificate) {
    throw 'Downloaded MSI has no signer certificate.'
  }
  if ($sig.SignerCertificate.Subject -notmatch 'Google') {
    throw "Downloaded MSI signer is unexpected: $($sig.SignerCertificate.Subject)"
  }
}

function Remove-LegacyMachineChromeHardening {
  $legacyBase = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
  if (Test-Path $legacyBase) {
    Write-Host "Removing legacy machine-wide Chrome policies so per-user policies can take effect..." -ForegroundColor Yellow
    Remove-Item -Path $legacyBase -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Apply-ChromeHardening([string]$HiveRoot, [string]$RestrictSigninPatternRegex) {
  $base = "$HiveRoot\Software\Policies\Google\Chrome"
  Ensure-RegistryKey $base

  Write-Host "Applying Chrome hardening policies to user hive: $HiveRoot" -ForegroundColor Cyan

  # Disable Guest
  Set-RegistryValue -Path $base -Name 'BrowserGuestModeEnabled'    -Value 0 -Type DWord
  # Disable Incognito (1 = disabled)
  Set-RegistryValue -Path $base -Name 'IncognitoModeAvailability'  -Value 1 -Type DWord
  # Browser sign-in mode (2 = force sign-in)
  Set-RegistryValue -Path $base -Name 'BrowserSignin'              -Value 2 -Type DWord
  # Lock down browser escape surfaces.
  Set-RegistryValue -Path $base -Name 'DeveloperToolsAvailability' -Value 2 -Type DWord
  Set-RegistryValue -Path $base -Name 'AutofillAddressEnabled'     -Value 0 -Type DWord
  Set-RegistryValue -Path $base -Name 'AutofillCreditCardEnabled'  -Value 0 -Type DWord
  Set-RegistryValue -Path $base -Name 'BlockExternalExtensions'    -Value 1 -Type DWord
  Set-RegistryValue -Path $base -Name 'BlockSensitiveInternalPages' -Value 1 -Type DWord

  # Download and search restrictions (config-driven).
  Set-RegistryValue -Path $base -Name 'DownloadRestrictions' -Value ([int]$Config.Chrome.DownloadRestrictions) -Type DWord
  if ($Config.Chrome.ForceSafeSearch) {
    Set-RegistryValue -Path $base -Name 'ForceGoogleSafeSearch' -Value 1 -Type DWord
  } else {
    Remove-ItemProperty -Path $base -Name 'ForceGoogleSafeSearch' -Force -ErrorAction SilentlyContinue
  }
  if ([int]$Config.Chrome.YouTubeRestrict -gt 0) {
    Set-RegistryValue -Path $base -Name 'ForceYouTubeRestrict' -Value ([int]$Config.Chrome.YouTubeRestrict) -Type DWord
  } else {
    # 0 = defer YouTube filtering to Family Link supervision of the signed-in account.
    Remove-ItemProperty -Path $base -Name 'ForceYouTubeRestrict' -Force -ErrorAction SilentlyContinue
  }

  # URL allowlist: exceptions to BlockSensitiveInternalPages and URLBlocklist (config-driven).
  $urlAllow = "$base\URLAllowlist"
  if (Test-Path $urlAllow) { Remove-Item -Path $urlAllow -Recurse -Force -ErrorAction SilentlyContinue }
  $allowedUrls = @($Config.Chrome.URLAllowlist | Where-Object { $_ })
  if ($allowedUrls.Count -gt 0) {
    Ensure-RegistryKey $urlAllow
    for ($i = 0; $i -lt $allowedUrls.Count; $i++) {
      Set-RegistryValue -Path $urlAllow -Name ($i + 1).ToString() -Value $allowedUrls[$i] -Type String
    }
  }


  if ($RestrictSigninPatternRegex) {
    # Restrict to allowed account(s) using regex
    Set-RegistryValue -Path $base -Name 'RestrictSigninToPattern' -Value $RestrictSigninPatternRegex -Type String
  } else {
    # Explicitly clear prior restriction when operator leaves allowed-email list empty.
    Remove-ItemProperty -Path $base -Name 'RestrictSigninToPattern' -Force -ErrorAction SilentlyContinue
  }

  # Block all extension installation by default.
  $extBlock = "$base\ExtensionInstallBlocklist"
  if (Test-Path $extBlock) { Remove-Item -Path $extBlock -Recurse -Force -ErrorAction SilentlyContinue }
  Ensure-RegistryKey $extBlock
  Set-RegistryValue -Path $extBlock -Name '1' -Value '*' -Type String

  # Allow specific extensions to be installed despite the '*' blocklist (config-driven).
  # An empty config list removes the key so no previously-set allowlist lingers.
  $extAllow = "$base\ExtensionInstallAllowlist"
  if (Test-Path $extAllow) { Remove-Item -Path $extAllow -Recurse -Force -ErrorAction SilentlyContinue }
  $allowedExtensions = @($Config.Chrome.ExtensionAllowlist | Where-Object { $_ })
  if ($allowedExtensions.Count -gt 0) {
    Ensure-RegistryKey $extAllow
    for ($i = 0; $i -lt $allowedExtensions.Count; $i++) {
      Set-RegistryValue -Path $extAllow -Name ($i + 1).ToString() -Value $allowedExtensions[$i] -Type String
    }
  }

  # Ensure no forced extension install remains from older script versions.
  $extForce = "$base\ExtensionInstallForcelist"
  if (Test-Path $extForce) { Remove-Item -Path $extForce -Recurse -Force -ErrorAction SilentlyContinue }

  # URL blocklist (config-driven). An empty list removes any previously-set key.
  $urlBlock = "$base\URLBlocklist"
  if (Test-Path $urlBlock) { Remove-Item -Path $urlBlock -Recurse -Force -ErrorAction SilentlyContinue }
  $blockedUrls = @($Config.Chrome.URLBlocklist | Where-Object { $_ })
  if ($blockedUrls.Count -gt 0) {
    Ensure-RegistryKey $urlBlock
    for ($i = 0; $i -lt $blockedUrls.Count; $i++) {
      Set-RegistryValue -Path $urlBlock -Name ($i + 1).ToString() -Value $blockedUrls[$i] -Type String
    }
  }

  Write-Host "Per-user Chrome policies written. In Chrome: open chrome://policy and click 'Reload policies'." -ForegroundColor Green
}

function Get-ChromeRestrictSigninPatternFromHive([string]$HiveRoot) {
  if (-not $HiveRoot) { return $null }
  $base = "$HiveRoot\Software\Policies\Google\Chrome"
  if (-not (Test-Path $base)) { return $null }
  try {
    $item = Get-ItemProperty -Path $base -Name 'RestrictSigninToPattern' -ErrorAction Stop
    if ($item -and $item.RestrictSigninToPattern) { return [string]$item.RestrictSigninToPattern }
  } catch {}
  return $null
}

function Convert-RestrictSigninPatternToEmails([string]$RestrictSigninPatternRegex) {
  if ([string]::IsNullOrWhiteSpace($RestrictSigninPatternRegex)) { return @() }

  $parts = @()
  if ($RestrictSigninPatternRegex -match '^\^\((.*)\)\$$') {
    $parts = @($Matches[1] -split '(?<!\\)\|')
  } elseif ($RestrictSigninPatternRegex -match '^\^(.*)\$$') {
    $parts = @($Matches[1])
  } else {
    return @()
  }

  $emails = @()
  foreach ($p in $parts) {
    $candidate = [Regex]::Unescape($p).Trim()
    if ($candidate) { $emails += $candidate }
  }

  return @($emails | Select-Object -Unique)
}

function Remove-ChromeHardening([string]$HiveRoot) {
  Write-Host "Removing per-user Chrome hardening policies from hive: $HiveRoot" -ForegroundColor Yellow
  $base = "$HiveRoot\Software\Policies\Google\Chrome"
  if (Test-Path $base) {
    Remove-Item -Path $base -Recurse -Force -ErrorAction SilentlyContinue
  }
  Write-Host "Removed per-user Chrome policy keys. Restart Chrome to verify." -ForegroundColor Green
}

function Get-UserProfilePath([string]$Sid) {
  $k = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$Sid"
  if (Test-Path $k) {
    return (Get-ItemProperty -Path $k).ProfileImagePath
  }
  return $null
}

function Apply-ChildExecutionDenyAcls([string]$Sid) {
  $profilePath = Get-UserProfilePath $Sid
  if (-not $profilePath -or -not (Test-Path $profilePath)) {
    Write-Host "Skipping execute-deny ACLs because profile path is not available yet." -ForegroundColor Yellow
    return
  }

  # Block running binaries from child-writable locations to reduce rename/copy bypasses.
  $mediaTargets = @(
    (Join-Path $profilePath 'Desktop'),
    (Join-Path $profilePath 'Downloads'),
    (Join-Path $profilePath 'Documents'),
    (Join-Path $profilePath 'Pictures'),
    (Join-Path $profilePath 'Music'),
    (Join-Path $profilePath 'Videos')
  )

  foreach ($p in $mediaTargets) {
    if (-not (Test-Path $p)) { continue }
    Write-Host "Applying execute-deny ACL for child SID on: $p" -ForegroundColor DarkCyan
    & icacls.exe $p /deny "*${Sid}:(OI)(CI)(X)" /T /C | Out-Null
  }

  # AppData trees: set an inheritable deny on the roots only (no /T). Inheritance covers
  # every descendant, and skipping the per-file stamp keeps the Google carve-out below
  # effective (an allow inherited from a nearer ancestor outranks an ancestor's deny).
  $appDataTargets = @(
    (Join-Path $profilePath 'AppData\Local'),
    (Join-Path $profilePath 'AppData\Roaming'),
    (Join-Path $profilePath 'AppData\Local\Temp')
  )

  foreach ($p in $appDataTargets) {
    if (-not (Test-Path $p)) { continue }
    Write-Host "Applying execute-deny ACL for child SID on: $p" -ForegroundColor DarkCyan
    & icacls.exe $p /deny "*${Sid}:(OI)(CI)(X)" /C | Out-Null
  }

  # Some allowed apps need execute back on part of their own AppData tree - Chrome loads
  # updatable components (e.g. the Widevine DRM module used by some school platforms)
  # from AppData\Local\Google. See $Config.ExecuteCarveOuts.
  foreach ($carve in @($Config.ExecuteCarveOuts)) {
    $carvePath = Join-Path $profilePath $carve.Path
    if (-not (Test-Path $carvePath)) {
      if ($carve.CreateIfMissing) {
        New-Item -Path $carvePath -ItemType Directory -Force | Out-Null
      } else {
        Write-Warning "Execute carve-out target does not exist, skipping: $carvePath"
        continue
      }
    }
    Write-Host "Granting execute back on: $carvePath" -ForegroundColor DarkCyan
    & icacls.exe $carvePath /grant "*${Sid}:(OI)(CI)(RX)" /C | Out-Null
  }
}

function Remove-ChildExecutionDenyAcls([string]$Sid) {
  $profilePath = Get-UserProfilePath $Sid
  if (-not $profilePath -or -not (Test-Path $profilePath)) { return }

  $targets = @(
    (Join-Path $profilePath 'Desktop'),
    (Join-Path $profilePath 'Downloads'),
    (Join-Path $profilePath 'Documents'),
    (Join-Path $profilePath 'Pictures'),
    (Join-Path $profilePath 'Music'),
    (Join-Path $profilePath 'Videos'),
    (Join-Path $profilePath 'AppData\Local'),
    (Join-Path $profilePath 'AppData\Roaming'),
    (Join-Path $profilePath 'AppData\Local\Temp')
  )

  foreach ($p in $targets) {
    if (-not (Test-Path $p)) { continue }
    Write-Host "Removing execute-deny ACL for child SID on: $p" -ForegroundColor DarkCyan
    & icacls.exe $p /remove:d "*$Sid" /T /C | Out-Null
  }

  # Remove the compensating execute grants added by Apply-ChildExecutionDenyAcls.
  foreach ($carve in @($Config.ExecuteCarveOuts)) {
    $carvePath = Join-Path $profilePath $carve.Path
    if (Test-Path $carvePath) {
      & icacls.exe $carvePath /remove:g "*$Sid" /C | Out-Null
    }
  }
}

function Resolve-UserHiveAccess([string]$Sid) {
  # Prefer the live HKEY_USERS\<SID> hive if already loaded (common during interactive sign-in).
  $liveMountPath = "Registry::HKEY_USERS\$Sid"
  if (Test-Path $liveMountPath) {
    return [PSCustomObject]@{
      HiveRoot           = "Registry::HKEY_USERS\$Sid"
      TempHiveName       = $null
      LoadedByThisScript = $false
    }
  }

  $profilePath = Get-UserProfilePath $Sid
  if (-not $profilePath) { return $null }

  $ntuser = Join-Path $profilePath 'NTUSER.DAT'
  if (-not (Test-Path $ntuser)) { return $null }

  $mountName = 'TEMP_CHILD_HIVE_{0}' -f ($Sid -replace '[^A-Za-z0-9]', '_')
  $mountPath = "Registry::HKEY_USERS\$mountName"

  if (Test-Path $mountPath) {
    return [PSCustomObject]@{
      HiveRoot           = "Registry::HKEY_USERS\$mountName"
      TempHiveName       = $mountName
      LoadedByThisScript = $false
    }
  }

  Write-Host "Loading user hive from $ntuser" -ForegroundColor DarkCyan
  & reg.exe load "HKU\$mountName" "$ntuser" | Out-Null
  if (($LASTEXITCODE -ne 0) -or -not (Test-Path $mountPath)) {
    # If profile just finished loading after task start, fallback to live SID hive.
    if (Test-Path $liveMountPath) {
      return [PSCustomObject]@{
        HiveRoot           = "Registry::HKEY_USERS\$Sid"
        TempHiveName       = $null
        LoadedByThisScript = $false
      }
    }
    Write-Host "Failed to load user hive for SID $Sid." -ForegroundColor Yellow
    return $null
  }

  return [PSCustomObject]@{
    HiveRoot           = "Registry::HKEY_USERS\$mountName"
    TempHiveName       = $mountName
    LoadedByThisScript = $true
  }
}

function Close-UserHiveAccess($HiveAccess) {
  if (-not $HiveAccess) { return }
  if (-not $HiveAccess.LoadedByThisScript) { return }
  if (-not $HiveAccess.TempHiveName) { return }

  $mountPath = "Registry::HKEY_USERS\$($HiveAccess.TempHiveName)"
  if (-not (Test-Path $mountPath)) { return }

  Write-Host "Unloading user hive..." -ForegroundColor DarkCyan

  # Every Set-ItemProperty against the mounted hive leaves a live RegistryKey handle, and
  # reg.exe cannot unload a hive while any handle into it is open. Collect first to release
  # them, and retry - finalization is not instantaneous.
  for ($attempt = 1; $attempt -le 5; $attempt++) {
    [gc]::Collect()
    [gc]::WaitForPendingFinalizers()
    [gc]::Collect()

    & reg.exe unload "HKU\$($HiveAccess.TempHiveName)" 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
      if ($attempt -gt 1) {
        Write-Host "User hive unloaded (attempt $attempt)." -ForegroundColor DarkCyan
      }
      return
    }
    Start-Sleep -Milliseconds (200 * $attempt)
  }

  # This matters more than it looks: a hive left mounted keeps the child's NTUSER.DAT
  # locked, so Windows hands them a TEMPORARY profile at next sign-in and the whole
  # lockdown appears to have silently done nothing.
  Write-Host "" 
  Write-Host "ERROR: could not unload temporary hive HKU\$($HiveAccess.TempHiveName) after 5 attempts." -ForegroundColor Red
  Write-Host "       The child's NTUSER.DAT is still locked - do NOT sign in as the child yet," -ForegroundColor Red
  Write-Host "       or Windows will give them a temporary profile." -ForegroundColor Red
  Write-Host "       From an elevated PowerShell, run:" -ForegroundColor Red
  Write-Host "         reg unload HKU\$($HiveAccess.TempHiveName)" -ForegroundColor Red
  Write-Host "       If that still fails, reboot and run this script again." -ForegroundColor Red
}

function Ensure-TaskSchedulerHistoryEnabled {
  Write-Host "Ensuring Task Scheduler history is enabled..." -ForegroundColor Cyan

  $wevtutil = Join-Path $env:windir 'System32\wevtutil.exe'
  if (-not (Test-Path $wevtutil)) { $wevtutil = 'wevtutil.exe' }

  & $wevtutil set-log 'Microsoft-Windows-TaskScheduler/Operational' /enabled:true | Out-Null
  if ($LASTEXITCODE -eq 0) {
    Write-Host "Task Scheduler history enabled." -ForegroundColor Green
  } else {
    Write-Host "Warning: could not enable Task Scheduler history." -ForegroundColor Yellow
  }
}

function Set-SystemTimeAndLocation {
  param(
    [Parameter(Mandatory)] [string]$TimeZoneId,
    [Parameter(Mandatory)] [int]$GeoId
  )

  try {
    Set-TimeZone -Id $TimeZoneId -ErrorAction Stop
    Write-Host "Time zone set to '$TimeZoneId'." -ForegroundColor Green
  } catch {
    Write-Host "Warning: failed to set time zone '$TimeZoneId': $($_.Exception.Message)" -ForegroundColor Yellow
  }

  if (Get-Command -Name Set-WinHomeLocation -ErrorAction SilentlyContinue) {
    try {
      Set-WinHomeLocation -GeoId $GeoId -ErrorAction Stop
      Write-Host "Windows home location GeoID set to $GeoId." -ForegroundColor Green
    } catch {
      Write-Host "Warning: failed to set Windows home location GeoID ${GeoId}: $($_.Exception.Message)" -ForegroundColor Yellow
    }
  } else {
    Write-Host "Set-WinHomeLocation cmdlet is unavailable; skipped home location update." -ForegroundColor Yellow
  }
}

function Get-CurrentSystemTimeAndLocation {
  $timeZoneId = $null
  $geoId = $null

  try {
    $tz = Get-TimeZone -ErrorAction Stop
    if ($tz -and $tz.Id) { $timeZoneId = $tz.Id }
  } catch {}

  if (-not $timeZoneId) {
    try {
      $tzText = (& tzutil.exe /g 2>$null)
      if ($tzText) { $timeZoneId = $tzText.Trim() }
    } catch {}
  }

  if (Get-Command -Name Get-WinHomeLocation -ErrorAction SilentlyContinue) {
    try {
      $loc = Get-WinHomeLocation -ErrorAction Stop
      if ($loc -and ($null -ne $loc.GeoId)) { $geoId = [int]$loc.GeoId }
    } catch {}
  }

  return [PSCustomObject]@{
    TimeZoneId = $timeZoneId
    GeoId      = $geoId
  }
}

function Prompt-TimeAndLocationSetup {
  $current = Get-CurrentSystemTimeAndLocation
  $defaultTimeZone = if ($current.TimeZoneId) { $current.TimeZoneId } else { 'Pacific Standard Time' }
  $defaultGeoId = if ($null -ne $current.GeoId) { [int]$current.GeoId } else { 244 } # 244 = United States

  Write-Host "`nTime and location setup:" -ForegroundColor Cyan
  $geoLabel = if ($null -ne $current.GeoId) { $current.GeoId } else { 'unknown' }
  Write-Host "Current system settings: Time Zone = $defaultTimeZone, GeoID = $geoLabel" -ForegroundColor Cyan
  $choice = Read-Host "Keep current system settings? (Y/N, Enter = Y)"

  if ([string]::IsNullOrWhiteSpace($choice) -or ($choice -match '^[Yy]')) {
    Write-Host "Keeping current system time/location settings." -ForegroundColor Green
    return
  }

  $tzInput = Read-Host "Enter Windows Time Zone ID (Enter = $defaultTimeZone)"
  if ([string]::IsNullOrWhiteSpace($tzInput)) { $tzInput = $defaultTimeZone }

  $geoInput = Read-Host "Enter Windows Home Location GeoID (Enter = $defaultGeoId)"
  $geoId = $defaultGeoId
  if (-not [string]::IsNullOrWhiteSpace($geoInput)) {
    if ($geoInput -match '^\d+$') {
      $geoId = [int]$geoInput
    } else {
      Write-Host "Invalid GeoID '$geoInput'; using default $defaultGeoId." -ForegroundColor Yellow
    }
  }

  Set-SystemTimeAndLocation -TimeZoneId $tzInput -GeoId $geoId
}

function Apply-UserLockdownToHive([string]$HiveRoot, [string]$Sid) {
  # $HiveRoot example: Registry::HKEY_USERS\<SID>

  Write-Host "Applying per-user lockdown policies to hive: $HiveRoot" -ForegroundColor Cyan

  # --- Block specific apps by name ---
  # See $Config.BlockedAppExeNames for why this is a deny list and not an allow list.
  $expl = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

  # RestrictRun (the old allow list) is cleared first, and this matters on re-apply:
  # Windows honours RestrictRun over DisallowRun, so a leftover from an earlier run of
  # this script would keep refusing everything and the deny list would never get a say.
  Remove-ItemProperty -Path $expl -Name 'RestrictRun' -Force -ErrorAction SilentlyContinue
  $rr = "$expl\RestrictRun"
  if (Test-Path $rr) { Remove-Item -Path $rr -Recurse -Force -ErrorAction SilentlyContinue }

  Set-RegistryValue -Path $expl -Name 'DisallowRun' -Value 1 -Type DWord
  $dr = "$expl\DisallowRun"
  if (Test-Path $dr) { Remove-Item -Path $dr -Recurse -Force -ErrorAction SilentlyContinue }
  Ensure-RegistryKey $dr
  $blockedApps = @($Config.BlockedAppExeNames | Where-Object { $_ } | Select-Object -Unique)
  for ($i = 0; $i -lt $blockedApps.Count; $i++) {
    Set-RegistryValue -Path $dr -Name ($i + 1).ToString() -Value $blockedApps[$i] -Type String
  }
  Write-Host "Blocked $($blockedApps.Count) executables by name for this child." -ForegroundColor Green

  # Reduce common shell escape vectors.
  Set-RegistryValue -Path $expl -Name 'NoRun'     -Value 1 -Type DWord
  Set-RegistryValue -Path $expl -Name 'NoWinKeys' -Value 1 -Type DWord

  # --- Block CMD ---
  $sysPol = "$HiveRoot\Software\Policies\Microsoft\Windows\System"
  # 2 = disable cmd and also disable batch scripts
  Set-RegistryValue -Path $sysPol -Name 'DisableCMD' -Value 2 -Type DWord

  # --- Block Registry Editor ---
  $sys = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\System"
  Set-RegistryValue -Path $sys -Name 'DisableRegistryTools' -Value 1 -Type DWord

  # --- Enforce lock screen on idle + password on resume ---
  $desktopPol = "$HiveRoot\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
  Set-RegistryValue -Path $desktopPol -Name 'ScreenSaveActive'    -Value '1'   -Type String
  Set-RegistryValue -Path $desktopPol -Name 'ScreenSaverIsSecure' -Value '0'   -Type String
  Set-RegistryValue -Path $desktopPol -Name 'ScreenSaveTimeOut'   -Value ([string]$Config.IdleLockSeconds) -Type String
  Set-RegistryValue -Path $desktopPol -Name 'SCRNSAVE.EXE'        -Value (Join-Path $env:WINDIR 'System32\scrnsave.scr') -Type String

  # --- Start Menu / Taskbar restrictions ---
  # Remove all programs list
  Set-RegistryValue -Path $expl -Name 'NoStartMenuMorePrograms' -Value 1 -Type DWord
  # Remove / prevent Shut Down / Restart
  Set-RegistryValue -Path $expl -Name 'NoClose'                -Value 1 -Type DWord
  # Hide notification area
  Set-RegistryValue -Path $expl -Name 'NoTrayItemsDisplay'     -Value 1 -Type DWord
  # Remove Search link / Disable find
  Set-RegistryValue -Path $expl -Name 'NoFind'                 -Value 1 -Type DWord
  # Remove pinned programs list
  Set-RegistryValue -Path $expl -Name 'NoStartMenuPinnedList'  -Value 1 -Type DWord
  # Remove notification center to reduce distractions.
  Set-RegistryValue -Path $expl -Name 'DisableNotificationCenter' -Value 1 -Type DWord
  # Do not allow pinning changes on taskbar.
  # Set-RegistryValue -Path $expl -Name 'NoPinningToTaskbar'     -Value 1 -Type DWord

  # --- Disable Store ---
  # RemoveWindowsStore hides the Store itself, so the child cannot install anything new.
  # DisableStoreApps is deliberately NOT set: Alpha TimeBack ships as an MSIX/Store
  # package and that value can block packaged apps from launching at all - including
  # TimeBack itself. Removing the Store per-user (ChildOnlyAppxPatterns) is what stops
  # new installs. Clear it actively in case an earlier version of this script set it.
  $store = "$HiveRoot\Software\Policies\Microsoft\WindowsStore"
  Set-RegistryValue -Path $store -Name 'RemoveWindowsStore' -Value 1 -Type DWord
  Remove-ItemProperty -Path $store -Name 'DisableStoreApps' -Force -ErrorAction SilentlyContinue

  # --- File Explorer context menu removal (blocks right-click) ---
  Set-RegistryValue -Path $expl -Name 'NoViewContextMenu' -Value 1 -Type DWord

  # --- Hide / Block all drives in This PC ---
  # "Restrict all drives" bitmask = 0x03FFFFFF (26 letters)
  $allDrives = 0x03FFFFFF
  Set-RegistryValue -Path $expl -Name 'NoDrives'      -Value $allDrives -Type DWord
  Set-RegistryValue -Path $expl -Name 'NoViewOnDrive' -Value $allDrives -Type DWord

  # --- Allow Settings app, but restrict visible pages to approved networking/display/device pages ---
  Set-RegistryValue -Path $expl -Name 'NoControlPanel' -Value 0 -Type DWord
  Set-RegistryValue -Path $expl -Name 'SettingsPageVisibility' -Value $Config.SettingsPages -Type String

  # --- Remove Task Manager ---
  Set-RegistryValue -Path $sys -Name 'DisableTaskMgr' -Value 1 -Type DWord

  # --- Reduce search surfaces (best-effort; varies by Windows build) ---
  $winExplorerPol = "$HiveRoot\Software\Policies\Microsoft\Windows\Explorer"
  Ensure-RegistryKey $winExplorerPol
  Set-RegistryValue -Path $winExplorerPol -Name 'DisableSearchBoxSuggestions' -Value 1 -Type DWord
  # Hide Task View to reduce virtual desktop creation/switching surfaces.
  Set-RegistryValue -Path $winExplorerPol -Name 'HideTaskViewButton' -Value 1 -Type DWord
  
  # Clear pinned Start apps.
  Set-RegistryValue -Path $winExplorerPol -Name 'ConfigureStartPins' -Value '{"pinnedList":[]}' -Type String

  # Disable widgets/feeds surfaces (best-effort across Windows builds).
  $dshPol = "$HiveRoot\Software\Policies\Microsoft\Dsh"
  Set-RegistryValue -Path $dshPol -Name 'AllowNewsAndInterests' -Value 0 -Type DWord
  $feedsPol = "$HiveRoot\Software\Policies\Microsoft\Windows\Windows Feeds"
  Set-RegistryValue -Path $feedsPol -Name 'EnableFeeds' -Value 0 -Type DWord

  # Windows location prompt toggle in child profile:
  # "Notify when apps request location" = off.
  $locationConsent = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
  Set-RegistryValue -Path $locationConsent -Name 'ShowGlobalPrompts' -Value 0 -Type DWord

  # Per-user taskbar/search/feed UI values are applied by a one-time child logon task
  # (offline hive ACLs can block writes under Explorer\Advanced).

  if ($Sid) {
    Apply-ChildExecutionDenyAcls -Sid $Sid
    Apply-ChildShellSurfaceLockdown -HiveRoot $HiveRoot -Sid $Sid
  }

  Write-Host "Per-user lockdown values written." -ForegroundColor Green
}

function Remove-UserLockdownFromHive([string]$HiveRoot, [string]$Sid) {
  Write-Host "Removing per-user lockdown policies from hive: $HiveRoot" -ForegroundColor Yellow

  $expl = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
  $sysPol = "$HiveRoot\Software\Policies\Microsoft\Windows\System"
  $sys = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\System"
  $desktopPol = "$HiveRoot\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
  $store = "$HiveRoot\Software\Policies\Microsoft\WindowsStore"
  $winExplorerPol = "$HiveRoot\Software\Policies\Microsoft\Windows\Explorer"
  $dshPol = "$HiveRoot\Software\Policies\Microsoft\Dsh"
  $feedsPol = "$HiveRoot\Software\Policies\Microsoft\Windows\Windows Feeds"
  $locationConsent = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
  $explorerAdvanced = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
  $search = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Search"
  $feeds = "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Feeds"

  # Remove the keys we created (best-effort)
  foreach ($k in @($expl, "$expl\RestrictRun", "$expl\DisallowRun", $sysPol, $sys, $desktopPol, $store, $winExplorerPol, $dshPol, $feedsPol)) {
    if (Test-Path $k) { Remove-Item -Path $k -Recurse -Force -ErrorAction SilentlyContinue }
  }

  # Clean up non-policy values written under regular per-user locations.
  foreach ($pair in @(
    @{ Path = $locationConsent; Name = 'ShowGlobalPrompts' },
    @{ Path = $explorerAdvanced; Name = 'TaskbarDa' },
    @{ Path = $explorerAdvanced; Name = 'TaskbarMn' },
    @{ Path = $explorerAdvanced; Name = 'ShowTaskViewButton' },
    @{ Path = $search; Name = 'SearchboxTaskbarMode' },
    @{ Path = $search; Name = 'IsDynamicSearchBoxEnabled' },
    @{ Path = $feeds; Name = 'ShellFeedsTaskbarViewMode' }
  )) {
    if (Test-Path $pair.Path) {
      Remove-ItemProperty -Path $pair.Path -Name $pair.Name -Force -ErrorAction SilentlyContinue
    }
  }

  if ($Sid) {
    Remove-ChildExecutionDenyAcls -Sid $Sid
    Remove-ChildShellSurfaceLockdown -HiveRoot $HiveRoot -Sid $Sid
  }

  Write-Host "Per-user lockdown keys removed (where present)." -ForegroundColor Green
}

function Ensure-SecureTaskScriptCopy([string]$SourcePath) {
  $taskDir = Ensure-SecureTaskScriptDirectory

  $destPath = Join-Path $taskDir 'ApplyChildLockdown.ps1'
  $sourceFullPath = [System.IO.Path]::GetFullPath($SourcePath)
  $destFullPath = [System.IO.Path]::GetFullPath($destPath)

  if ($sourceFullPath -ne $destFullPath) {
    Copy-Item -Path $SourcePath -Destination $destPath -Force
  }

  # Lock task script path to SYSTEM + local admins only.
  & icacls.exe $destPath /inheritance:r /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" /C | Out-Null

  return $destPath
}

function Ensure-FirstLogonTask([string]$ChildUserName, [string]$ChildSid, [string]$RestrictSigninPatternRegex) {
  # Creates (or replaces) a SYSTEM task that runs this script at logon of the target user to apply per-user policies.
  # This avoids needing MMC per-user GPO for most settings.

  $taskName = "ApplyChildLockdown_$ChildUserName"
  $scriptPath = $PSCommandPath
  if (-not $scriptPath) { throw "Cannot determine script path. Save this script to disk and rerun." }
  $taskScriptPath = Ensure-SecureTaskScriptCopy -SourcePath $scriptPath

  $cmdArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$taskScriptPath`" -InternalApplyUserLockdown -InternalUserSid `"$ChildSid`""
  if ($RestrictSigninPatternRegex) {
    $patternBytes = [System.Text.Encoding]::Unicode.GetBytes($RestrictSigninPatternRegex)
    $patternBase64 = [Convert]::ToBase64String($patternBytes)
    $cmdArgs += " -InternalRestrictSigninPatternRegexBase64 `"$patternBase64`""
  }

  # Resolve schtasks path (handle Sysnative when running 32-bit PowerShell on 64-bit Windows)
  $schtasksPath = "$env:windir\Sysnative\schtasks.exe"
  if (-not (Test-Path $schtasksPath)) {
    $schtasksPath = "$env:windir\System32\schtasks.exe"
  }
  if (-not (Test-Path $schtasksPath)) {
    $schtasksPath = 'schtasks.exe'
  }

  # If resolved path doesn't exist, fall back to PATH resolution and warn
  if (($schtasksPath -ne 'schtasks.exe') -and -not (Test-Path $schtasksPath)) {
    Write-Host "schtasks not found at $schtasksPath; falling back to PATH resolution." -ForegroundColor Yellow
    $schtasksPath = 'schtasks.exe'
  }
  # Prefer ScheduledTasks cmdlets (clean) with a schtasks.exe fallback for older systems
  if (Get-Command -Name Register-ScheduledTask -ErrorAction SilentlyContinue) {
    try {
      if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
      }

      $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $cmdArgs
      $trigger = New-ScheduledTaskTrigger -AtLogOn -User $ChildUserName
      $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

      Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force -ErrorAction Stop
    } catch {
      throw "Failed to create scheduled task using ScheduledTasks cmdlets: $($_.Exception.Message)"
    }
  } else {
    # Delete existing (best-effort)
    try {
      Start-Process -FilePath $schtasksPath -ArgumentList '/Delete','/TN',$taskName,'/F' -NoNewWindow -Wait -PassThru -ErrorAction Stop | Out-Null
    } catch {
      Write-Host "Existing task delete attempted but failed (may not exist): $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # Create the task using schtasks.exe
    try {
      $trCmd = "powershell.exe $cmdArgs"
      $trArg = '"' + $trCmd + '"'
      Start-Process -FilePath $schtasksPath -ArgumentList '/Create','/TN',$taskName,'/SC','ONLOGON','/RU','SYSTEM','/RL','HIGHEST','/TR',$trArg,'/F' -NoNewWindow -Wait -PassThru -ErrorAction Stop | Out-Null
    } catch {
      throw "Failed to create scheduled task via ${schtasksPath}: $($_.Exception.Message)"
    }
  }

  Write-Host "Created logon task '$taskName' to apply per-user Chrome + Windows lockdown at first sign-in." -ForegroundColor Green
}

function Internal-ApplyUserLockdown([string]$Sid, [string]$RestrictSigninPatternRegex) {
  Assert-Admin
  $hiveAccess = $null
  try {
    $hiveAccess = Resolve-UserHiveAccess $Sid
    if (-not $hiveAccess) {
      Write-Host "User hive not available yet (profile not created)." -ForegroundColor Yellow
      return
    }
    Remove-LegacyMachineChromeHardening
    Apply-ChromeHardening -HiveRoot $hiveAccess.HiveRoot -RestrictSigninPatternRegex $RestrictSigninPatternRegex
    Apply-UserLockdownToHive -HiveRoot $hiveAccess.HiveRoot -Sid $Sid
  } finally {
    Close-UserHiveAccess -HiveAccess $hiveAccess
  }

  # Deliberately after the hive is unloaded: the app model writes to the target user's
  # own registry, and it cannot do that while we still have NTUSER.DAT mounted.
  Remove-ChildOnlyAppxPackages -Sid $Sid
}

# ---------------- MAIN ----------------
Assert-Admin
Assert-LockdownConfig
try {
  Start-SecureTranscriptLogging
  $secureTaskScriptPath = $null
  $scriptPathForSecureCopy = $PSCommandPath
  if (-not $scriptPathForSecureCopy) { $scriptPathForSecureCopy = $MyInvocation.MyCommand.Path }
  if ($scriptPathForSecureCopy -and (Test-Path $scriptPathForSecureCopy)) {
    try {
      $secureTaskScriptPath = Ensure-SecureTaskScriptCopy -SourcePath $scriptPathForSecureCopy
    } catch {
      Write-Host "Warning: could not refresh secure task script copy: $($_.Exception.Message)" -ForegroundColor Yellow
    }
  } else {
    Write-Host "Warning: script path was not resolvable; secure task script copy was not refreshed." -ForegroundColor Yellow
  }

  if ($InternalApplyUserLockdown) {
    if (-not $InternalUserSid) { throw 'Missing -InternalUserSid' }
    $internalRestrictPattern = $null
    if ($InternalRestrictSigninPatternRegexBase64) {
      try {
        $patternBytes = [Convert]::FromBase64String($InternalRestrictSigninPatternRegexBase64)
        $internalRestrictPattern = [System.Text.Encoding]::Unicode.GetString($patternBytes)
      } catch {
        throw "Invalid -InternalRestrictSigninPatternRegexBase64 value: $($_.Exception.Message)"
      }
    }
    Internal-ApplyUserLockdown -Sid $InternalUserSid -RestrictSigninPatternRegex $internalRestrictPattern
    return
  }

  if ($RemoveChromePolicies) {
    if (-not $UserName) { $UserName = Read-Host 'Enter the child local username to remove Chrome policies from' }
    $sid = Get-LocalUserSid $UserName
    if (-not $sid) { throw "Could not find SID for user '$UserName'" }

    $hiveAccess = $null
    try {
      $hiveAccess = Resolve-UserHiveAccess $sid
      if (-not $hiveAccess) {
        Write-Host "Cannot load hive now. Have the user sign in once to create the profile, then rerun." -ForegroundColor Yellow
        return
      }
      Remove-ChromeHardening -HiveRoot $hiveAccess.HiveRoot
      Remove-LegacyMachineChromeHardening
    } finally {
      Close-UserHiveAccess -HiveAccess $hiveAccess
    }
    return
  }

  if ($RemoveUserLockdown) {
    if (-not $UserName) { $UserName = Read-Host 'Enter the child local username to unlock' }
    $sid = Get-LocalUserSid $UserName
    if (-not $sid) { throw "Could not find SID for user '$UserName'" }

    $hiveAccess = $null
    try {
      $hiveAccess = Resolve-UserHiveAccess $sid
      if (-not $hiveAccess) {
        Write-Host "Cannot load hive now. Have the user sign in once to create the profile, then rerun." -ForegroundColor Yellow
        return
      }
      Remove-UserLockdownFromHive -HiveRoot $hiveAccess.HiveRoot -Sid $sid
    } finally {
      Close-UserHiveAccess -HiveAccess $hiveAccess
    }

    Restore-ChildOnlyAppxPackages -Sid $sid

    Remove-FirstLogonTask -ChildUserName $UserName
    Remove-ChildTaskbarUiLockTask -ChildUserName $UserName
    Remove-LegacyInstallTasks -ChildUserName $UserName
    return
  }

  # Interactive flow
  $selection = Prompt-ChildUserSelection
  $childUser = $selection.UserName
  if (-not $childUser) { throw 'Username cannot be empty.' }
  
  Ensure-CurrentUserExecutionPolicyBypass
  Ensure-TaskSchedulerHistoryEnabled
  Prompt-TimeAndLocationSetup

  Ensure-WidgetsDisabledMachinePolicy
  Remove-UnnecessaryBuiltInApps
  Ensure-ChromeInstalled
  $creationResult = $null
  if ($selection.CreateNew) {
    $creationResult = Create-LocalStandardUser -Name $childUser
  } else {
    if (Test-LocalUserIsAdmin -Name $childUser) {
      throw "Selected user '$childUser' is an administrator. Choose a non-admin account."
    }
    Write-Host "Using existing non-admin local user '$childUser'." -ForegroundColor Green
  }

  $promptForPasswordUpdate = $true
  if ($selection.CreateNew -and $creationResult -and $creationResult.PasswordConfigured) {
    $promptForPasswordUpdate = $false
  }
  Ensure-ChildUserPasswordSettings -Name $childUser -PromptForPasswordUpdate:$promptForPasswordUpdate
  $sid = Get-LocalUserSid $childUser
  if (-not $sid) { throw "Could not resolve SID for '$childUser'" }

  # Always clean up stale scheduled tasks and payloads from prior script versions.
  Remove-FirstLogonTask -ChildUserName $childUser
  Remove-ChildTaskbarUiLockTask -ChildUserName $childUser
  Remove-LegacyInstallTasks -ChildUserName $childUser

  if ($selection.CreateNew) {
    Write-Host "`nNew child account '$childUser' created." -ForegroundColor Green
    Write-Host "Next step required before lockdown can be applied:" -ForegroundColor Cyan
    Write-Host "1) Sign in as '$childUser' once (initializes the user profile), then sign out." -ForegroundColor Cyan
    Write-Host "2) (Recommended) Install the allowed apps (e.g., Alpha TimeBack) system-wide as admin if not present." -ForegroundColor Cyan
    Write-Host "3) Sign back in as admin and run this script again; select existing user '$childUser'." -ForegroundColor Cyan
    return
  }

  Ensure-ChildTaskbarUiLockTask -ChildUserName $childUser -Sid $sid

  # Chrome RestrictSigninToPattern
  Write-Host "`nChrome sign-in restriction:" -ForegroundColor Cyan
  $emails = @($Config.AllowedSigninEmails | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
  if ($emails.Count -gt 0) {
    Write-Host ("Using allowed sign-in email(s) from config: {0}" -f ($emails -join ', ')) -ForegroundColor DarkCyan
  }
  $defaultAllowedEmails = @()
  if (($emails.Count -eq 0) -and (-not $selection.CreateNew)) {
    $existingPattern = $null
    $existingPolicyHive = $null
    try {
      $existingPolicyHive = Resolve-UserHiveAccess $sid
      if ($existingPolicyHive) {
        $existingPattern = Get-ChromeRestrictSigninPatternFromHive -HiveRoot $existingPolicyHive.HiveRoot
      }
    } finally {
      Close-UserHiveAccess -HiveAccess $existingPolicyHive
    }
    if ($existingPattern) {
      $defaultAllowedEmails = Convert-RestrictSigninPatternToEmails -RestrictSigninPatternRegex $existingPattern
      if ($defaultAllowedEmails.Count -gt 0) {
        Write-Host ("Existing allowed email(s): {0}" -f ($defaultAllowedEmails -join ', ')) -ForegroundColor DarkCyan
      } else {
        Write-Host "Existing RestrictSigninToPattern found but not in simple email-list form; enter desired email(s)." -ForegroundColor Yellow
      }
    }
  }

  if ($defaultAllowedEmails.Count -gt 0) {
    $emailsRaw = Read-Host 'Keep existing allowed email(s)? (Y/N, Enter = Y)'
    if ([string]::IsNullOrWhiteSpace($emailsRaw) -or ($emailsRaw -match '^[Yy]')) {
      $emails = @($defaultAllowedEmails)
    } 
  } 
  if ($emails.Count -eq 0) {
    Write-Host "Enter allowed child email(s). Separate multiple emails with commas. Leave blank to allow all." -ForegroundColor Cyan
    $emailsRaw = Read-Host 'Allowed email(s)'
    if ($emailsRaw) {
      $emails = @($emailsRaw.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
  }
  $emails = @($emails | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ } | Select-Object -Unique)

  $pattern = $null
  if ($emails.Count -eq 1) {
    # exact match
    $escaped = [Regex]::Escape($emails[0])
    $pattern = "^$escaped$"
  } elseif ($emails.Count -gt 1) {
    $escaped = $emails | ForEach-Object { [Regex]::Escape($_) }
    $pattern = "^($($escaped -join '|'))$"
  } else {
    Write-Host "No email pattern provided; Chrome will still force sign-in but will not restrict to a specific account." -ForegroundColor Yellow
  }

  # Per-user lockdown + Chrome policy
  Write-Host "`nApplying per-user Chrome and Windows lockdown for '$childUser'..." -ForegroundColor Cyan
  $hiveAccess = $null
  try {
    $hiveAccess = Resolve-UserHiveAccess $sid
    if ($hiveAccess) {
      Remove-LegacyMachineChromeHardening
      Apply-ChromeHardening -HiveRoot $hiveAccess.HiveRoot -RestrictSigninPatternRegex $pattern
      Apply-UserLockdownToHive -HiveRoot $hiveAccess.HiveRoot -Sid $sid
    } else {
      Write-Host "User profile hive not found yet. Sign in once as '$childUser', sign out, then rerun this script." -ForegroundColor Yellow
      return
    }
  } finally {
    Close-UserHiveAccess -HiveAccess $hiveAccess
  }

  # See Internal-ApplyUserLockdown: this has to happen with the hive unloaded.
  Remove-ChildOnlyAppxPackages -Sid $sid

  Write-Host "`nDONE." -ForegroundColor Green
  $secureRoot = Ensure-SecureChildLockdownRoot
  if (-not $secureTaskScriptPath) {
    $secureTaskScriptPath = Join-Path (Join-Path $secureRoot 'TaskScripts') 'ApplyChildLockdown.ps1'
  }
  Write-Host "Reusable secure path (kept until manually removed): $secureRoot" -ForegroundColor Cyan
  if (Test-Path $secureTaskScriptPath) {
    Write-Host "- Script copy (admin/system only): $secureTaskScriptPath" -ForegroundColor Cyan
  }
  Write-Host "finished." -ForegroundColor Cyan
  Write-Host "`nRollback (must be run as the administrative user):" -ForegroundColor Yellow
  Write-Host "- Remove Chrome policies:   $secureTaskScriptPath -RemoveChromePolicies -UserName $childUser" -ForegroundColor Yellow
  Write-Host "- Remove user lockdown:     $secureTaskScriptPath -RemoveUserLockdown -UserName $childUser" -ForegroundColor Yellow
} finally {
  Stop-SecureTranscriptLogging
}
