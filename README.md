# ChildLockdown

Locks the child accounts on a shared Windows 11 laptop down to schoolwork.
Each child account can open only an allowed set of apps (Chrome, the school
app, and a few basic tools). Chrome on a child account accepts only that
child's own Google addresses. The administrator account is untouched.

Based on [Child-School-Account-Lockdown](https://github.com/philliphall/Child-School-Account-Lockdown)
by philliphall (MIT), heavily modified.

## Download

Grab the ready-made ZIP from the
[latest release](../../releases/latest/download/ChildLockdown.zip) and
extract it into the Downloads folder of the laptop's administrator account.
The step-by-step setup guide lives in the family's Google Doc.

## Use

From an administrator PowerShell:

    powershell -ExecutionPolicy Bypass -File "$HOME\Downloads\ChildLockdown\TaskScripts\ApplyChildLockdown.ps1"

The script is interactive: it creates the child account, installs Chrome if
missing, asks for the allowed sign-in emails, and applies the lockdown. Run
it once to create the account, have the child sign in and out once, then run
it again to lock the account. Rerunning is always safe.

All per-deployment settings live in the `$Config` block at the top of the
script. No personal data is stored in this repository; names and emails are
entered when the script runs.

## Updating the release ZIP

After changing the script, rebuild and re-upload the asset so the download
link stays current:

    zip -r ChildLockdown.zip TaskScripts -x "*.bak*"
    gh release upload v1.0.0 ChildLockdown.zip --clobber
