# Detect Domain Admin Logins on Servers

This KQL script identifies **logins by Domain Admin accounts on Windows servers**, helping security teams monitor privileged access and detect potential misuse.

---

## Purpose

Helps security teams:
- Detect and audit **logins by high-privilege Domain Admin accounts**
- Identify **unauthorized or unexpected use** of privileged credentials
- Strengthen **server access visibility** and security monitoring

---

## KQL Query

```kusto
SecurityEvent
| where EventID in (4624, 4648)  // Successful logon and logon with explicit credentials
| where AccountType == "User"
| where Account has "DOMAIN"  // Adjust to your domain name if needed
| where TargetUserName !endswith "$"  // Exclude machine accounts
| extend UserSID = tostring(TargetUserSid)
| join kind=inner (
    IdentityInfo
    | where Title contains "Domain Admin"  // Title must map to Domain Admins
    | project TargetUserSid = Sid, DA_Username = AccountName
) on TargetUserSid
| project TimeGenerated, Computer, DA_Username, LogonType, Account, TargetDomainName, TargetUserName, IpAddress, EventID
| order by TimeGenerated desc
