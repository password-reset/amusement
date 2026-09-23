# amusement

*anagram of "teams enum"*

Authenticated cross-tenant M365 user enumeration and external chat discovery via the Teams `externalsearchv3` API, with SMTP auditing and DNS recon.

The technique exploits the same `externalsearchv3` API that powers the autocomplete when composing a new chat message in Teams (every keystroke in the "To" field triggers a lookup against external tenants). This tool just calls that endpoint directly. Because it's a type-ahead endpoint handling per-keystroke queries across all Teams users globally, rate limiting and other anti-enumeration controls appears to be minimal or absent.

## Usage examples

### With config file (recommended)

Set your tokens and domain in `amusement.json` once (see Config section below), then:

```bash
# Teams enum + DNS recon (most common use case)
python3 amusement.py -e users.txt --disable-smtp-checks

# Single email check
python3 amusement.py -e j.smith@corp.com --disable-smtp-checks

# Full recon: Teams enum + DNS + SMTP audit
python3 amusement.py 10.0.0.25 -e users.txt

# DNS only (no Teams, no SMTP) - check provider, Direct Send, SPF/DMARC
python3 amusement.py -d corp.com --disable-smtp-checks
```

### Without config file

```bash
# Teams enum with bearer token on CLI
python3 amusement.py -e users.txt -d corp.com \
  --teams-token 'eyJ0eX...' --disable-smtp-checks

# Long-running session with auto-refreshing token
python3 amusement.py -e large_list.txt -d corp.com \
  --refresh-token '0.AVY...' --client-id '5e3ce6c0-...' \
  --threads 20 --teams-output valid.txt --disable-smtp-checks

# SMTP audit only (no Teams, no DNS)
python3 amusement.py 10.0.0.25 -p 25,587

# SMTP with VRFY user enumeration
python3 amusement.py 10.0.0.25 -U usernames.txt -d corp.com

# Comma-separated emails, APAC region
python3 amusement.py -e 'admin@corp.com,hr@corp.com,it@corp.com' \
  --region apac --disable-smtp-checks
```

### Input formats for `-e`

```bash
# Single email
-e admin@corp.com

# Comma-separated list
-e 'admin,hr,finance'  # requires -d corp.com to append domain

# File (one per line)
-e users.txt
```

## Extracting bearer + refresh tokens

Open Teams (PWA or https://teams.microsoft.com) in Brave/Chrome/Edge, press **F12 > Console**, paste:

```js
(()=>{let cid='';[sessionStorage,localStorage].forEach(s=>{for(let i=0;i<s.length;i++){let k=s.key(i);if(k.includes('accesstoken')&&k.includes('api.spaces.skype.com')){cid=k.split('|')[4]||'';let o=JSON.parse(s.getItem(k));console.log('BEARER (client_id='+cid+'):');console.log(o.secret)}}});if(!cid){console.log('No bearer found');return}[sessionStorage,localStorage].forEach(s=>{for(let i=0;i<s.length;i++){let k=s.key(i);if(k.includes('refreshtoken')&&k.includes(cid)){let o=JSON.parse(s.getItem(k));console.log('REFRESH TOKEN (client_id='+cid+'):');console.log(o.secret)}}})})()
```

- **BEARER:** use with `--teams-token` or put in config. Expires in ~60 min.
- **REFRESH TOKEN** + **client_id:** use with `--refresh-token` and `--client-id`. The script auto-refreshes every 50 min. Lasts up to 90 days.

**Requires a commercial M365 tenant**. Consumer accounts (outlook.com) don't seem to work.

## Config file

Drop your engagement settings in `amusement.json` (same directory as the script) to avoid passing tokens on the CLI every time:

```json
{
    "domain":        "corp.com",
    "teams_token":   "",
    "refresh_token": "0.AVY...",
    "client_id":     "5e3ce6c0-...",
    "region":        "emea",
    "threads":       5,
    "ports":         "25,465,587",
    "teams_output":  "teams_valid.txt"
}
```

CLI args always override config values. Empty strings are treated as unset.

## What it does

| Module | What | How |
|--------|------|-----|
| **Teams** | User enumeration via `externalsearchv3` | Authenticated API (bearer token) |
| **DNS** | MX, SPF, DMARC, CNAME chase, provider detection, Direct Send | dnspython |
| **SMTP** | Banner, EHLO, VRFY enum, open relay, TLS, NTLM info leak, vuln scan | Raw sockets + nmap NSE scripts |

## Teams enum results

| Output | Meaning |
|--------|---------|
| `[+] OPEN` | User exists, Teams-licensed, external chat allowed |
| `[!] 403` | User exists but tenant blocks external chat |
| `[-] not found` | User doesn't exist or has no Teams license |
| `[x] 401` | Bearer expired or invalid |

## DNS / provider detection

MX records are resolved and CNAMEs chased to identify the actual mail provider. Recognized providers:

| Provider | Action |
|----------|--------|
| M365 (`*.mail.protection.outlook.com`) | Continue + Direct Send check |
| Google Workspace, Yahoo, Fastmail, Zoho | **Abort** Teams enum (not M365) |
| Proofpoint, Mimecast, Barracuda, Cisco, Sophos, Trend Micro, FireEye | Warning (gateway - may front M365) |

If MX points to a non-M365 provider, Teams enumeration is skipped automatically since externalsearchv3 requires an M365 tenant.

When a gateway is detected, the script probes `<domain-dashed>.mail.protection.outlook.com` to confirm whether M365 is behind it.

### Direct Send

M365 accepts unauthenticated SMTP on port 25 at `*.mail.protection.outlook.com`. The script detects the endpoint in two cases:

- **Direct MX** — MX points straight to `*.mail.protection.outlook.com`
- **Behind a gateway** — MX is Barracuda/Proofpoint/etc., but the M365 endpoint is confirmed via DNS probe

The script cross-references SPF and DMARC posture to gauge spoofing viability:

| SPF | DMARC | Assessment |
|-----|-------|------------|
| `-all` | `p=reject` | Likely dropped, but test to confirm |
| `-all` | `p=quarantine` | May land in junk |
| `~all` or weaker | `p=none` or missing | Likely lands in inbox |

DNS records alone can't account for Exchange transport rules, EOP anti-spoof policies, or third-party filtering. The only real test is to send a swaks spoof to your point of contact and confirm whether it hit inbox, junk, or quarantine. The script prints a ready-to-use command — swap in the POC's address.

**Note:** orgs with a mail gateway (Barracuda, Proofpoint, etc.) may have a partner connector configured with `RestrictDomainsToIPAddresses` or `RestrictDomainsToCertificate`, which locks down the M365 endpoint to only accept mail from the gateway's IPs. In that case, swaks will return `550 5.7.51 TenantInboundAttribution` at `RCPT TO` — Direct Send is mitigated. The endpoint resolves and accepts connections, but rejects delivery from unauthorized sources.

## Options

```
positional:
  host                    Target host/IP for SMTP checks

flags:
  -e, --email             Email(s): address, comma list, or file (one per line)
  -d, --domain            Domain for bare usernames + DNS lookups
  -p, --ports             SMTP ports (default: 25,465,587)
  -U, --users             File of usernames for VRFY enum
  --teams-token           Bearer token (from F12 snippet)
  --refresh-token         Refresh token (auto-refreshes every 50 min)
  --client-id             OAuth client ID (must match refresh token)
  --region                API region: emea, amer, apac (default: emea)
  --threads               Concurrent Teams checks (default: 5)
  --teams-output          Write valid emails to file
  --exists-only           Only show users that exist (suppress misses)
  --disable-smtp-checks   Skip SMTP, run Teams + DNS only
```

## Dependencies

```
pip install requests dnspython
```
