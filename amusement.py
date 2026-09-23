#!/usr/bin/env python3
"""
amusement.py - M365 Teams external-chat user enumeration + SMTP audit.

EXTRACTING BEARER + REFRESH TOKENS (Teams PWA)
  1. Open Teams (PWA or https://teams.microsoft.com) in Brave/Chrome/Edge
  2. Press F12 > Console
  3. Paste this one-liner:

(()=>{let cid='';[sessionStorage,localStorage].forEach(s=>{for(let i=0;i<s.length;i++){let k=s.key(i);if(k.includes('accesstoken')&&k.includes('api.spaces.skype.com')){cid=k.split('|')[4]||'';let o=JSON.parse(s.getItem(k));console.log('BEARER (client_id='+cid+'):');console.log(o.secret)}}});if(!cid){console.log('No bearer found');return}[sessionStorage,localStorage].forEach(s=>{for(let i=0;i<s.length;i++){let k=s.key(i);if(k.includes('refreshtoken')&&k.includes(cid)){let o=JSON.parse(s.getItem(k));console.log('REFRESH TOKEN (client_id='+cid+'):');console.log(o.secret)}}})})()

  4. Copy the BEARER for --teams-token, or use REFRESH TOKEN + client_id
     for long-running sessions:

     python3 amusement.py -e users.txt -d corp.com \\
       --refresh-token '<RT>' --client-id '<client_id>'
"""

import argparse, base64, json, os, shutil, socket, ssl, subprocess
import threading, time, sys
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    requests = None


_no_color = not sys.stdout.isatty() or os.environ.get('NO_COLOR')
def _a(code): return '' if _no_color else f'\033[{code}m'

W, G, R, Y, C, M = _a(37), _a(32), _a(31), _a(33), _a(36), _a(35)
B, DIM, RST = _a(1), _a(2), _a(0)

BANNER_ART = rf"""{C}{B}                                                      _
   __ _ _ __ ___  _   _ ___  ___ _ __ ___   ___ _ __ | |_
  / _` | '_ ` _ \| | | / __|/ _ \ '_ ` _ \ / _ \ '_ \| __|
 | (_| | | | | | | |_| \__ \  __/ | | | | |  __/ | | | |_
  \__,_|_| |_| |_|\__,_|___/\___|_| |_| |_|\___|_| |_|\__|
                                {Y}teams enum + smtp audit  {DIM}v1.1{RST}"""


def _show_banner():
    if _no_color or not sys.stdout.isatty():
        print(f"\n{BANNER_ART}\n")
        return

    P = 18
    moves = [
        ('T', P+0,  P+16), ('E', P+2,  P+8),  ('A', P+4,  P+0),
        ('M', P+6,  P+2),  ('S', P+8,  P+6),  ('E', P+12, P+12),
        ('N', P+14, P+14), ('U', P+16, P+4),   ('M', P+18, P+10),
    ]

    W, FRAMES = 50, 14
    buf = [' '] * W
    for ch, sx, _ in moves:
        if 0 <= sx < W: buf[sx] = ch
    print()
    sys.stdout.write(f'  {C}{B}{"".join(buf).rstrip()}{RST}')
    sys.stdout.flush()
    time.sleep(0.4)

    for f in range(1, FRAMES + 1):
        t = f / FRAMES
        t = t * t * (3 - 2 * t)
        buf = [' '] * W
        for ch, sx, ex in moves:
            x = int(sx + (ex - sx) * t + 0.5)
            if 0 <= x < W: buf[x] = ch
        sys.stdout.write(f'\033[2K\r  {C}{B}{"".join(buf).rstrip()}{RST}')
        sys.stdout.flush()
        time.sleep(0.05)

    time.sleep(0.3)
    sys.stdout.write('\033[2K\r')
    print(BANNER_ART)
    print()

_COLS = shutil.get_terminal_size((120, 24)).columns
_PAD  = 39  # 2 + 8 + 1 + 16 + 1 + 6 + 1 + 3 + 1

def log(proto, target, port, status, msg, color=W):
    tag = f"{C}{B}{proto:<8}{RST}"
    tgt = f"{W}{target:<16}{RST}" if target else f"{'':16}"
    prt = f"{DIM}{port:<6}{RST}" if port else f"{'':6}"
    prefix = f"  {tag} {tgt} {prt} {color}{status}{RST} "
    avail = max(40, _COLS - _PAD)
    indent = '\n' + ' ' * _PAD + color
    words, lines, cur = msg.split(), [], ''
    for w in words:
        if cur and len(cur) + 1 + len(w) > avail:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}" if cur else w
    if cur: lines.append(cur)
    print(f"{prefix}{color}{(indent).join(lines)}{RST}")

def info(proto, target, port, msg):   log(proto, target, port, '[*]', msg, C)
def good(proto, target, port, msg):   log(proto, target, port, '[+]', msg, G)
def bad(proto, target, port, msg):    log(proto, target, port, '[-]', msg, DIM)
def warn(proto, target, port, msg):   log(proto, target, port, '[!]', msg, Y)
def fail(proto, target, port, msg):   log(proto, target, port, '[x]', msg, R)

TEAMS_CLIENT_ID = '1fec8e78-bce4-4aaf-ab1b-5451cc387264'
TOKEN_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
REFRESH_INTERVAL = 50 * 60

def _jwt_exp(token):
    try:
        part = token.split('.')[1]
        part += '=' * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part)).get('exp', 0) - time.time()
    except Exception:
        return -1

def _do_refresh(refresh_token, client_id=None):
    r = requests.post(TOKEN_URL, data={
        'grant_type':    'refresh_token',
        'client_id':     client_id or TEAMS_CLIENT_ID,
        'refresh_token': refresh_token,
        'scope':         'https://api.spaces.skype.com/.default offline_access',
    }, headers={'Origin': 'https://teams.microsoft.com'}, timeout=30)
    if r.status_code != 200:
        return None, None, r.text[:200]
    d = r.json()
    return d.get('access_token'), d.get('refresh_token'), None


class TokenHolder:
    def __init__(self, bearer=None, refresh_token=None, client_id=None):
        self._bearer, self._rt, self._cid = bearer, refresh_token, client_id
        self._lock, self._timer, self._stop = threading.Lock(), None, threading.Event()

    @property
    def bearer(self):
        with self._lock:
            return self._bearer

    def refresh_now(self):
        if not self._rt:
            return False
        info('TOKEN', '', '', 'refreshing bearer via Azure AD...')
        new_bearer, new_rt, err = _do_refresh(self._rt, self._cid)
        if err:
            fail('TOKEN', '', '', f'refresh failed: {err}')
            return False
        with self._lock:
            self._bearer = new_bearer
            if new_rt:
                self._rt = new_rt
        ttl = int(_jwt_exp(new_bearer))
        good('TOKEN', '', '', f'new bearer obtained, expires in {ttl//60}m{ttl%60}s')
        return True

    def _loop(self):
        if self._stop.is_set(): return
        self.refresh_now()
        if not self._stop.is_set():
            self._timer = threading.Timer(REFRESH_INTERVAL, self._loop)
            self._timer.daemon = True
            self._timer.start()

    def start(self):
        if not self._rt: return
        if not self.refresh_now():
            warn('TOKEN', '', '', 'initial refresh failed - falling back to --teams-token')
            return
        self._timer = threading.Timer(REFRESH_INTERVAL, self._loop)
        self._timer.daemon = True
        self._timer.start()
        info('TOKEN', '', '', f'auto-refresh armed (every {REFRESH_INTERVAL//60}m)')

    def stop(self):
        self._stop.set()
        if self._timer: self._timer.cancel()


def run(cmd, timeout=120):
    if shutil.which(cmd[0]) is None:
        return False, f"{cmd[0]} not found in PATH"
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return True, (p.stdout + p.stderr).strip()
    except subprocess.TimeoutExpired:
        return False, f"timeout: {' '.join(cmd)}"
    except Exception as e:
        return False, str(e)

def smtp_converse(host, port, commands, timeout=10, use_tls=False):
    transcript = []
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw)
        raw.settimeout(timeout)
        transcript.append(raw.recv(2048).decode(errors="replace").strip())
        for cmd in commands:
            raw.sendall((cmd + "\r\n").encode())
            time.sleep(0.3)
            try:
                transcript.append(f">>> {cmd}")
                transcript.append(raw.recv(2048).decode(errors="replace").strip())
            except socket.timeout:
                transcript.append("[no response]")
        raw.close()
    except Exception as e:
        transcript.append(str(e))
    return "\n".join(transcript)


def check_banner_and_ehlo(host, port):
    info('SMTP', host, port, 'banner + EHLO')
    resp = smtp_converse(host, port, ["EHLO recon.local", "HELP", "QUIT"])
    for line in resp.splitlines():
        if line.startswith('>>>'):
            print(f"  {'':8} {'':16} {'':6} {DIM}{line}{RST}")
        elif line.startswith('2'):
            print(f"  {'':8} {'':16} {'':6} {G}{line}{RST}")
        elif line.startswith(('4', '5')):
            print(f"  {'':8} {'':16} {'':6} {R}{line}{RST}")
        else:
            print(f"  {'':8} {'':16} {'':6} {W}{line}{RST}")


def check_user_enum(host, port, users):
    info('SMTP', host, port, f'VRFY enumeration ({len(users)} users)')
    cmds = ["EHLO recon.local"] + [f"VRFY {u}" for u in users] + ["QUIT"]
    resp = smtp_converse(host, port, cmds)
    for line in resp.splitlines():
        if 'VRFY' in line:
            continue
        if line.startswith('250'):
            good('SMTP', host, port, f'VRFY {line}')
        elif line.startswith('550'):
            bad('SMTP', host, port, f'VRFY {line}')
        elif line.startswith(('252', '251')):
            warn('SMTP', host, port, f'VRFY {line}')


def check_open_relay(host, port):
    info('SMTP', host, port, 'open relay check (nmap)')
    ok, out = run(["nmap", "-p", str(port), "--script", "smtp-open-relay", "-v", host])
    if not ok:
        bad('SMTP', host, port, out)
        return
    for line in out.splitlines():
        if 'OPEN RELAY' in line.upper() or 'open relay' in line.lower():
            warn('SMTP', host, port, line.strip())
        elif 'smtp-open-relay' in line:
            good('SMTP', host, port, line.strip()) if 'not' in line.lower() else info('SMTP', host, port, line.strip())


def check_tls(host, port):
    info('SMTP', host, port, 'TLS / STARTTLS')
    ok, out = run(["nmap", "-p", str(port), "--script", "ssl-enum-ciphers,ssl-cert", host])
    if not ok:
        bad('SMTP', host, port, out)
        return
    for line in out.splitlines():
        ls = line.strip()
        if not ls: continue
        if 'SSLv' in ls or 'TLSv1.0' in ls or 'TLSv1.1' in ls:
            warn('SMTP', host, port, f'weak: {ls}')
        elif 'TLSv1.2' in ls or 'TLSv1.3' in ls:
            good('SMTP', host, port, ls)
        elif 'subject:' in ls.lower() or 'issuer:' in ls.lower():
            info('SMTP', host, port, ls)


def check_ntlm_info(host, port):
    info('SMTP', host, port, 'AUTH NTLM info leak')
    ok, out = run(["nmap", "-p", str(port), "--script", "smtp-ntlm-info", host])
    if not ok:
        bad('SMTP', host, port, out)
        return
    for line in out.splitlines():
        ls = line.strip()
        if any(k in ls for k in ('Target_Name', 'NetBIOS', 'DNS_', 'Product_')):
            good('SMTP', host, port, ls)


def check_vulns(host, port):
    info('SMTP', host, port, 'vulnerability scan (nmap)')
    ok, out = run(["nmap", "-p", str(port), "--script", "smtp-vuln-*", host])
    if not ok:
        bad('SMTP', host, port, out)
        return
    for line in out.splitlines():
        ls = line.strip()
        if 'VULNERABLE' in ls:
            warn('SMTP', host, port, f'VULN: {ls}')
        elif 'CVE-' in ls:
            warn('SMTP', host, port, ls)


# ---------------------------------------------------------------------------
# DNS records
# ---------------------------------------------------------------------------
PROVIDERS = {
    'mail.protection.outlook.com': ('M365',            'm365'),
    'google.com':                  ('Google Workspace', 'foreign'),
    'googlemail.com':              ('Google Workspace', 'foreign'),
    'yahoodns.net':                ('Yahoo Mail',       'foreign'),
    'messagingengine.com':         ('Fastmail',         'foreign'),
    'zoho.com':                    ('Zoho Mail',        'foreign'),
    'pphosted.com':                ('Proofpoint',       'gateway'),
    'ppe-hosted.com':              ('Proofpoint',       'gateway'),
    'mimecast.com':                ('Mimecast',         'gateway'),
    'barracudanetworks.com':       ('Barracuda',        'gateway'),
    'iphmx.com':                   ('Cisco IronPort',   'gateway'),
    'sophos.com':                  ('Sophos',           'gateway'),
    'trendmicro.com':              ('Trend Micro',      'gateway'),
    'fireeyecloud.com':            ('FireEye/Trellix',  'gateway'),
    'exclaimer.net':               ('Exclaimer',        'gateway'),
}


def _chase_cname(hostname, resolver):
    chain, seen = [hostname], {hostname}
    while True:
        try:
            ans = resolver.resolve(chain[-1], 'CNAME')
            target = ans[0].target.to_text().rstrip('.').lower()
            if target in seen: break
            seen.add(target)
            chain.append(target)
        except Exception:
            break
    return chain


def _identify_provider(hostname):
    for suffix, (name, kind) in PROVIDERS.items():
        if hostname.endswith(suffix):
            return name, kind
    return None, 'unknown'


def check_email_records(domain):
    """Returns True if mail appears M365-backed (or unknown), False if foreign."""
    info('DNS', domain, '', 'SPF / DMARC / MX')
    try:
        import dns.resolver
    except ImportError:
        bad('DNS', domain, '', 'dnspython not installed (pip install dnspython)')
        return True

    resolver = dns.resolver.Resolver()
    mx_hosts, spf_hard = [], False
    dmarc_policy = None
    lookups = {"MX": (domain, "MX"), "SPF": (domain, "TXT"), "DMARC": (f"_dmarc.{domain}", "TXT")}
    for label, (name, rtype) in lookups.items():
        try:
            for r in dns.resolver.resolve(name, rtype):
                txt = r.to_text()
                if label == "SPF" and "v=spf1" not in txt: continue
                good('DNS', domain, '', f'{label}: {txt}')
                if label == "MX":
                    mx_hosts.append(txt.split()[-1].rstrip('.').lower() if ' ' in txt else txt.lower())
                if label == "SPF" and "-all" in txt:
                    spf_hard = True
                if label == "SPF" and "~all" in txt:
                    warn('DNS', domain, '', 'soft-fail (~all) - spoofing partly viable')
                if label == "SPF" and "-all" not in txt and "~all" not in txt:
                    warn('DNS', domain, '', 'no strict -all - check enforcement')
                if label == "DMARC":
                    for p in ['reject', 'quarantine', 'none']:
                        if f'p={p}' in txt:
                            dmarc_policy = p
                            break
                if label == "DMARC" and "p=none" in txt:
                    warn('DNS', domain, '', 'p=none - no enforcement')
                if label == "DMARC" and "p=reject" in txt:
                    good('DNS', domain, '', 'p=reject - enforced')
        except Exception as e:
            bad('DNS', domain, '', f'{label}: not found ({e})')

    # Resolve CNAMEs and identify mail providers
    is_m365, is_foreign = False, False
    foreign_name, seen_providers = None, set()
    for mx in mx_hosts:
        chain = _chase_cname(mx, resolver)
        terminal = chain[-1]
        provider, kind = _identify_provider(terminal)
        if not provider:
            provider, kind = _identify_provider(mx)

        if provider and provider not in seen_providers:
            seen_providers.add(provider)
            if len(chain) > 1:
                info('DNS', domain, '', f'CNAME: {mx} -> {terminal} ({provider})')
            else:
                info('DNS', domain, '', f'MX provider: {mx} ({provider})')
            if kind == 'gateway':
                warn('DNS', domain, '', f'{provider} gateway - may front M365 or another provider')
                gw_chain = _chase_cname(terminal, resolver)
                if len(gw_chain) > 1:
                    _, gw_kind = _identify_provider(gw_chain[-1])
                    if gw_kind == 'm365':
                        is_m365 = True
                        info('DNS', domain, '', f'gateway resolves to M365: {gw_chain[-1]}')

        if kind == 'm365':
            is_m365 = True
        elif kind == 'foreign':
            is_foreign, foreign_name = True, provider

    # Probe for M365 behind gateways: <domain-dashed>.mail.protection.outlook.com
    m365_endpoint = None
    m365_direct = [h for h in mx_hosts if 'mail.protection.outlook.com' in h]
    if m365_direct:
        m365_endpoint = m365_direct[0]
    elif not is_m365:
        m365_probe = domain.replace('.', '-') + '.mail.protection.outlook.com'
        try:
            resolver.resolve(m365_probe, 'A')
            is_m365 = True
            m365_endpoint = m365_probe
            good('DNS', domain, '', f'M365 confirmed: {m365_probe} resolves')
        except Exception:
            pass

    if is_foreign and not is_m365:
        fail('DNS', domain, '', f'{foreign_name} detected - not M365. Teams enum will not work.')
        return False

    # M365 Direct Send check
    if m365_endpoint:
        if m365_direct:
            warn('DNS', domain, '', f'M365 Direct Send - MX points directly to {m365_endpoint}')
        else:
            warn('DNS', domain, '', f'M365 Direct Send - gateway fronts {m365_endpoint}')
        warn('DNS', domain, '', 'endpoint accepts unauthenticated SMTP on port 25')
        if dmarc_policy == 'reject' and spf_hard:
            info('DNS', domain, '', 'SPF -all + DMARC reject - spoofed mail likely dropped, but test to confirm')
        elif dmarc_policy == 'quarantine' and spf_hard:
            warn('DNS', domain, '', 'SPF -all + DMARC quarantine - spoofed mail may land in junk')
        elif dmarc_policy == 'none' or not spf_hard:
            warn('DNS', domain, '', 'weak SPF/DMARC - spoofed mail likely lands in inbox')
        else:
            info('DNS', domain, '', 'check SPF/DMARC above to gauge spoofing viability')
        info('DNS', domain, '', f'test: swaks --to victim@{domain} --from ceo@{domain} --server {m365_endpoint}:25')
        info('DNS', domain, '', 'SMTP 250 != inbox delivery - check junk/quarantine')

    return True


def _resolve_emails(spec, domain=None):
    if os.path.isfile(spec):
        with open(spec) as fh:
            lines = [l.strip() for l in fh if l.strip() and not l.startswith('#')]
    else:
        lines = [s.strip() for s in spec.split(',') if s.strip()]
    out = []
    for e in lines:
        if '@' in e:   out.append(e)
        elif domain:   out.append(f"{e}@{domain}")
        else:          warn('TEAMS', e, '', f'skipping bare username - no -d set')
    return out


def teams_external_check(email, bearer=None, region="emea", exists_only=False):
    if not bearer:
        return None
    url = (f"https://teams.microsoft.com/api/mt/{region}/beta/users/"
           f"{email}/externalsearchv3?includeTFLUsers=true")
    headers = {
        "Authorization": bearer if bearer.lower().startswith("bearer") else f"Bearer {bearer}",
        "X-Ms-Client-Version": "1415/1.0.0.2023032504",
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json",
    }
    for attempt in range(3):
        try:
            r = requests.get(url, headers=headers, timeout=15)
            if r.status_code == 200:
                body = r.json() if r.text.strip() else []
                if body:
                    rec = body[0] if isinstance(body, list) else body
                    tid = rec.get('tenantId', '?')
                    upn = rec.get('userPrincipalName', '?')
                    coex = rec.get('featureSettings', {}).get('coExistenceMode', '?')
                    good('TEAMS', email, '', f'OPEN  tenant={tid}  upn={upn}  coex={coex}')
                    return email
                elif not exists_only:
                    bad('TEAMS', email, '', 'not found or no Teams license')
                return None
            elif r.status_code == 403:
                warn('TEAMS', email, '', '403 - exists but BLOCKS external chat')
                return email
            elif r.status_code == 401:
                fail('TEAMS', email, '', '401 - bearer expired or invalid')
                return None
            elif not exists_only:
                bad('TEAMS', email, '', f'HTTP {r.status_code}: {r.text[:80]}')
            return None
        except (requests.ConnectionError, requests.Timeout, requests.ReadTimeout):
            if attempt < 2:
                time.sleep(2)
                continue
            fail('TEAMS', email, '', 'connection error / timed out (after 3 attempts)')
        except Exception as e:
            fail('TEAMS', email, '', str(e)[:80])
            return None
    return None


CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'amusement.json')

def _load_config():
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
        info('CONFIG', '', '', f'loaded {CONFIG_FILE}')
        return cfg
    except FileNotFoundError:
        return {}
    except Exception as e:
        warn('CONFIG', '', '', f'error reading config: {e}')
        return {}


def main():
    _show_banner()

    cfg = _load_config()

    ap = argparse.ArgumentParser(
        description="M365 Teams user enumeration + SMTP recon (authorized use only)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host", nargs="?", help="Target host/IP for SMTP checks")
    ap.add_argument("-p", "--ports",
                    help="Comma-separated SMTP ports (default 25,465,587)")
    ap.add_argument("-U", "--users", help="File of usernames for VRFY enum")
    ap.add_argument("-e", "--email",
                    help="Target email(s) for Teams check: address, comma list, or file")
    ap.add_argument("-d", "--domain",
                    help="Domain: appended to bare usernames, used for DNS lookups")
    ap.add_argument("--teams-token",
                    help="Teams bearer token (commercial M365 tenant only)")
    ap.add_argument("--refresh-token",
                    help="Azure AD refresh token (see docstring for extraction)")
    ap.add_argument("--client-id",
                    help="OAuth client ID for --refresh-token (from MSAL key)")
    ap.add_argument("--region",
                    help="Teams API region: emea, amer, apac (default emea)")
    ap.add_argument("--teams-output",
                    help="Write valid emails to this file")
    ap.add_argument("--threads", type=int, default=None,
                    help="Concurrent threads for Teams checks (default 5)")
    ap.add_argument("--exists-only", action="store_true",
                    help="Only show users that exist (suppress misses)")
    ap.add_argument("--disable-smtp-checks", action="store_true",
                    help="Skip SMTP; run Teams enum + DNS only")
    args = ap.parse_args()

    # CLI overrides config; config overrides defaults
    def opt(name, default=None):
        cli = getattr(args, name, None)
        return cli if cli is not None else cfg.get(name, default)

    args.domain        = opt('domain')
    args.teams_token   = opt('teams_token')
    args.refresh_token = opt('refresh_token')
    args.client_id     = opt('client_id')
    args.region        = opt('region', 'emea')
    args.threads       = opt('threads', 5)
    args.ports         = opt('ports', '25,465,587')
    args.teams_output  = opt('teams_output')

    # --- SMTP ---
    if args.host and not args.disable_smtp_checks:
        ports = [int(x) for x in args.ports.split(",")]
        users = []
        if args.users:
            try:
                with open(args.users) as fh:
                    users = [l.strip() for l in fh if l.strip()]
            except OSError as e:
                warn('SMTP', args.host, '', f'could not read users file: {e}')
        users = users or ["root", "admin", "nonexistent_xyz12345"]

        for port in ports:
            print()
            check_banner_and_ehlo(args.host, port)
            check_user_enum(args.host, port, users[:15])
            check_open_relay(args.host, port)
            check_tls(args.host, port)
            check_ntlm_info(args.host, port)
            check_vulns(args.host, port)

    # --- DNS ---
    m365_ok = True
    if args.domain:
        print()
        m365_ok = check_email_records(args.domain)

    # --- Teams ---
    if args.email and not m365_ok:
        fail('TEAMS', '', '', 'skipping Teams enum - domain is not M365-backed')
    elif args.email:
        emails = _resolve_emails(args.email, args.domain)
        if not emails:
            fail('TEAMS', '', '', 'no emails resolved from --email')
            return

        holder = None
        if args.refresh_token:
            holder = TokenHolder(refresh_token=args.refresh_token, client_id=args.client_id)
            holder.start()
        get_bearer = (lambda: holder.bearer) if holder else (lambda: args.teams_token)

        if not get_bearer():
            fail('TEAMS', '', '', 'no bearer available. Use --teams-token or --refresh-token.')
            return

        print()
        info('TEAMS', '', '', f'enumerating {len(emails)} target(s) / {args.threads} threads / region={args.region}')
        valid = []
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futs = {pool.submit(teams_external_check, e, get_bearer(), args.region, args.exists_only): e for e in emails}
            for fut in as_completed(futs):
                result = fut.result()
                if result:
                    valid.append(result)

        if holder:
            holder.stop()

        # Summary
        print()
        info('TEAMS', '', '', f'scan complete: {G}{len(valid)}{RST} {C}valid / {len(emails)} tested')
        if valid:
            for v in valid:
                good('TEAMS', v, '', '')
        if args.teams_output and valid:
            with open(args.teams_output, "w") as f:
                f.write("\n".join(valid) + "\n")
            good('TEAMS', '', '', f'{len(valid)} email(s) written to {args.teams_output}')


if __name__ == "__main__":
    main()
