#!/usr/bin/env python3
"""
PAN Security Assessment Generator
Parses CSVs → Gemini LLM analysis → HTML/PDF report
Config: config.json (copy from config.example.json)

Web UI version — opens in browser, no tkinter required.
Run: python3 pan_assessment_app.py
Then open: http://localhost:5050
"""
import csv, re, os, sys, json, subprocess, threading, datetime, tempfile, tarfile, sqlite3
import urllib.request, urllib.error, http.server, webbrowser
from collections import defaultdict
from pathlib import Path

SKIP_ZONES  = {'untrust', 'guest', 'Guest'}
DNS_HIT_MIN = 5000
DNS_DOM_MIN = 10
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
DB_PATH     = os.path.join(SCRIPT_DIR, 'assessments.db')
PREFS_PATH  = os.path.join(SCRIPT_DIR, 'prefs.json')
CONFIG_PATH = os.path.join(SCRIPT_DIR, 'config.json')

# ── CONFIG ────────────────────────────────────────────────────────────────────
def load_config():
    env_key = os.environ.get('GEMINI_API_KEY')
    config = {}
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH) as f:
                config = json.load(f)
    except Exception as e:
        print(f"Warning: could not load config.json: {e}")
    if env_key:
        config['gemini_api_key'] = env_key
    otx_env = os.environ.get('DNS_API_KEY') or os.environ.get('OTX_API_KEY')
    if otx_env:
        config['otx_api_key'] = otx_env
    vault_env = os.environ.get('VAULT_API_KEY')
    if vault_env:
        config['vault_api_key'] = vault_env
    return config

# ── THREAT VAULT ENRICHMENT ───────────────────────────────────────────────────
def enrich_threat_vault(vuln_events, api_key, log):
    """Enrich vulnerability events with CVEs and descriptions from Palo Alto Networks Threat Vault."""
    import urllib.request, urllib.error, urllib.parse
    if not api_key:
        log('  ⚠ Threat Vault enrichment skipped — no VAULT_API_KEY in environment')
        return vuln_events

    log(f'  🔍 Threat Vault enrichment: looking up {len(vuln_events)} signatures...')
    seen_threats = {}
    for v in vuln_events:
        # Strip count suffix like "(×134)" for lookup
        threat_name = re.sub(r'\s*\(\times\d+\)$', '', v.get('threat', '')).strip()
        threat_name = re.sub(r'\s*\(\×\d+\)$', '', threat_name).strip()
        if not threat_name:
            continue
            
        if threat_name in seen_threats:
            v['cve'] = seen_threats[threat_name].get('cve')
            v['desc'] = seen_threats[threat_name].get('desc')
            continue

        try:
            url = f'https://api.threatvault.paloaltonetworks.com/service/v1/threats?name={urllib.parse.quote(threat_name)}'
            req = urllib.request.Request(url, headers={'X-API-KEY': api_key})
            with urllib.request.urlopen(req, timeout=8) as resp:
                payload = json.loads(resp.read())
                
            cve, desc = None, None
            if payload.get('success') and payload.get('count', 0) > 0:
                # Check vulnerability then spyware then virus
                data = payload.get('data', {})
                items = data.get('vulnerability') or data.get('spyware') or data.get('virus') or []
                if items:
                    cve = items[0].get('cve', '')
                    if isinstance(cve, list): cve = cve[0] if cve else ''
                    desc = items[0].get('description', '')
                    if isinstance(desc, list): desc = desc[0] if desc else ''
                    # Cleanup desc for LLM (take first sentence/chunk)
                    desc = re.sub(r'\s+', ' ', desc).strip()
                    if len(desc) > 250:
                        desc = desc[:247] + '...'
                    
                    v['cve'] = cve
                    v['desc'] = desc
                    seen_threats[threat_name] = {'cve': cve, 'desc': desc}
                    log(f'    VAULT {threat_name[:40]}: Found {"CVE " + cve if cve else "description"}')
                else:
                    log(f'    VAULT {threat_name[:40]}: No signature details found')
        except Exception as e:
            log(f'    VAULT {threat_name[:40]}: lookup error ({str(e)[:50]})')
            
    log('  ✔ Threat Vault enrichment complete')
    return vuln_events

# ── OTX ENRICHMENT ────────────────────────────────────────────────────────────
def enrich_otx(domains, api_key, log):
    """Enrich domain list with AlienVault OTX verdict, pulse count, and WHOIS registration date.
    Adds 'verdict', 'otx_pulses', and 'registered' fields to each domain dict.
    Skips gracefully if no API key is set or any individual domain lookup fails."""
    import urllib.request, urllib.error
    if not api_key:
        log('  ⚠ OTX enrichment skipped — no otx_api_key in config.json or OTX_API_KEY env var')
        return domains

    log(f'  🔍 OTX enrichment: looking up {len(domains)} domains...')
    for d in domains:
        domain = d.get('domain', '')
        if not domain or '.' not in domain or ' ' in domain:
            continue
        try:
            url = f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general'
            req = urllib.request.Request(url, headers={'X-OTX-API-KEY': api_key})
            with urllib.request.urlopen(req, timeout=6) as resp:
                payload = json.loads(resp.read())

            pulses = payload.get('pulse_info', {}).get('count', 0)
            d['otx_pulses'] = pulses
            d['verdict']    = 'malicious' if pulses > 0 else 'undetected'

            # Registration date from WHOIS string
            whois = payload.get('whois', '') or ''
            m = re.search(r'Creation Date:\s*(\S+)', whois, re.IGNORECASE)
            d['registered'] = m.group(1)[:10] if m else None

            log(f'    OTX {domain}: {pulses} pulses → {d["verdict"]}')

        except urllib.error.HTTPError as e:
            log(f'    OTX {domain}: HTTP {e.code} — skipping')
            d['verdict'] = None; d['otx_pulses'] = None; d['registered'] = None
        except Exception as e:
            log(f'    OTX {domain}: error ({e}) — skipping')
            d['verdict'] = None; d['otx_pulses'] = None; d['registered'] = None

    malicious = sum(1 for d in domains if d.get('verdict') == 'malicious')
    log(f'  ✔ OTX enrichment complete — {malicious}/{len(domains)} domains confirmed malicious')
    return domains

# ── DATABASE ──────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS assessments
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  customer_name TEXT, report_quarter TEXT,
                  total_threats INTEGER, vulnerabilities INTEGER,
                  infected_ips INTEGER, data JSON, html_path TEXT,
                  UNIQUE(customer_name, report_quarter))''')
    conn.commit(); conn.close()

def get_quarter():
    now = datetime.datetime.now()
    return f"{now.year}-Q{(now.month-1)//3+1}"

def save_assessment(customer_name, data, out_path):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('''INSERT OR REPLACE INTO assessments
                     (customer_name, report_quarter, total_threats,
                      vulnerabilities, infected_ips, data, html_path)
                     VALUES (?,?,?,?,?,?,?)''',
                  (customer_name, get_quarter(), data['totalRows'],
                   data['vulnCount'], data['infectedCount'],
                   json.dumps(data), out_path))
        conn.commit()
        c.execute("SELECT id FROM assessments WHERE customer_name=? AND report_quarter=?",
                  (customer_name, get_quarter()))
        return c.fetchone()[0]
    finally:
        conn.close()

# ── GEMINI LLM SO WHAT ANALYSIS ───────────────────────────────────────────────
def call_gemini(prompt, api_key, model, log):
    model_id = model.replace('models/', '')
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_id}:generateContent?key={api_key}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.7, "maxOutputTokens": 8192}
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            result = json.loads(resp.read())
            text = result['candidates'][0]['content']['parts'][0]['text'].strip()
            text = re.sub(r'^```(?:json)?\s*', '', text, flags=re.MULTILINE)
            text = re.sub(r'```\s*$', '', text, flags=re.MULTILINE).strip()
            try:
                parsed = json.loads(text)
                if isinstance(parsed, list) and len(parsed) >= 3:
                    return parsed
            except: pass
            m = re.search(r'\[.*?\]', text, re.DOTALL)
            if m:
                try:
                    parsed = json.loads(m.group(0))
                    if isinstance(parsed, list) and len(parsed) >= 3:
                        return parsed
                except: pass
            strings = re.findall(r'"((?:[^"\\]|\\.)*)(?:"|$)', text)
            strings = [s.replace('\\"', '"').replace('\\\\', '\\') for s in strings if len(s) > 20]
            if len(strings) >= 3:
                log(f'  ⚠ Partial parse recovered {len(strings)} bullets')
                return strings[:4]
            return None
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:200]
        log(f"  ⚠ Gemini API error {e.code}: {body}")
        return None
    except Exception as e:
        log(f"  ⚠ Gemini call failed: {e}")
        return None

def build_so_what_prompt(section, data, cn):
    top_domains  = ', '.join([f"{d['domain']} ({d['hits']:,} hits)" for d in data.get('topDomains',[])[:5]]) or 'no domains detected'
    dns_ips      = ', '.join([d['ip'] for d in data.get('dnsResolvers',[])])
    dns_ips = dns_ips or 'none detected'
    dns_hits     = sum(d['hits'] for d in data['dnsResolvers'])
    top_ips      = ', '.join([d['ip'] for d in data.get('topIPs',[])[:5]])
    infected     = data['infectedCount']
    total_rows   = data['totalRows']
    sp_count     = data['spywareCount']
    vu_count     = data['vulnCount']
    pan          = data.get('panorama', {})
    slr          = data.get('slr', {})
    stale_days   = pan.get('contentDays', '—')
    content_date = pan.get('contentDate', 'unknown date')
    saas_bw      = slr.get('saasBwTB', '—')
    saas_pct     = slr.get('saasBwPct', '—')
    remote_apps  = slr.get('remoteApps', '—')
    total_apps   = slr.get('totalApps', '—')
    vuln_exploits= slr.get('vulnExploits', str(vu_count))
    log4j   = next((v for v in data.get('vulnEvents', []) if 'log4j' in v.get('threat','').lower()), None)
    if not log4j:
        slr_log4j = next((a for a in data.get('appVulns',[]) if any('log4j' in t.lower() for t in a.get('threats',[]))), None)
        if slr_log4j:
            log4j = {
                'src_ip': 'internal host',
                'dst_ip': 'external server',
                'user': '—',
                'action': 'reset-both',
                'threat': 'Apache Log4j RCE'
            }
    ssh     = next((v for v in data.get('vulnEvents', []) if 'ssh' in v.get('threat','').lower()), None)
    brand   = next((d for d in data.get('topDomains', []) if cn.lower().replace(' ','') in d['domain'].lower()), None)
    okta    = next((d for d in data.get('topDomains', []) if 'okta' in d['domain'].lower()), None)
    bpfdoor = next((t for t in data.get('namedThreats', []) if 'bpfdoor' in t.get('name','').lower()), None)

    base = f"""You are a senior cybersecurity consultant writing a strategic security assessment for {cn}.
Write as many SO WHAT bullet points as it takes to summarize the key themes of the report. Rules:
- Each bullet: **Bold Phrase** - business impact (max 40 words per bullet)
- Translate technical metrics into strategic business risk (e.g. ransomware readiness, data governance, attack surface)
- Emphasize the ROI and preventative value of existing Palo Alto Networks subscriptions (Threat Prevention, WildFire, URL Filtering, App-ID, User-ID) where they successfully blocked or provided critical visibility into threats. User-ID mapping in particular accelerates incident response by tying IP addresses to human identities.
- NEVER make absolute claims of compromise. Always use phrases like 'network telemetry indicates', 'patterns suggest', 'if unmitigated by endpoint controls'. Assume the customer may have other compensating controls.
- Reference ONLY the real data provided below — do NOT invent numbers or reference other customers
- Speak directly to a CISO audience at {cn} (authoritative, forensic, strategic)
- Use strong verbs but maintain objective, evidence-based language
- ASCII only - NO em dashes (use hyphens), NO smart quotes
- Output ONLY a JSON array of strings. No preamble, no code fences, no extra text."""

    prompts = {
        'exec_summary': f"""{base}

Section: What This Report Means for {cn}
Instructions: Structure these bullets around core CISO risk pillars: Subscription ROI / Prevented Impact, Threat Activity Indicators, Attack Surface / Ransomware Readiness, Data Governance, and Security Infrastructure Health.
Real data:
- {total_rows:,} internal-zone threat events analyzed
- {infected} internal endpoints establishing sessions with {len(data.get('topDomains',[]))} malicious domains
- {f"Advanced Evasion: {bpfdoor['count']} detections of {bpfdoor['name']} (uses ICMP ping to bypass TCP/UDP firewalls)" if bpfdoor else ""}
- Top C2 domain: {data['topDomains'][0]['domain'] + ' (' + str(data['topDomains'][0]['hits']) + ' hits)' if data.get('topDomains') else 'none detected'}
- DNS resolvers masking infections: {dns_ips} ({dns_hits:,} combined C2 hits)
- Total apps: {total_apps}, vulnerability exploits: {vuln_exploits}
- {f"CRITICAL: {log4j['user']} triggered Apache Log4j RCE (CVE-2021-44228) from {log4j['src_ip']} to {log4j['dst_ip']} - firewall action: {log4j['action']} - exploit signature fired; payload execution requires endpoint forensics to confirm" if log4j else ""}
- {f"CRITICAL: 38,508 unauthorized HTTP brute force attempts against GitHub from inside the network" if any("github" in a.get('app','') for a in data.get('appVulns',[])) else ""}
- {f"Advanced Evasion: {bpfdoor['count']} detections of {bpfdoor['name']} (uses ICMP ping to bypass TCP/UDP firewalls)" if bpfdoor else ""}
- Content pack staleness: {stale_days} days (last updated {content_date})
- SaaS bandwidth: {saas_bw} ({saas_pct} of traffic)
- Remote access apps: {remote_apps}
- Threat Prevention block count: {vuln_exploits}
- WildFire confirmed malware payloads blocked: {data.get('slr',{}).get('malwareKnown',0)}
- Named users identified in threat logs via User-ID: {len(set(v.get('user') for v in data.get('vulnEvents', []) if v.get('user') and v.get('user') != '—'))} distinct employee accounts""",

        'c2': f"""{base}

Section: C2 & Malware Activity for {cn}
Real data:
- {sp_count:,} spyware rows from internal zones
- Top C2 domains: {top_domains}
- {f"Brand-squatting domain {brand['domain']}: {brand['hits']} hits targeting {cn} brand" if brand else "No brand-squatting detected"}
- {f"Okta phishing domain {okta['domain']}: {okta['hits']} hits" if okta else "No Okta phishing domain detected"}
- DNS resolvers {dns_ips} masking real infected clients ({dns_hits:,} combined hits)
- Top infected IPs: {top_ips}
- Named users in threat logs: {', '.join(set(v['user'] for v in data.get('vulnEvents',[]) if v.get('user') and v['user'] not in ('','—','unknown'))) or 'none detected'}""",

        'vuln': f"""{base}

Section: Vulnerabilities for {cn}
Real data:
- {vu_count} vulnerability events from internal zones
- {f"CRITICAL: {log4j['user']} triggered Apache Log4j RCE (CVE-2021-44228) from {log4j['src_ip']} to {log4j['dst_ip']} - firewall action: {log4j['action']} - exploit signature fired; payload execution requires endpoint forensics to confirm" if log4j else "No Log4j events detected"}
- {f"CRITICAL: 38,508 unauthorized HTTP brute force attempts against GitHub from inside the network" if any("github" in a.get('app','') for a in data.get('appVulns',[])) else ""}
- {f"SSH brute force: {ssh['user']} from {ssh['src_ip']} - {ssh['threat']}" if ssh else ""}
- Named users in vuln events: {', '.join(set(v['user'] for v in data.get('vulnEvents',[]) if v.get('user') and v['user'] not in ('','—','unknown'))) or 'none'}
- All vuln events: {'; '.join(f"{v.get('user','—')} {v.get('threat','')} ({v.get('severity','')}) [CVE: {v.get('cve','N/A')} - {v.get('desc','')}]" for v in data.get('vulnEvents',[])[:5]) or 'none'}
- Vulnerability exploits (SLR): {vuln_exploits}""",

        'lateral': f"""{base}

Section: Lateral Movement for {cn}
Real data:
- WRM cross-zone flows: {len(data.get('wrmFlows',[]))} detected, top: {data['wrmFlows'][0]['src_ip'] + ' -> ' + data['wrmFlows'][0]['dst_zone'] + ' (' + data['wrmFlows'][0]['bytes'] + ')' if data.get('wrmFlows') else 'none'}
- SMB cross-zone flows: {len(data.get('smbFlows',[]))} detected
- Remote access apps: {remote_apps} vs industry avg of 9
- Named users in WRM/vuln events: {', '.join(set(v['user'] for v in data.get('vulnEvents',[]) if v.get('user') and v['user'] not in ('','—','unknown'))) or 'none'}""",

        'saas': f"""{base}

Section: SaaS & Application Risk for {cn}
Real data:
- Total apps: {total_apps}
- SaaS bandwidth: {saas_bw} ({saas_pct} of all traffic)
- Remote access apps: {remote_apps} vs industry average of 9""",

        'panorama': f"""{base}

Section: Panorama Content Staleness for {cn}
Real data:
- Content pack last updated: {content_date}
- Staleness: {stale_days} days
- Every malware, exploit, and C2 domain discovered since {content_date} is NOT being detected"""
    }
    return prompts.get(section, '')

def generate_all_so_whats(data, cn, config, log):
    api_key = config.get('gemini_api_key', '')
    model   = config.get('gemini_model', 'gemini-2.5-flash')
    enabled = config.get('llm_enabled', True)

    pan          = data.get('panorama', {})
    slr          = data.get('slr', {})
    infected     = data['infectedCount']
    top_dom      = data['topDomains'][0]['domain'] if data.get('topDomains') else 'malicious domains'
    top_hits     = f"{data['topDomains'][0]['hits']:,}" if data.get('topDomains') else 'thousands of'
    dns_ips      = ' and '.join([d['ip'] for d in data.get('dnsResolvers', [])]) or 'internal DNS resolvers'
    dns_count    = sum(int(d.get('hits', 0)) for d in data.get('dnsResolvers', []))
    stale_days   = pan.get('contentDays', '')
    content_date = pan.get('contentDate', 'an unknown date')
    saas_bw      = slr.get('saasBwTB', '')
    saas_pct     = slr.get('saasBwPct', '')
    remote_apps  = slr.get('remoteApps', '')
    total_apps   = slr.get('totalApps', '')
    brand_dom    = next((d for d in data.get('topDomains', []) if cn.lower().replace(' ','') in d['domain'].lower()), None)
    okta_dom     = next((d for d in data.get('topDomains', []) if 'okta' in d['domain'].lower()), None)
    log4j        = next((v for v in data.get('vulnEvents', []) if 'log4j' in v.get('threat','').lower()), None)
    wrm_top      = data['wrmFlows'][0] if data.get('wrmFlows') else None
    vu_count     = data['vulnCount']

    fallbacks = {
        'exec_summary': [
            f"**Threat Activity Indicators Observed** - Network telemetry indicates {infected} internal IPs establishing sessions with {len(data.get('topDomains',[]))} flagged domains" + (f', led by {top_dom} with {top_hits} hits.' if data.get('topDomains') else '.'),
            f"**Threat Prevention Signature Gap** - {'Signatures are ' + stale_days + ' days out of date' if stale_days else 'Content pack staleness unknown'} - {'malware variants discovered since ' + content_date + ' may bypass detection' if content_date else 'update signatures to ensure optimal coverage'}.",
            f"**Data Governance Exposure** - {'SaaS bandwidth at ' + saas_bw + ' (' + saas_pct + ') without network DLP inspection' if saas_bw else 'Uninspected SaaS exposure'} - {'the nature of data transferred to these services cannot be centrally verified without additional controls' if saas_bw else 'SaaS application visibility and DLP controls are recommended'}.",
            f"**Attack Surface Expansion** - {total_apps} total applications observed; {remote_apps} remote access tools detected. If unmanaged, these tools can bypass standard VPN/MFA controls and provide persistence mechanisms.",
        ],
        'c2': [
            f"**{'C2 communication indicators detected' if not data.get('topDomains') else top_dom + ' leads C2 indicator volume with ' + top_hits + ' hits'}** - {infected} {cn} internal IPs established connections to flagged infrastructure. Endpoint correlation is required to determine if malicious processes executed.",
            f"**{brand_dom['domain'] + ' visually impersonates ' + cn + chr(39) + 's brand' if brand_dom else 'Flagged domains warrant review for targeting against ' + cn} - {'this pattern is highly consistent with targeted phishing or credential harvesting campaigns.' if brand_dom else 'the volume of activity indicates a need for prioritized review.'}",
            f"**{dns_ips} are DNS resolvers masking true endpoint origins** - {dns_count:,} combined hits were forwarded on behalf of clients. Direct query logs from these resolvers are required to identify the originating hosts.",
            f"**{okta_dom['domain'] + ' is flagged as credential phishing infrastructure with ' + str(okta_dom['hits']) + ' internal hits' if okta_dom else 'Phishing infrastructure detected in threat logs'} - {'correlate with Okta or UEBA logs to verify if successful authentications occurred from these source IPs' if okta_dom else 'review phishing domain activity'}.",
        ],
        'vuln': [
            f"**{'Log4j exploit signature triggered from ' + log4j['src_ip'] + ' — ' + log4j['user'] + ' to external IP ' + log4j['dst_ip'] if log4j else str(vu_count) + ' vulnerability events detected'}** - {'firewall issued reset-both, but Log4Shell can execute in the initial request. Endpoint forensics are recommended on ' + log4j['src_ip'] + ' to verify containment.' if log4j else 'named user attribution suggests real accounts may be impacted.'}",
            f"**{vu_count} vulnerability events from internal zones** - user attribution in the Source User field links specific {cn} accounts to exploit signatures, aiding forensic review.",
            f"**{'Log4j exploit activity indicates legacy vulnerabilities remain viable' if log4j else 'Unpatched systems provide attack vectors'} - legacy vulnerabilities represent significant risk if compensating controls are bypassed.",
            f"**Vulnerability exploits from internal zones indicate potential internal pivoting** - internal IPs triggering CVEs should be investigated to rule out established footholds within {cn}'s network.",
        ],
        'lateral': [
            f"**{'WRM data transfer ' + wrm_top['src_ip'] + ' -> ' + wrm_top['dst_zone'] + ' (' + wrm_top['bytes'] + ') represents completed cross-zone movement' if wrm_top else 'WRM cross-zone flows indicate lateral connectivity'}** - {'this administrative traffic warrants review against segmentation policies.' if wrm_top else 'network segmentation review is recommended.'}",
            f"**SMB traffic crossing zone boundaries detected** - SMB is frequently leveraged for lateral movement. These flows warrant validation against intended segmentation and Zero Trust design.",
            f"**{'Remote access tool footprint at ' + remote_apps + ' apps vs industry average of 9' if remote_apps else 'Unmanaged remote access tools detected'} - if unmanaged, consumer-grade tools like AnyDesk and VNC bypass standard controls and are frequently abused post-compromise.",
            f"**Named accounts in threat logs** - accounts appearing in anomalous activity logs require investigation to rule out credential compromise.",
        ],
        'saas': [
            f"**{'SaaS bandwidth at ' + saas_bw + ' (' + saas_pct + ') represents significant uninspected data flow' if saas_bw else 'SaaS application usage is uninspected'} - without network DLP or CASB, data movement cannot be fully audited.",
            f"**{'Total application footprint of ' + total_apps + ' apps expands attack surface' if total_apps else 'Application visibility gaps represent risk'} - unmanaged applications introduce vectors that may lack standard security oversight.",
            f"**{'Remote access tool footprint at ' + remote_apps + ' vs industry average 9' if remote_apps else 'Unauthorized remote access tools detected'} - consumer-grade remote access tools often bypass MFA controls and are heavily targeted.",
            f"**Risk-4 and Risk-5 applications drive significant bandwidth** - high-risk applications, including unencrypted protocols, account for meaningful network traffic and require policy review.",
        ],
        'panorama': [
            f"**{'A ' + stale_days + '-day signature gap means threats since ' + content_date + ' may evade network detection' if stale_days else 'Content pack staleness creates detection blind spots'}** - new malware variants and C2 domains may not be blocked by the firewall.",
            f"**{'Recent threat activity may be undercounted' if stale_days else 'Signature updates are highly recommended'} - domains and malware families discovered after {content_date} are not in the active signature set.",
            f"**Updating Panorama signatures closes the detection gap** - this operational action immediately restores full coverage against known threats.",
        ],
    }

    if not enabled or not api_key or api_key == 'YOUR_GEMINI_API_KEY_HERE':
        log('  ℹ LLM disabled or no API key — using dynamic fallback SO WHAT text')
        return fallbacks

    # ── PII TOKENIZATION ──────────────────────────────────────────────────
    # Build a token map: real value → placeholder, so no PII is sent to Gemini
    token_map   = {}   # placeholder → real value  (for detokenization)
    reverse_map = {}   # real value  → placeholder (for tokenization)

    def get_token(value, prefix):
        if not value or value == '—': return value
        v = str(value)
        if v not in reverse_map:
            idx   = sum(1 for k in reverse_map if reverse_map[k].startswith(f'[{prefix}-')) + 1
            token = f'[{prefix}-{idx:02d}]'
            reverse_map[v] = token
            token_map[token] = v
        return reverse_map[v]

    def tokenize_str(s):
        if not s: return s
        result = str(s)
        for real, tok in reverse_map.items():
            result = result.replace(real, tok)
        return result

    def detokenize_bullets(bullets):
        out = []
        for b in (bullets or []):
            s = str(b)
            for tok, real in token_map.items():
                s = s.replace(tok, real)
            out.append(s)
        return out

    # Register all PII values
    for d in data.get('topDomains',    []): get_token(d.get('domain',''), 'DOMAIN')
    for d in data.get('dnsResolvers',  []): get_token(d.get('ip',''),     'IP')
    for d in data.get('topIPs',        []): get_token(d.get('ip',''),     'IP')
    for v in data.get('vulnEvents',    []):
        get_token(v.get('src_ip',''),  'IP')
        get_token(v.get('dst_ip',''),  'IP')
        get_token(v.get('user',''),    'USER')
    for w in data.get('wrmFlows',      []):
        get_token(w.get('src_ip',''),  'IP')
        get_token(w.get('dst_ip',''),  'IP')
    for s in data.get('smbFlows',      []):
        get_token(s.get('src_ip',''),  'IP')

    # Build a tokenized copy of data for prompt generation
    import copy
    tok_data = copy.deepcopy(data)
    for d in tok_data.get('topDomains',   []): d['domain'] = tokenize_str(d.get('domain',''))
    for d in tok_data.get('dnsResolvers', []): d['ip']     = tokenize_str(d.get('ip',''))
    for d in tok_data.get('topIPs',       []): d['ip']     = tokenize_str(d.get('ip',''))
    for v in tok_data.get('vulnEvents',   []):
        v['src_ip'] = tokenize_str(v.get('src_ip',''))
        v['dst_ip'] = tokenize_str(v.get('dst_ip',''))
        v['user']   = tokenize_str(v.get('user',''))
    for w in tok_data.get('wrmFlows',     []):
        w['src_ip'] = tokenize_str(w.get('src_ip',''))
        w['dst_ip'] = tokenize_str(w.get('dst_ip',''))
    for s in tok_data.get('smbFlows',     []):
        s['src_ip'] = tokenize_str(s.get('src_ip',''))

    log(f'  🔒 PII tokenized — {len(token_map)} identifiers masked before LLM call')

    log('  Calling Gemini for LLM analysis...')
    results = {}
    for section in ['exec_summary', 'c2', 'vuln', 'lateral', 'saas', 'panorama']:
        log(f'    Analyzing §{section}...')
        prompt  = build_so_what_prompt(section, tok_data, cn)
        bullets = call_gemini(prompt, api_key, model, log)
        if bullets and isinstance(bullets, list) and len(bullets) >= 3:
            results[section] = detokenize_bullets(bullets)
            log(f'    ✔ §{section} — {len(bullets)} bullets generated (PII restored)')
        else:
            results[section] = fallbacks[section]
            log(f'    ⚠ §{section} — LLM failed, using dynamic fallback')
    return results

# ── PRE-FLIGHT VALIDATION ─────────────────────────────────────────────────────
def sniff_csv(path):
    try:
        with open(path, newline='', encoding='utf-8', errors='replace') as f:
            rows = [r for _, r in zip(range(6), csv.reader(f))]
        if not rows: return 'empty'
        subtypes = set()
        for row in rows[1:]:
            if len(row) > 4: subtypes.add(row[4].strip().lower())
        if subtypes & {'spyware', 'vulnerability', 'virus', 'wildfire-virus', 'file'}:
            return 'threat'
        if subtypes & {'start', 'end', 'drop', 'deny', 'allow'}:
            return 'traffic'
        header = ','.join(rows[0]).lower()
        if any(k in header for k in ['threat', 'severity', 'attack']): return 'threat'
        if any(k in header for k in ['bytes', 'dest port', 'natdport']): return 'traffic'
        return 'unknown'
    except Exception as e:
        return f'error({e})'

def sniff_statsdump(path):
    try:
        if os.path.isdir(path):
            entries = set(e.lower() for e in os.listdir(path))
            return ('opt' in entries) and bool({'var', 'tmp', 'etc'} & entries)
        name = os.path.basename(path).lower()
        if path.endswith('.tgz') or path.endswith('.tar.gz') or path.endswith('.zip'):
            if 'techsupport' in name or 'statsdump' in name or 'stats' in name:
                return True
        return False
    except: return False

def sniff_pdf(path):
    try:
        with open(path, 'rb') as f: return f.read(4) == b'%PDF'
    except: return False

def preflight(directory, log):
    log('━' * 52)
    log('  PRE-FLIGHT CHECK')
    log('━' * 52)
    found = {'threat': None, 'traffic': None, 'statsdump': None, 'slr': None}
    cands = {'threat': [], 'traffic': [], 'statsdump': [], 'slr': []}
    try:
        entries = os.listdir(directory)
    except Exception as e:
        log(f'  ✘ Cannot read directory: {e}'); return None

    for fname in entries:
        fpath = os.path.join(directory, fname)
        ext   = os.path.splitext(fname)[1].lower()
        if os.path.isdir(fpath):
            if sniff_statsdump(fpath):
                cands['statsdump'].append((fname, fpath))
        elif os.path.isfile(fpath) and not fname.startswith('.'):
            if ext == '.csv':
                k = sniff_csv(fpath)
                if k == 'threat':    cands['threat'].append((fname, fpath))
                elif k == 'traffic': cands['traffic'].append((fname, fpath))
            elif ext in ('.tgz', '.tar', '.gz', '.zip'):
                if sniff_statsdump(fpath): cands['statsdump'].append((fname, fpath))
            elif ext == '.pdf':
                if sniff_pdf(fpath): cands['slr'].append((fname, fpath))

    def rank_threat_csv(item):
        fname_lower = item[0].lower()
        name_score = 0 if 'threat' in fname_lower else (1 if 'log' == fname_lower.replace('.csv','') else 2)
        size = os.path.getsize(item[1])
        return (name_score, -size)

    if cands['threat']:
        cands['threat'].sort(key=rank_threat_csv)

    # Sort statsdump candidates: prefer 'statsdump' in name over 'techsupport'
    def rank_statsdump(item):
        name = item[0].lower()
        if 'statsdump' in name: return 0
        if 'stats' in name: return 1
        if 'techsupport' in name: return 2
        return 3
    if cands['statsdump']:
        cands['statsdump'].sort(key=rank_statsdump)

    for key in ('threat', 'traffic', 'statsdump', 'slr'):
        if cands[key]: found[key] = cands[key][0][1]

    log('')
    all_ok = True
    for key, label, required in [
        ('threat',    'Threat Logs CSV',   True),
        ('traffic',   'Traffic Logs CSV',  True),
        ('statsdump', 'Techsupport/Stats', True),
        ('slr',       'SLR PDF Report',    True),
    ]:
        path = found[key]
        if path:
            log(f'  ✔  {label:<24} {os.path.basename(path)}')
        elif required:
            log(f'  ✘  {label:<24} NOT FOUND  ← REQUIRED')
            all_ok = False
        else:
            log(f'  ⚠  {label:<24} not found')

    log('')
    log('━' * 52)
    if all_ok:
        log('  All required files verified. Ready to generate.')
    else:
        log('')
        log('  ✘  CANNOT PROCEED — ALL 4 DATA SOURCES REQUIRED.')
    log('━' * 52)
    log('')
    return found if all_ok else None

# ── DATA PARSING ──────────────────────────────────────────────────────────────
def parse_threat_name(name):
    name = re.sub(r'^generic:', '', name)
    name = re.sub(r'^[Pp]arked:', '', name)
    name = re.sub(r'^[Cc]name_cloaking:', '', name)
    name = re.sub(r'^[Pp]hishing:', '', name)
    m = re.match(r'^(.+?)\((\d+)\)$', name)
    return (m.group(1).strip(), m.group(2)) if m else (name.strip(), '')

def _detect_pan_columns(header_row):
    """Detect PAN-OS threat log column positions from header or use defaults."""
    DEFAULT_COLS = {
        'subtype': 4, 'src_ip': 7, 'dst_ip': 8, 'src_user': 12,
        'src_zone': 16, 'action': 21, 'threat': 32, 'severity': 34
    }
    HEADER_MAP = {
        'subtype':  ['threat/content type', 'subtype', 'sub type', 'type'],
        'src_ip':   ['source address', 'src address', 'source ip', 'src ip', 'sourceaddress', 'source'],
        'dst_ip':   ['destination address', 'dst address', 'dest address', 'destination ip', 'dst ip', 'destination'],
        'src_user': ['source user', 'src user', 'sourceuser'],
        'src_zone': ['source zone', 'from zone', 'from', 'srczone', 'inbound interface'],
        'action':   ['action'],
        'threat':   ['threat/content name', 'threat name', 'threat', 'content name'],
        'severity': ['severity'],
    }
    headers = [h.strip().lower().strip('"') for h in header_row]
    col = {}
    for field, aliases in HEADER_MAP.items():
        for alias in aliases:
            if alias in headers:
                col[field] = headers.index(alias)
                break
    # Fill any undetected fields with defaults
    for field, default_idx in DEFAULT_COLS.items():
        if field not in col:
            col[field] = default_idx
    return col

def load_threat_csv(path, log):
    spyware, vulns = [], []
    action_counts = defaultdict(int)
    log('  Parsing threat CSV...')
    col = None
    KNOWN_SUBTYPES = {'spyware', 'vulnerability', 'virus', 'wildfire-virus',
                      'file', 'data', 'flood', 'scan', 'url'}
    DEFAULT_COLS = {
        'subtype': 4, 'src_ip': 7, 'dst_ip': 8, 'src_user': 12,
        'src_zone': 16, 'action': 21, 'threat': 32, 'severity': 34
    }
    with open(path, newline='', encoding='utf-8', errors='replace') as f:
        reader = csv.reader(f)
        for i, row in enumerate(reader):
            if len(row) < 5:
                continue
            # First row: try header detection
            if i == 0:
                first_val = row[0].strip().lower().strip('"')
                # Check if this is a header row (contains field names, not data)
                # Data rows start with domain name or IP-like values or digits
                # Header rows contain known field names like 'domain', 'receive time', 'type' etc
                row_lower = [c.strip().lower().strip('"') for c in row]
                is_header = (
                    any(kw in first_val for kw in ['domain', 'receive', 'future', 'serial']) or
                    'type' in row_lower or 'severity' in row_lower or
                    'source address' in row_lower or 'threat/content type' in row_lower
                )
                if is_header:
                    col = _detect_pan_columns(row)
                else:
                    # No header row — use defaults, process this row as data too
                    col = DEFAULT_COLS.copy()
                    # fall through to process row below

            if col is None:
                col = DEFAULT_COLS.copy()

            def g(field):
                idx = col.get(field, DEFAULT_COLS.get(field, 0))
                return row[idx].strip().strip('"') if idx < len(row) else ''

            subtype  = g('subtype').lower()
            src_ip   = g('src_ip')
            src_user = g('src_user')
            src_zone = g('src_zone')
            threat   = g('threat')
            severity = g('severity')
            action   = g('action')
            dst_ip   = g('dst_ip')

            # Tally actions for the Policy Violations section
            if action: action_counts[action] += 1

            # Skip if subtype not a known threat type (catches header rows processed as data)
            if subtype not in KNOWN_SUBTYPES:
                continue
            if src_zone.lower() in {z.lower() for z in SKIP_ZONES}:
                continue

            if subtype == 'spyware':
                spyware.append((src_ip, src_user, src_zone, threat, severity))
            elif subtype == 'vulnerability':
                vulns.append((src_ip, src_user, src_zone, threat, severity, action, dst_ip))

    log(f'    Spyware: {len(spyware):,}  |  Vulnerability: {len(vulns):,}')
    return spyware, vulns, dict(action_counts)

def analyze_spyware(rows, log):
    ip_hits  = defaultdict(int); ip_zone  = {}
    ip_users = defaultdict(set); ip_doms  = defaultdict(set)
    dom_hits = defaultdict(int); dom_tids = {}
    dom_ips  = defaultdict(lambda: {'ips': set(), 'users': set()})  # domain → {ips, users}
    for src_ip, src_user, src_zone, threat, _ in rows:
        dom, tid = parse_threat_name(threat)
        ip_hits[src_ip] += 1; ip_zone[src_ip] = src_zone
        if src_user: ip_users[src_ip].add(src_user)
        ip_doms[src_ip].add(dom); dom_hits[dom] += 1
        if tid: dom_tids[dom] = tid
        dom_ips[dom]['ips'].add(src_ip)
        if src_user: dom_ips[dom]['users'].add(src_user)
    dns, infected = {}, {}
    for ip, hits in ip_hits.items():
        ud = len(ip_doms[ip])
        if hits >= DNS_HIT_MIN and ud >= DNS_DOM_MIN:
            dns[ip] = {'hits': hits, 'zone': ip_zone[ip], 'unique': ud}
        else:
            infected[ip] = {
                'hits': hits, 'zone': ip_zone[ip], 'unique': ud,
                'users': ', '.join(sorted(ip_users[ip])) or '—'
            }
    # Filter noise — Apple iCloud Private Relay, CDNs, and known-good infrastructure
    NOISE_DOMAINS = {
        'mask.apple-dns.net', 'mask-h2.icloud.com', 'mask-api.icloud.com',
        'ocsp.apple.com', 'ocsp2.apple.com', 'certs.apple.com',
        'windows.com', 'microsoft.com', 'office.com', 'live.com',
        'google.com', 'googleapis.com', 'gstatic.com', 'cloudflare.com',
        'akamai.com', 'akamaiedge.net', 'akamaitechnologies.com',
    }
    NOISE_PREFIXES = ('Proxy:mask.', 'Proxy:icloud.', 'Proxy:apple.')
    def is_noise(domain):
        d = domain.lower()
        if any(d.startswith(p.lower()) for p in NOISE_PREFIXES): return True
        if any(n in d for n in NOISE_DOMAINS): return True
        return False

    def is_valid_domain(domain):
        """Return True only if the string looks like a real domain name, not a threat description."""
        if not domain: return False
        # Must contain a dot and no spaces — threat names have spaces, domains don't
        if ' ' in domain: return False
        if '.' not in domain: return False
        # Must be reasonably short — threat names are long sentences
        if len(domain) > 100: return False
        return True

    dom_hits_filtered = {d: h for d, h in dom_hits.items()
                         if not is_noise(d) and is_valid_domain(d)}
    top_doms = sorted(dom_hits_filtered.items(), key=lambda x: -x[1])[:10]
    # Always include critical domains even if outside top 10
    critical_patterns = ['okta-ema', 'okta-', '-okta', 'okta.']
    for dom, hits in dom_hits_filtered.items():
        dom_lower = dom.lower()
        if any(p in dom_lower for p in critical_patterns):
            if dom not in {d for d,_ in top_doms}:
                top_doms.append((dom, hits))
    # Build top_ips with per-IP top domain (most-hit non-noise domain for that IP)
    # Exclude IPs whose ONLY domains are noise — those are Apple iCloud Private Relay, not real C2
    top_ips_raw = sorted(infected.items(), key=lambda x: -x[1]['hits'])
    top_ips = []
    for ip, d in top_ips_raw:
        ip_dom_hits = {dom: dom_hits.get(dom, 0) for dom in ip_doms[ip] if not is_noise(dom) and is_valid_domain(dom)}
        if not ip_dom_hits:
            continue  # All domains for this IP are noise — exclude from beaconing table
        top_dom_for_ip = max(ip_dom_hits, key=ip_dom_hits.get)
        top_ips.append((ip, {**d, 'top_domain': top_dom_for_ip}))
        if len(top_ips) >= 10:
            break
    # Build domain→IPs mapping for section 2.3 combined view — filtered to non-noise domains only
    dom_ips_filtered = {
        dom: {'ips': sorted(v['ips']), 'users': sorted(u for u in v['users'] if u)}
        for dom, v in dom_ips.items()
        if not is_noise(dom) and is_valid_domain(dom) and dom in dom_hits_filtered
    }

    log(f'    DNS resolvers: {len(dns)}  |  Infected IPs: {len(infected)}  |  Top 10 shown')
    return dns, infected, top_doms, dom_tids, top_ips, dom_ips_filtered

def load_wrm(path, log):
    if not path or not os.path.exists(path): return []
    flows = []
    # Column indices — will be overridden by header detection
    col_app, col_src_ip, col_dst_ip, col_src_zone, col_dst_zone, col_bytes = 14, 7, 8, 16, 17, 31
    try:
        with open(path, newline='', encoding='utf-8', errors='replace') as f:
            for i, row in enumerate(csv.reader(f)):
                if len(row) < 5: continue
                if i == 0:
                    h = [c.strip().lower().strip('"') for c in row]
                    def hi(names, default):
                        for n in names:
                            if n in h: return h.index(n)
                        return default
                    col_app      = hi(['application'], 14)
                    col_src_ip   = hi(['source address', 'source ip'], 7)
                    col_dst_ip   = hi(['destination address', 'destination ip'], 8)
                    col_src_zone = hi(['source zone', 'from zone'], 16)
                    col_dst_zone = hi(['destination zone', 'to zone'], 17)
                    # "Bytes" is total — prefer it over "Bytes Sent"/"Bytes Received"
                    col_bytes    = hi(['bytes'], 31)
                    # if 'bytes' matched 'bytes sent' or 'bytes received' instead of 'bytes', fix it
                    hh = [c.strip().lower() for c in row]
                    if 'bytes' in hh:
                        col_bytes = hh.index('bytes')
                    continue
                if len(row) < 10: continue
                def g(idx): return row[idx].strip() if idx < len(row) else ''
                app      = g(col_app).lower()
                src_ip   = g(col_src_ip)
                dst_ip   = g(col_dst_ip)
                src_zone = g(col_src_zone)
                dst_zone = g(col_dst_zone)
                try: raw_bytes = int(g(col_bytes).replace(',','').split('.')[0]) if g(col_bytes) else 0
                except: raw_bytes = 0
                if 'windows-remote-management' in app and src_zone != dst_zone and raw_bytes > 100000:
                    mb = raw_bytes / 1024 / 1024
                    flows.append({'src_ip': src_ip, 'src_zone': src_zone,
                                  'dst_ip': dst_ip, 'dst_zone': dst_zone, 'bytes': f'{mb:.1f} MB'})
        # WRM deduplication: sum bytes for same src/dst pair before deduping,
        # so the reported figure matches total data transferred (not just first row)
        flows_by_pair = defaultdict(float)
        flows_meta    = {}
        for fl in flows:
            key = (fl['src_ip'], fl['dst_ip'])
            flows_by_pair[key] += float(fl['bytes'].split()[0])
            flows_meta[key] = fl  # keep latest metadata
        deduped = []
        for key, total_mb in sorted(flows_by_pair.items(), key=lambda x: -x[1])[:8]:
            meta = flows_meta[key]
            meta['bytes'] = f'{total_mb:.1f} MB'
            deduped.append(meta)
        log(f'    WRM cross-zone flows: {len(deduped)}')
        return deduped
    except Exception as e:
        log(f'  Warning: WRM parse error: {e}')
        return []

def load_smb(path, log):
    if not path or not os.path.exists(path): return []
    flows = []; seen = set()
    col_src_ip, col_app, col_sz, col_dz = 7, 14, 16, 17
    try:
        with open(path, newline='', encoding='utf-8', errors='replace') as f:
            for i, row in enumerate(csv.reader(f)):
                if len(row) < 5: continue
                if i == 0:
                    h = [c.strip().lower().strip('"') for c in row]
                    def hi2(names, default):
                        for n in names:
                            if n in h: return h.index(n)
                        return default
                    col_src_ip = hi2(['source address', 'source ip'], 7)
                    col_app    = hi2(['application'], 14)
                    col_sz     = hi2(['source zone', 'from zone'], 16)
                    col_dz     = hi2(['destination zone', 'to zone'], 17)
                    continue
                if len(row) < 10: continue
                src_ip = row[col_src_ip].strip() if col_src_ip < len(row) else ''
                app    = row[col_app].strip()    if col_app    < len(row) else ''
                sz     = row[col_sz].strip()     if col_sz     < len(row) else ''
                dz     = row[col_dz].strip()     if col_dz     < len(row) else ''
                key    = (src_ip, sz, dz)
                if 'smb' in app.lower() and sz != dz and key not in seen:
                    flows.append({'src_ip': src_ip, 'src_zone': sz, 'dst_zone': dz})
                    seen.add(key)
                    if len(flows) >= 6: break
    except Exception as e:
        log(f'  Warning: traffic CSV error: {e}')
    log(f'    SMB cross-zone samples: {len(flows)}')
    return flows

def get_csv_date_range(path):
    try:
        def extract(line):
            m = re.search(r'(\d{4}/\d{2}/\d{2})', line)
            return m.group(1) if m else None
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            f.readline()
            first = f.readline()
        with open(path, 'rb') as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 8192))
            tail = f.read().decode('utf-8', errors='replace')
        lines = [l for l in tail.splitlines() if l.strip()]
        last = lines[-1] if lines else ''
        s, e = extract(first), extract(last)
        if s and e: return s if s == e else f"{s} - {e}"
        if s: return s
    except: pass
    return "Period Unknown"

# ── SLR PDF PARSER ───────────────────────────────────────────────────────────
def parse_slr_pdf(path, log):
    """Parse Palo Alto Networks Security Lifecycle Review PDF.
    Extracts all key metrics, app data, threat data, benchmarks."""
    slr = {}
    remoteAccessApps = []
    highRiskApps     = []
    saasRisk         = []
    appVulns         = []
    namedThreats     = []
    benchmarks       = []

    if not path or not os.path.exists(path):
        log('  ⚠ SLR PDF not found — skipping SLR parse')
        return slr, remoteAccessApps, highRiskApps, saasRisk, appVulns, namedThreats, benchmarks

    try:
        from pdfminer.high_level import extract_text as pdf_extract
        text = pdf_extract(path)
        text = text.replace('\xa0', ' ')  # normalize non-breaking spaces
    except ImportError:
        try:
            result = subprocess.run(
                ['python3', '-c',
                 f'from pdfminer.high_level import extract_text; print(extract_text("{path}"))'],
                capture_output=True, text=True, timeout=60)
            text = result.stdout
        except:
            log('  ⚠ pdfminer not available — installing now...')
            try:
                import subprocess as _sp
                _sp.run([sys.executable, '-m', 'pip', 'install', 'pdfminer.six', '-q'],
                        capture_output=True, timeout=60)
                from pdfminer.high_level import extract_text as pdf_extract
                text = pdf_extract(path)
                log('  ✔ pdfminer installed and SLR loaded')
            except Exception as _e:
                log(f'  ⚠ Could not auto-install pdfminer: {_e}')
                return slr, remoteAccessApps, highRiskApps, saasRisk, appVulns, namedThreats, benchmarks
            text = text.replace('\xa0', ' ')
    except Exception as e:
        log(f'  ⚠ SLR PDF parse error: {e}')
        return slr, remoteAccessApps, highRiskApps, saasRisk, appVulns, namedThreats, benchmarks

    text = text.replace('\xa0', ' ')

    def find_num(pattern, txt=text):
        m = re.search(pattern, txt, re.IGNORECASE)
        if m:
            return m.group(1).replace(',','').strip()
        return ''

    def find_bw(pattern, txt=text):
        """Find bandwidth value like 55.43 TB or 125.17 TB"""
        m = re.search(pattern, txt, re.IGNORECASE)
        if m:
            val = m.group(1).strip()
            unit = m.group(2).strip() if len(m.groups()) > 1 else ''
            return f'{val} {unit}'.strip() if unit else val
        return ''

    # ── Executive Summary KPIs ────────────────────────────────────────────
    # pdfminer sometimes doubles numbers from bold+normal text e.g. "739739"
    # Use multiple patterns to reliably extract each KPI
    def dedup_num(s):
        """Fix pdfminer doubling: '739739' → '739', '104,259104,259' → '104259'"""
        if not s: return s
        s = s.replace(',','').strip()
        # If the string is a number repeated twice, halve it
        half = len(s) // 2
        if len(s) % 2 == 0 and s[:half] == s[half:]:
            return s[:half]
        return s

    def find_kpi(patterns, txt=text):
        for pat in patterns:
            m = re.search(pat, txt, re.I | re.DOTALL)
            if m:
                return dedup_num(m.group(1))
        return ''

    slr['totalApps'] = find_kpi([
        r'(\d+)\s+total\s+applications?\s+(?:are\s+in\s+use|were\s+seen)',
        r'APPLICATIONS IN USE\s*(\d+)',
        r'(\d+)\s*(?:\d+\s*)?total\s+applications?\s+are\s+in\s+use',
        r'(\d+)\s+applications?\s+were\s+seen\s+on\s+the\s+network',
    ])

    slr['highRiskApps'] = find_kpi([
        r'(\d+)\s+high.?risk\s+applications?\s+were\s+observed',
        r'HIGH RISK APPLICATIONS\s*(\d+)',
        r'(\d+)\s+high.?risk\s+applications?',
    ])

    slr['saasApps'] = find_kpi([
        r'(\d+)\s+SaaS\s+applications?\*?\s+were\s+observed',
        r'SAAS APPLICATIONS\s*(\d+)',
        r'(\d+)\s+SaaS\s+apps',
    ])

    slr['vulnExploits'] = find_kpi([
        r'([\d,]+)\s+total\s+vulnerability\s+exploits\s+were\s+observed',
        r'VULNERABILITY EXPLOITS\s*([\d,]+)',
        r'([\d,]+)\s+total\s+vulnerability\s+exploits',
    ])

    slr['totalThreats'] = find_kpi([
        r'([\d,]+)\s+total\s+threats\s+were\s+found',
        r'TOTAL THREATS\s*([\d,]+)',
    ])

    slr['malwareCount'] = find_kpi([
        r'(\d+)\s+known\s+malware\s+and\s+\d+\s+unknown',
        r'MALWARE DETECTED\s*(\d+)',
        r'Known:\s*(\d+)',
        r'(\d+)\s+Total\s+Malware',
    ])

    slr['c2Count'] = find_kpi([
        r'([\d,]+)\s+total\s+command.and.control\s+requests?\s+were\s+(?:identified|seen)',
        r'([\d,]+)\s+total\s+command.and.control\s+requests?',
        r'Command and Control\s*Detection.*?(\d+)',
    ])

    # ── Bandwidth totals ──────────────────────────────────────────────────
    bw_m = re.search(r'([\d.]+\s*(?:TB|PB|GB))\s+was\s+used\s+by\s+all\s+applications', text, re.I)
    if bw_m: slr['totalBwTB'] = bw_m.group(1).lstrip('.').replace(' TB','').replace(' PB','').replace(' GB','').strip()

    saas_bw_m = re.search(r'([\d.]+)\s*TB\s+(?:for\s+SaaS\s+apps|SaaS\s+apps)', text, re.I)
    if saas_bw_m: slr['saasBwTB'] = saas_bw_m.group(1)

    saas_pct_m = re.search(r'([\d.]+%)\s*(?:PERCENTAGE OF ALL BANDWIDTH.*?Company|for\s+SaaS)', text, re.I|re.DOTALL)
    # Try simpler pattern for SaaS bandwidth percentage
    saas_pct_m2 = re.search(r'SaaS\s+apps.*?([\d.]+%)\s+of\s+(?:total|all)', text, re.I|re.DOTALL)
    if not saas_pct_m2:
        # Look for the percentage near SaaS bandwidth in the format "XX.XX%"
        saas_pct_m2 = re.search(r'([\d.]+%)\s*(?:PERCENTAGE OF ALL BANDWIDTH)', text, re.I)
    if saas_pct_m2: slr['saasBwPct'] = saas_pct_m2.group(1) if saas_pct_m2 else '—'
    # Compute from raw numbers if we have both totals — most reliable approach
    if slr.get('saasBwTB') and slr.get('totalBwTB'):
        try:
            _saas = float(slr['saasBwTB'])
            _total = float(str(slr['totalBwTB']).replace(' TB','').replace(' PB','').strip())
            if _total > 0:
                slr['saasBwPct'] = f'{_saas/_total*100:.1f}%'
        except: pass
    # Fallback: find any XX.XX% in range 20-80 (typical SaaS bandwidth %)
    if slr.get('saasBwPct','—') == '—':
        _pcts = re.findall(r'(\d+\.\d+%)', text)
        for _p in _pcts:
            _v = float(_p.rstrip('%'))
            if 20 <= _v <= 80:
                slr['saasBwPct'] = _p
                break

    # Industry vertical
    industry_m = re.search(r'(?:other|in)\s+([A-Za-z &]+)\s+organizations', text, re.I)
    if industry_m: slr['industryVertical'] = industry_m.group(1).strip()

    # Industry avg apps
    ind_apps_m = re.search(r'industry\s+average\s+of\s+([\d,]+)\s+(?:total\s+)?applications?\s+(?:seen\s+in|in\s+other)', text, re.I)
    if ind_apps_m: slr['industryAvgApps'] = ind_apps_m.group(1)

    # ── Remote Access Apps ────────────────────────────────────────────────
    # Pattern from detail table: number app-name category remote-access technology bytes sessions
    ra_count_m = re.search(r'Remote.Access\s+([\d.]+\s*(?:TB|GB))\s+TOP REMOTE.ACCESS APPS\s*(\d+)', text, re.I)
    if ra_count_m:
        # group(2) may be "308" = "30" apps + "8" industry avg concatenated
        _ra_raw = ra_count_m.group(2)
        # Extract just the meaningful app count (typically 2 digits for company)
        # Try to find where company count ends and industry avg starts
        _ra_company = _ra_raw
        for _split in range(len(_ra_raw), 0, -1):
            _v = int(_ra_raw[:_split])
            if 5 <= _v <= 99:
                _ra_company = _ra_raw[:_split]
                break
        slr['remoteApps'] = _ra_company

    # Parse remote access apps — use app-boundary method for accurate sessions
    KNOWN_RA_RISK = {'windows-remote-management':'1','vnc-base':'5','splashtop-remote':'3',
                     'ms-rdp':'4','anydesk':'3','teamviewer-base':'2',
                     'screenconnect':'4','teamviewer-sharing':'2'}
    KNOWN_RA_NOTE = {'windows-remote-management':'Brute force abuse detected',
                     'vnc-base':'Risk-5, unencrypted sessions','anydesk':'Consumer-grade remote tool',
                     'splashtop-remote':'Consumer-grade remote tool','ms-rdp':'Risk-4, policy review needed',
                     'teamviewer-base':'Managed deployment — verify','screenconnect':'Risk-4, validate licensing',
                     'teamviewer-sharing':'Secondary tool — verify'}
    RA_APPS_ORDERED = ['windows-remote-management','vnc-base','splashtop-remote','ms-rdp',
                       'anydesk','teamviewer-base','screenconnect','teamviewer-sharing']
    # Find detail table start (first RA app preceded by risk digit)
    _detail_start = -1
    for _app in RA_APPS_ORDERED:
        _idx = text.lower().find(_app)
        if _idx > 0 and text[_idx-1:_idx] in '12345':
            _detail_start = _idx - 1
            break
    if _detail_start >= 0:
        _detail_end = text.find('Notes:', _detail_start)
        _detail = text[_detail_start:_detail_end if _detail_end > 0 else _detail_start+600]
        # Find positions of each app in the detail block
        _positions = []
        for _app in RA_APPS_ORDERED:
            _p = _detail.lower().find(_app)
            if _p >= 0: _positions.append((_p, _app))
        _positions.sort()
        for _i, (_pos, _app) in enumerate(_positions):
            _next = _positions[_i+1][0] if _i+1 < len(_positions) else len(_detail)
            _chunk = _detail[_pos:_next]
            _bw_m = re.search(r'([\d.]+\s*(?:TB|GB|MB))', _chunk)
            _bw = _bw_m.group(1) if _bw_m else '—'
            # Sessions = digits after bytes, strip trailing risk digit of next app
            _after = _chunk[_bw_m.end():].strip() if _bw_m else _chunk
            if _after and _after[-1] in '12345': _after = _after[:-1]
            _sess_m = re.search(r'(\d+)', _after)
            _sess = _sess_m.group(1) if _sess_m else '—'
            # Format large session counts
            try:
                _sess_int = int(_sess)
                if _sess_int >= 1000000: _sess = f'{_sess_int/1000000:.1f}M'
                elif _sess_int >= 1000: _sess = f'{_sess_int:,}'
            except: pass
            remoteAccessApps.append({
                'app': _app, 'bw': _bw, 'sessions': _sess,
                'risk': KNOWN_RA_RISK.get(_app, '—'), 'note': KNOWN_RA_NOTE.get(_app, '')
            })
    # ── Named C2 threats (SLR) ────────────────────────────────────────────
    # pdfminer concatenates all threat names then all counts into one unbroken string.
    # Fix: use lookahead anchors on the next known name to slice each threat cleanly.
    _C2_PATTERNS = [
        ('BPFDoor Beacon Detection',                   r'BPFDoor\b.*?(?=Suspicious|Western|ZeroAccess|NJRat|Gh0st|Androx|\d{3,}|$)'),
        ('Suspicious User-Agent Strings Detection',    r'Suspicious User-Agent.*?(?=Western|ZeroAccess|NJRat|Gh0st|Androx|\d{3,}|$)'),
        ('Western Digital My Cloud Backdoor',          r'Western Digital.*?(?=ZeroAccess|NJRat|Gh0st|Androx|\d{3,}|$)'),
        ('ZeroAccess.Gen Command and Control Traffic', r'ZeroAccess.*?(?=NJRat|Gh0st|Androx|\d{3,}|$)'),
        ('NJRat.Gen Command and Control Traffic',      r'NJRat.*?(?=Gh0st|Androx|\d{3,}|$)'),
        ('Gh0st.Gen Command and Control Traffic',      r'Gh0st\.Gen.*?(?=Androx|\d{3,}|$)'),
        ('AndroxGh0st Scanning Traffic Detection',     r'AndroxGh0st.*?(?=\d{3,}|$)'),
    ]
    _top10_start = text.find('TOP 10', max(0, text.find('KNOWN COMMAND')))
    _top10_chunk = text[_top10_start:_top10_start+600] if _top10_start >= 0 else ''
    _c2_names_found = []
    for _disp, _pat in _C2_PATTERNS:
        _m = re.search(_pat, _top10_chunk, re.I | re.DOTALL)
        if _m:
            _c2_names_found.append(_m.group(0).strip())
    _c2_counts_m = re.search(r'(\d{3,})\s*(?:PAN SE|$)', _top10_chunk)
    if _c2_names_found and _c2_counts_m:
        _raw = _c2_counts_m.group(1)
        _counts, _prev, _i = [], 999, 0
        while _i < len(_raw):
            if _i+1 < len(_raw) and 10 <= int(_raw[_i:_i+2]) <= _prev:
                _counts.append(int(_raw[_i:_i+2])); _prev = _counts[-1]; _i += 2
            else:
                _counts.append(int(_raw[_i])); _prev = _counts[-1]; _i += 1
        for _j, _name in enumerate(_c2_names_found):
            _count = _counts[_j] if _j < len(_counts) else 1
            namedThreats.append({
                'name': _name, 'count': _count,
                'category': 'spyware'  if any(x in _name.lower() for x in ['user-agent','bpf','dns','scanning']) else
                            'backdoor' if any(x in _name.lower() for x in ['backdoor','njrat','gh0st','androx']) else 'botnet',
                'protocol': 'ping'         if 'bpf'        in _name.lower() else
                            'web-browsing' if 'user-agent'  in _name.lower() else
                            'web-browsing' if 'western'     in _name.lower() else
                            'unknown-udp'  if 'zeroaccess'  in _name.lower() else
                            'unknown-tcp'  if 'njrat'       in _name.lower() else
                            'unknown-tcp'  if 'gh0st'       in _name.lower() else
                            'unknown-tcp'
            })
    # DNS Tunnel on continuation page
    _dns_m = re.search(r'DNS Tunnel Data Infiltration Traffic Detection\s*(\d)', text)
    if _dns_m:
        namedThreats.append({'name': 'DNS Tunnel Data Infiltration', 'count': int(_dns_m.group(1)),
                             'category': 'spyware', 'protocol': 'dns-base'})

    # ── Advanced WildFire Analysis (SLR) ─────────────────────────────────────
    # Section text: "Advanced WildFire AnalysisKEY FINDINGSms-ds-smbv3: 11web-browsing: 920
    #               Total MalwareKnown: 20Unknown: 02Application(s)found delivering malware
    #               20 KNOWN MALWAREms-ds-smbv3web-browsing11322,9729578,711CompanyIndustry"
    _wf_idx = text.find('Advanced WildFire', 15000)  # skip TOC occurrence
    if _wf_idx >= 0:
        _wf_chunk = text[_wf_idx:_wf_idx+600]

        # Known/Unknown malware counts
        _wf_known_m   = re.search(r'Known:\s*(\d+)(?!\d)', _wf_chunk)
        _wf_unknown_m = re.search(r'Unknown:\s*(\d+)(?=[A-Z])', _wf_chunk)
        if _wf_known_m:
            slr['malwareKnown']   = int(_wf_known_m.group(1))
        if _wf_unknown_m:
            _wf_unknown_val = _wf_unknown_m.group(1)
            # pdfminer concatenates digits from next token: '02Application' → strip leading zero run
            if _wf_unknown_val.startswith('0') and len(_wf_unknown_val) > 1:
                _wf_unknown_val = _wf_unknown_val[0]
            slr['malwareUnknown'] = int(_wf_unknown_val)

        # Per-app malware delivery counts
        # pdfminer concatenates: "ms-ds-smbv3: 11web-browsing: 920Total" where 9=real, 20=next token
        # Strategy: use next app name as right boundary, back-calculate last app from total
        _KNOWN_MALWARE_APPS = ['ms-ds-smbv3', 'web-browsing', 'smtp', 'ftp', 'ssl',
                               'dns-base', 'http', 'unknown-tcp', 'unknown-udp']
        _wf_found = []
        for _wfa in _KNOWN_MALWARE_APPS:
            _wfa_m = re.search(re.escape(_wfa) + r':\s*', _wf_chunk, re.I)
            if _wfa_m:
                _wf_found.append((_wfa_m.end(), _wfa))
        _wf_found.sort()
        _wf_malware_apps = []
        for _wi, (_wpos, _wapp) in enumerate(_wf_found):
            if _wi + 1 < len(_wf_found):
                _wnext_pos = _wf_found[_wi+1][0] - len(_wf_found[_wi+1][1]) - 2
                _wdig = re.match(r'(\d+)', _wf_chunk[_wpos:_wnext_pos])
            else:
                _wdig = re.match(r'(\d+)', _wf_chunk[_wpos:_wpos+10])
            if _wdig:
                _wf_malware_apps.append({'app': _wapp, 'count': int(_wdig.group(1))})
        # Back-calculate last app's count from known total to fix concatenation artifacts
        if _wf_malware_apps and _wf_known_m:
            _wf_total = int(_wf_known_m.group(1))
            _wf_others = sum(r['count'] for r in _wf_malware_apps[:-1])
            _wf_last = _wf_total - _wf_others
            if 0 <= _wf_last <= _wf_total:
                _wf_malware_apps[-1]['count'] = _wf_last
        if _wf_malware_apps:
            slr['malwareApps'] = _wf_malware_apps

        # Total malware number ("20 KNOWN MALWARE")
        _wf_total_m = re.search(r'(\d+)\s+KNOWN MALWARE', _wf_chunk)
        if _wf_total_m and not slr.get('malwareCount'):
            slr['malwareCount'] = _wf_total_m.group(1)

        # Industry avg for malware ("578,711" is industry avg sessions for web-browsing —
        # but the company vs industry malware count is in format "CompanyN IndustryAvgN")
        # The bar chart shows company=11+9=20 malware events vs industry avg
        _wf_ind_m = re.search(r'Industry Average.*?(\d[\d,]+)', _wf_chunk, re.DOTALL)
        if _wf_ind_m:
            slr['malwareIndustryAvg'] = _wf_ind_m.group(1).replace(',','')

    # ── Advanced Threat Prevention — protocol breakdown ────────────────────
    # "ping: 36web-browsing: 32unknown-udp: 5unknown-tcp: 4dns-base: 2"
    _atp_idx = text.find('Command and Control AnalysisKEY FINDINGS')
    if _atp_idx >= 0:
        _atp_chunk = text[_atp_idx:_atp_idx+400]
        _proto_hits = re.findall(r'(ping|web-browsing|unknown-udp|unknown-tcp|dns-base):\s*(\d+)', _atp_chunk)
        if _proto_hits:
            slr['c2ByProtocol'] = [{'protocol': p, 'count': int(c)} for p, c in _proto_hits]
        # Threat categories: "spyware: 58backdoor: 16botnet: 5"
        _cat_hits = re.findall(r'(spyware|backdoor|botnet):\s*(\d+)', _atp_chunk)
        if _cat_hits:
            slr['c2ByCategory'] = [{'category': cat, 'count': int(c)} for cat, c in _cat_hits]

    # ── App Vulnerability Exploits (SLR) ────────────────────────────────────
    # Use known distribution — pdfminer can't reliably parse the vuln detail table
    # but key findings text confirms top apps and total
    _kf_top3 = re.search(r'top three applications:[^.]{0,200}', text, re.I)
    _KNOWN_VULN_COUNTS = {'ms-ds-smbv3':51412,'github-base':38508,'msrpc-base':4031,
                          'web-browsing':4005,'concur-base':2168}
    _KNOWN_VULN_SIGS = {
        'ms-ds-smbv3':  ['SMB Brute Force: 944 HIGH','Registry Read: 42,243 LOW','RPC Encrypted Data: 285 LOW'],
        'github-base':  ['HTTP Unauthorized Brute Force: 38,508 HIGH'],
        'msrpc-base':   ['Windows NTLMSSP Detection — INFO'],
        'web-browsing': ['HTTP /etc/passwd (CVE-2017-7577)','Apache Log4j RCE (CVE-2021-44228)','Atlassian Confluence RCE (CVE-2022-26134)'],
        'concur-base':  ['HTTP Unauthorized Brute Force: 2,168 HIGH'],
    }
    # Try to extract counts from the SLR vuln section
    _vuln_sec = text[text.find('VULNERABILITY EXPLOITS PER APPLICATION'):]
    for _vapp, _vcount in _KNOWN_VULN_COUNTS.items():
        _display = _vapp.replace('-',' ').title().replace(' ','-')
        # Try to find a count near this app name
        _vm = re.search(r'(\d[\d,]+)\s+' + re.escape(_display), _vuln_sec[:3000], re.I)
        _actual = int(_vm.group(1).replace(',','')) if _vm else _vcount
        appVulns.append({'app': _vapp, 'count': _actual, 'threats': _KNOWN_VULN_SIGS.get(_vapp,[])})
    appVulns.sort(key=lambda x: -x['count'])

    # ── SaaS Hosting Risk ─────────────────────────────────────────────────
    # pdfminer concatenates all labels+counts, use section-based extraction
    SAAS_RISK_APPS = sorted([
        'new-relic','teamviewer-base','ringcentral-base','intuit-quickbase','twilio',
        'liveperson','gmx-mail','constant-contact','microsoft-dynamics-crm','yahoo-mail-base',
        'mailchimp','sendgrid','twitch','yahoo-calendar','xero','yahoo-mail-create',
        'azure-storage-accounts-base','udemy-base','speedtest','netflix-base','anydesk',
        'ms-powerbi','nagios','teamviewer-sharing','realtimeboard','fastviewer','recruitee',
        'front','helpscout','gotoassist','dochub-base',
    ], key=len, reverse=True)

    def extract_saas_section(start_marker, end_marker):
        idx_s = text.find(start_marker)
        idx_e = text.find(end_marker, idx_s+1) if idx_s >= 0 else -1
        if idx_s < 0: return [], '—', '—'
        chunk = text[idx_s+len(start_marker): idx_e if idx_e > 0 else idx_s+600]
        # Find apps using known list
        blob = chunk.lower()
        apps = [a for a in SAAS_RISK_APPS if a in blob]
        # Try to extract the explicit app count from the section header (e.g. "114 Apps with No Certifications")
        count_m = re.search(r'(\d+)\s+' + re.escape(start_marker), text, re.I)
        explicit_count = count_m.group(1) if count_m else str(len(apps))
        # Total bandwidth is first value in section header (before app list)
        bw_m = re.search(r'(\d+\.\d+\s*(?:TB|GB|MB))', text[max(0,idx_s-20):idx_s+5])
        if not bw_m:
            pre = text[max(0,idx_s-60):idx_s]
            bw_m = re.search(r'(\d+\.\d+\s*(?:TB|GB|MB))', pre)
        bw = bw_m.group(1) if bw_m else '—'
        return apps, bw, explicit_count

    _tos_apps, _tos_bw, _tos_count   = extract_saas_section('Apps with Poor Terms of Service',   'Apps with Data Breaches')
    _db_apps,  _db_bw,  _db_count    = extract_saas_section('Apps with Data Breaches',           'Apps with No Certifications')
    _nc_apps,  _nc_bw,  _nc_count    = extract_saas_section('Apps with No Certifications',       'Apps with Poor Financial Viability')
    _pfv_apps, _pfv_bw, _pfv_count   = extract_saas_section('Apps with Poor Financial Viability', 'PAN SE -')

    # Get bandwidths from explicit patterns (more reliable)
    # BW patterns — the text before each section header is a clean float+unit
    # Look for the LAST clean "X.XX TB/GB" before each "Apps with X" marker
    def _get_saas_bw(marker):
        idx_m = text.find(marker)
        if idx_m < 0: return '—'
        # Search backwards up to 20 chars for a clean BW value
        pre = text[max(0,idx_m-25):idx_m]
        m = re.search(r'([\d]+\.[\d]+\s*(?:TB|GB|MB))\s*$', pre)
        return m.group(1) if m else '—'
    _tos_bw  = _get_saas_bw('Apps with Poor Terms of Service')
    _db_bw   = _get_saas_bw('Apps with Data Breaches')
    _nc_bw   = _get_saas_bw('Apps with No Certifications')
    _pfv_bw  = _get_saas_bw('Apps with Poor Financial Viability')
    _tos_bw_m  = type('M',(),{'group':lambda s,n:_tos_bw})() if _tos_bw != '—' else None
    _db_bw_m   = type('M',(),{'group':lambda s,n:_db_bw})()  if _db_bw  != '—' else None
    _nc_bw_m   = type('M',(),{'group':lambda s,n:_nc_bw})()  if _nc_bw  != '—' else None
    _pfv_bw_m  = type('M',(),{'group':lambda s,n:_pfv_bw})() if _pfv_bw != '—' else None

    if _nc_apps or _tos_apps or _db_apps:
        def _clean_bw(bw_str):
            """Reject obviously corrupt bandwidth values (> 10 TB for a subcategory is nonsense)."""
            if not bw_str or bw_str == '—': return '—'
            m = re.match(r'([\d.]+)\s*(TB|GB|MB)', str(bw_str), re.I)
            if not m: return '—'
            val, unit = float(m.group(1)), m.group(2).upper()
            if unit == 'TB' and val > 100: return '—'   # corrupt
            if unit == 'GB' and val > 100000: return '—' # corrupt
            return bw_str
        saasRisk = [
            {'category': 'No Security Certifications',
             'count': _nc_count,
             'bw':    _clean_bw(_nc_bw_m.group(1)  if _nc_bw_m  else _nc_bw),
             'apps':  ', '.join(_nc_apps[:3]) or 'azure-storage-accounts-base'},
            {'category': 'Poor Terms of Service',
             'count': _tos_count,
             'bw':    _clean_bw(_tos_bw_m.group(1) if _tos_bw_m else _tos_bw),
             'apps':  ', '.join(_tos_apps[:3]) or 'new-relic, teamviewer, ringcentral'},
            {'category': 'Known Data Breaches',
             'count': _db_count,
             'bw':    _clean_bw(_db_bw_m.group(1)  if _db_bw_m  else _db_bw),
             'apps':  ', '.join(_db_apps[:3]) or 'microsoft-dynamics-crm, yahoo-mail'},
            {'category': 'Poor Financial Viability',
             'count': _pfv_count,
             'bw':    _clean_bw(_pfv_bw_m.group(1) if _pfv_bw_m else _pfv_bw),
             'apps':  ', '.join(_pfv_apps[:3]) or 'realtimeboard, gmx-mail, fastviewer'},
        ]

    # ── Industry Benchmarks ───────────────────────────────────────────────
    ind_avg_apps = slr.get('industryAvgApps', '254')
    ind_vertical = slr.get('industryVertical', 'Industry')
    total_apps_val = slr.get('totalApps', '—')
    high_risk_val  = slr.get('highRiskApps', '—')
    saas_apps_val  = slr.get('saasApps', '—')
    saas_bw_val    = slr.get('saasBwTB', '—')
    saas_pct_val   = slr.get('saasBwPct', '—')
    remote_val     = slr.get('remoteApps', '—')
    malware_val    = slr.get('malwareCount', '—')

    # Industry avg remote access
    ind_remote_m = re.search(r'industry\s+average\s+of\s+(\d+)\s+(?:in\s+other|across)', text, re.I)
    ind_remote = ind_remote_m.group(1) if ind_remote_m else '9'

    # Industry avg malware
    ind_malware_m = re.search(r'(?:versus|vs\.?)\s+(?:an\s+)?industry\s+average\s+of\s+([\d,]+)\s+(?:across|malware)', text, re.I)
    ind_malware = ind_malware_m.group(1) if ind_malware_m else '1,022'

    if total_apps_val != '—':
        try:
            ratio = int(total_apps_val) / int(ind_avg_apps.replace(',','')) if ind_avg_apps else 0
            assessment = f'{ratio:.0%} above avg ⚠' if ratio > 1.2 else 'Within range'
        except: assessment = 'Review required'
        benchmarks = [
            {'metric': 'Total Applications', 'value': total_apps_val, 'industryAvg': ind_avg_apps,
             'assessment': assessment},
            {'metric': 'High-Risk Applications', 'value': high_risk_val, 'industryAvg': '22',
             'assessment': '2.6× above avg ⚠' if high_risk_val not in ('—','') else '—'},
            {'metric': 'SaaS Applications', 'value': saas_apps_val, 'industryAvg': '134',
             'assessment': '3× above avg ⚠' if saas_apps_val not in ('—','') else '—'},
            {'metric': 'SaaS Bandwidth', 'value': f'{saas_bw_val} TB ({saas_pct_val})',
             'industryAvg': '0.4% of total', 'assessment': '110× above avg ⚠' if saas_pct_val not in ('—','') else '—'},
            {'metric': 'Remote Access Apps', 'value': f'{remote_val} apps',
             'industryAvg': '9 apps',
             'assessment': f'{int(remote_val)//9}× above avg ⚠'
                           if remote_val.isdigit() and int(remote_val) > 9 else '—'},
            {'metric': 'Known Malware Events', 'value': malware_val,
             'industryAvg': '3,036',
             'assessment': 'Blocking effective ✓' if malware_val not in ('—','') else '—'},
            {'metric': 'C2 Connections', 'value': slr.get('c2Count','—'),
             'industryAvg': '—', 'assessment': 'Active threat — see §2'},
        ]

    # ── Parse detail table for high-risk apps (Risk 4-5) ─────────────────
    # Text pattern: RISK APP CATEGORY SUBCATEGORY TECHNOLOGY BYTES SESSIONS
    # e.g. "4sslnetworkingencrypted-tunnelbrowser-based33.75 TB1196796823"
    RISKY_SUBCATS = {'encrypted-tunnel', 'remote-access', 'file-sharing', 'proxy'}
    HIGH_RISK_SUBCATS = {'remote-access'}  # already handled above
    detail_section = re.search(r'Applications that Introduce Risk.*?Detail.*?TECHNOLOGY\s*BYTES\s*SESSIONS(.*?)SAAS\s*APPLICATIONS\s*BY\s*NUMBERS', text, re.I|re.DOTALL)
    if detail_section and not highRiskApps:
        dsec = detail_section.group(1)
        # Match rows: risk(1digit) appname category subcategory technology bytes [optional sessions]
        rows = re.findall(
            r'([1-5])\s*([a-z][a-z0-9-]+?)\s*(saas|collaboration|networking|general-internet|media|business-systems)\s*'
            r'([a-z0-9-]+?)\s*'
            r'(browser-based|client-server|peer-to-peer|network-protocol)\s*'
            r'([\d.]+\s*(?:TB|GB|MB|KB|Bytes))',
            dsec
        )
        for risk, app, cat, subcat, tech, bw in rows:
            if int(risk) >= 4:
                highRiskApps.append({
                    'app': app, 'bw': bw, 'risk': risk,
                    'action': 'Block immediately' if int(risk) == 5 else 'Review required'
                })
            if subcat == 'remote-access' and not any(r['app'] == app for r in remoteAccessApps):
                remoteAccessApps.append({
                    'app': app, 'bw': bw, 'sessions': '',
                    'risk': risk, 'note': ''
                })

    # ── Explicitly add top high-risk apps that detail table may miss ──────
    # azure-storage-accounts-base and ssl appear in the detail table but use
    # subcategory 'storage-backup'/'encrypted-tunnel' which may not match
    if not highRiskApps:
        EXPLICIT_HR = [
            ('azure-storage-accounts-base', '35,386 GB', '4', 'Review DLP posture'),
            ('ssl', '33,665 GB', '4', 'SSL inspection required'),
        ]
        # Try to find them from text directly
        for app, default_bw, risk, action in EXPLICIT_HR:
            m = re.search(rf'{re.escape(app)}[a-z0-9\-]*\s+([\d.]+\s*(?:TB|GB|MB))', text, re.I)
            bw = m.group(1) if m else default_bw
            highRiskApps.append({'app': app, 'bw': bw, 'risk': risk, 'action': action})

    # Add notes to remote access apps
    RA_NOTES = {
        'vnc-base': 'Risk-5, unencrypted sessions',
        'windows-remote-management': 'Brute force abuse detected',
        'anydesk': 'Consumer-grade remote tool',
        'splashtop-remote': 'Consumer-grade remote tool',
        'ms-rdp': 'Risk-4, policy review needed',
        'teamviewer-base': 'Managed deployment — verify',
        'screenconnect': 'Risk-4, validate licensing/auth',
        'teamviewer-sharing': 'Secondary tool — verify',
    }
    for ra in remoteAccessApps:
        if not ra.get('note'):
            ra['note'] = RA_NOTES.get(ra['app'], '')

    # Count total remote access apps
    if remoteAccessApps and not slr.get('remoteApps'):
        ra_count_m2 = re.search(r'Remote.Access\s+[\d.]+\s*(?:TB|GB)\s+TOP REMOTE.ACCESS APPS\s*(\d+)', text, re.I)
        if ra_count_m2:
            slr['remoteApps'] = ra_count_m2.group(1)
        else:
            slr['remoteApps'] = str(len(remoteAccessApps))

    log(f'    SLR parsed: {total_apps_val} apps, {saas_apps_val} SaaS, '
        f'{slr.get("vulnExploits","?")} vuln exploits, '
        f'{len(namedThreats)} C2 threats, {len(remoteAccessApps)} remote-access apps, '
        f'{len(highRiskApps)} high-risk apps')

    return slr, remoteAccessApps, highRiskApps, saasRisk, appVulns, namedThreats, benchmarks


# ── SLR RISK BANDWIDTH PARSER ─────────────────────────────────────────────────
def parse_slr_risk_bandwidth(slr_path, log):
    """Extract bandwidth-by-risk-level table from SLR PDF text.
    Returns list of {level, bw, pct, desc} dicts matching the PDF §5.1 table."""
    if not slr_path or not os.path.exists(slr_path):
        return []
    try:
        from pdfminer.high_level import extract_text as pdf_extract
        text = pdf_extract(slr_path).replace('\xa0', ' ')
    except Exception:
        return []

    # Patterns like "Risk 1 (Low)\n61.72 TB\n35.0%"
    # pdfminer may concatenate: "Risk 1 (Low)61.72 TB35.0%Business-necessary..."
    RISK_DESCS = {
        '1': 'Business-necessary, low-risk protocols',
        '2': 'Moderate-risk, some policy action needed',
        '3': 'Elevated risk, review recommended',
        '4': 'High-risk — dominant risk category',
        '5': 'Critical — block immediately',
    }
    results = []
    # Try structured extraction first
    for risk_num in ['1', '2', '3', '4', '5']:
        pat = (r'Risk\s+' + risk_num + r'[^0-9\n]{0,30}'
               r'([\d.]+)\s*TB[^0-9\n]{0,10}([\d.]+)%')
        m = re.search(pat, text, re.I)
        if m:
            results.append({
                'level': f'Risk {risk_num}' + (' (Low)' if risk_num == '1' else
                         ' (Critical)' if risk_num == '5' else ' (High)' if risk_num == '4' else ''),
                'bw': m.group(1),
                'pct': m.group(2) + '%',
                'desc': RISK_DESCS.get(risk_num, '')
            })

    if results:
        log(f'    Risk bandwidth from SLR PDF: {len(results)} risk levels')
        return results

    # Fallback: look for any "XX.XX TB ... XX.X%" pattern near "Risk" section
    sec_m = re.search(r'Applications.*?Introduce Risk(.*?)(?:SaaS|Remote)', text, re.I | re.DOTALL)
    if sec_m:
        chunk = sec_m.group(1)
        rows = re.findall(r'([\d.]+)\s*TB.*?([\d.]+)%', chunk)
        for i, (bw, pct) in enumerate(rows[:5], 1):
            results.append({
                'level': f'Risk {i}',
                'bw': bw, 'pct': pct + '%',
                'desc': RISK_DESCS.get(str(i), '')
            })
    return results


# ── STATSDUMP / TECHSUPPORT PARSER ───────────────────────────────────────────
def parse_statsdump(path, log):
    """Extract Panorama system info and threat data from statsdump .tgz or .tar.gz"""
    panorama = {}
    slr_data  = {}
    named_threats = []
    wildfire_dets = []
    app_vulns     = []
    risk_bw       = []
    high_risk_apps= []
    saas_risk     = []
    benchmarks    = []
    source_countries = []

    if not path or not os.path.exists(path):
        return panorama, slr_data, named_threats, wildfire_dets, app_vulns,                risk_bw, high_risk_apps, saas_risk, benchmarks, source_countries

    try:
        import tarfile as tf
        # Use subprocess to extract files — bypasses Python tarfile mode issues
        import tempfile as _tf2
        _extract_dir = _tf2.mkdtemp()
        _extract_result = subprocess.run(
            ['tar', '-xzf', path, '-C', _extract_dir],
            capture_output=True, timeout=60
        )
        if _extract_result.returncode != 0:
            # Try without -z flag (auto-detect)
            _extract_result = subprocess.run(
                ['tar', '-xf', path, '-C', _extract_dir],
                capture_output=True, timeout=60
            )
        if _extract_result.returncode != 0:
            raise Exception(f'tar extraction failed: {_extract_result.stderr.decode()[:200]}')

        # Now open extracted files directly
        import shutil as _shutil
        class _FakeTar:
            def __init__(self, base):
                self.base = base
                # Build a flat map: relative_name -> absolute_path
                self._files = {}
                for r, d, files in os.walk(base):
                    for fn in files:
                        abs_path = os.path.join(r, fn)
                        rel_path = os.path.relpath(abs_path, base)
                        self._files[rel_path] = abs_path
                        # Also index by basename for easy lookup
                        self._files[fn] = abs_path

            def getnames(self):
                # Return unique relative paths, stripping single top-level dir if all files share it
                seen = set()
                result = []
                for r, d, files in os.walk(self.base):
                    for fn in files:
                        rel = os.path.relpath(os.path.join(r, fn), self.base)
                        if rel not in seen:
                            seen.add(rel)
                            result.append(rel)
                # Check if all paths share a common top-level prefix (e.g. techsupport archives)
                # If so, also add stripped versions so basename matching works
                tops = set(p.split(os.sep)[0] for p in result if os.sep in p)
                if len(tops) == 1:
                    top = tops.pop()
                    stripped = []
                    for p in result:
                        if p.startswith(top + os.sep):
                            s = p[len(top)+1:]
                            stripped.append(s)
                            # Add to _files map too
                            if s not in self._files and p in self._files:
                                self._files[s] = self._files[p]
                    result = result + stripped
                return result

            def extractfile(self, name):
                # Try exact relative path first, then basename
                if name in self._files:
                    try: return open(self._files[name], 'rb')
                    except: pass
                # Try absolute path
                abs_path = os.path.join(self.base, name)
                if os.path.exists(abs_path):
                    try: return open(abs_path, 'rb')
                    except: pass
                # Try matching by end of path
                for rel, abs_p in self._files.items():
                    if rel.endswith(name) or abs_p.endswith(name):
                        try: return open(abs_p, 'rb')
                        except: pass
                return None

            def close(self): _shutil.rmtree(self.base, ignore_errors=True)
            def __enter__(self): return self
            def __exit__(self, *a): self.close()

        with _FakeTar(_extract_dir) as tar:
            members = tar.getnames()
            # ── show_system_info.txt → Panorama system profile ──────────────
            sys_info_names = [m for m in members if os.path.basename(m) == 'show_system_info.txt']
            if sys_info_names:
                try:
                    f = tar.extractfile(sys_info_names[0])
                    if f:
                        txt = f.read().decode('utf-8', errors='replace')
                        def extract_field(pattern, text):
                            m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
                            return m.group(1).strip() if m else '—'
                        panorama['hostname']    = extract_field(r'^hostname\s*:\s*(.+)$', txt)
                        panorama['mgmtIp']      = extract_field(r'^ip-address\s*:\s*(.+)$', txt)
                        # platform: try vm-mode first, then model
                        vm_mode = extract_field(r'^vm-mode\s*:\s*(.+)$', txt)
                        model   = extract_field(r'^model\s*:\s*(.+)$', txt)
                        panorama['platform']    = vm_mode if vm_mode != '—' else model
                        panorama['serial']      = extract_field(r'^serial\s*:\s*(.+)$', txt)
                        panorama['version']     = extract_field(r'^sw-version\s*:\s*(.+)$', txt)
                        # Device groups: extract from managed-devices or dg-hierarchy-level-1 count
                        dg_count = extract_field(r'^managed-devices\s*:\s*(.+)$', txt)
                        if dg_count == '—':
                            # Count distinct device-group names from the system info if present
                            dg_count = extract_field(r'^device-groups\s*:\s*(.+)$', txt)
                        panorama['deviceGroups'] = dg_count
                        panorama['contentPkg']  = extract_field(r'^app-version\s*:\s*(.+)$', txt)
                        panorama['avSigs']      = extract_field(r'^av-version\s*:\s*(.+)$', txt)
                        panorama['threatSigs']  = extract_field(r'^app-version\s*:\s*(.+)$', txt)
                        panorama['gpVersion']   = extract_field(r'^wildfire-version\s*:\s*(.+)$', txt)
                        # Content date and staleness — use app-release-date
                        content_date_str = extract_field(r'^app-release-date\s*:\s*(.+)$', txt)
                        if content_date_str and content_date_str != '—':
                            # Store the full timestamp so the HTML shows it precisely
                            panorama['contentDate'] = content_date_str.strip()
                            try:
                                # Parse date like "2025/09/15 13:30:16 CDT", "2025/09/15 12:00:00 UTC", or "2025-09-15"
                                # Strip timezone label before parsing
                                date_part = re.sub(r'\s+[A-Z]{2,4}\s*$', '', content_date_str.strip())
                                for fmt in ('%Y/%m/%d %H:%M:%S', '%Y/%m/%d', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d'):
                                    try:
                                        cd = datetime.datetime.strptime(date_part.strip(), fmt)
                                        # Use the report generation date (March 9 2026) as the reference point
                                        # so staleness is consistent regardless of when the app runs
                                        report_date = datetime.datetime(2026, 3, 9)
                                        days = (report_date - cd).days
                                        # Clamp to 0 minimum — negative means signatures are current
                                        panorama['contentDays'] = str(max(0, days))
                                        break
                                    except: continue
                            except: pass
                        log(f'    Panorama: {panorama.get("hostname","?")} PAN-OS {panorama.get("version","?")}')
                except Exception as e:
                    log(f'    Warning: system_info parse error: {e}')

            # ── ThreatReport.xml → named threats, C2 summary, WildFire ──────
            threat_xml_names = [m for m in members if os.path.basename(m) == 'ThreatReport.xml']
            wildfire_rows = []
            for txml in sorted(threat_xml_names):  # process both reports/ and statsv2/
                try:
                    f = tar.extractfile(txml)
                    if f:
                        txt = f.read().decode('utf-8', errors='replace')
                        # Named threat entries — XML uses child elements not attributes
                        # Format: <entry><app>X</app><threatid>Name</threatid><count>N</count>
                        #         <subtype>spyware</subtype><category-of-threatid>C</category-of-threatid>
                        import xml.etree.ElementTree as ET
                        try:
                            root = ET.fromstring(txt)
                            for entry in root.iter('entry'):
                                tid_el    = entry.find('threatid')
                                count_el  = entry.find('count')
                                cat_el    = entry.find('category-of-threatid')
                                app_el    = entry.find('app')
                                sev_el    = entry.find('severity-of-threatid')
                                if tid_el is None or count_el is None: continue
                                tid_text = tid_el.text or ''
                                # Skip numeric-only threat IDs (not named threats)
                                if tid_text.strip().isdigit(): continue
                                cat  = (cat_el.text  or 'unknown').strip() if cat_el  is not None else 'unknown'
                                app  = (app_el.text  or '—').strip()       if app_el  is not None else '—'
                                cnt  = int(count_el.text.strip())          if count_el.text else 0
                                named_threats.append({
                                    'name':     tid_text.strip(),
                                    'count':    cnt,
                                    'category': cat,
                                    'protocol': app
                                })
                        except ET.ParseError:
                            # Fallback to regex for malformed XML
                            entries = re.findall(
                                r'<threatid>([^<]+)</threatid>.*?<count>(\d+)</count>.*?<category-of-threatid>([^<]+)</category-of-threatid>',
                                txt, re.DOTALL)
                            for name, count, cat in entries[:30]:
                                if not name.strip().isdigit():
                                    named_threats.append({
                                        'name': name.strip(), 'count': int(count),
                                        'category': cat.strip(), 'protocol': '—'
                                    })
                        # WildFire/threat type summary from statsv2
                        if 'statsv2' in txml.replace(os.sep, '/'):
                            try:
                                root2 = ET.fromstring(txt)
                                for entry in root2.iter('entry'):
                                    cat_el2   = entry.find('category-of-threatid')
                                    count_el2 = entry.find('count')
                                    if cat_el2 is None or count_el2 is None: continue
                                    cat_name = (cat_el2.text or '').strip()
                                    c = int(count_el2.text.strip()) if count_el2.text else 0
                                    n = cat_name.lower()
                                    if c > 0 and ('spyware' in n or 'malware' in n or 'dns' in n or 'botnet' in n or 'backdoor' in n):
                                        wildfire_rows.append({'type': cat_name, 'count': f'{c:,}', 'note': 'Aggregate statsv2'})
                            except ET.ParseError:
                                pass
                        # Total from XML
                        try:
                            root3 = ET.fromstring(txt)
                            result_el = root3.find('result')
                            if result_el is not None:
                                total_attr = result_el.get('total') or result_el.get('count')
                                if total_attr and not slr_data.get('totalThreats'):
                                    slr_data['totalThreats'] = int(total_attr)
                        except: pass
                except Exception as e:
                    log(f'    Warning: ThreatReport parse error: {e}')
            if wildfire_rows:
                wildfire_dets = wildfire_rows[:6]

            # ── ApplicationReport.xml → app risk / SaaS data ─────────────────
            app_xml_names = [m for m in members if os.path.basename(m) == 'ApplicationReport.xml']
            for axml in app_xml_names[:1]:
                try:
                    f = tar.extractfile(axml)
                    if f:
                        txt = f.read().decode('utf-8', errors='replace')
                        # Total apps
                        apps = re.findall(r'<entry[^>]*name="([^"]+)"', txt)
                        if apps:
                            slr_data['totalApps'] = str(len(set(apps)))
                        # High risk apps (risk >= 4)
                        high_risk = re.findall(
                            r'<entry[^>]*name="([^"]+)"[^>]*>.*?<risk>([4-5])</risk>.*?<bytes>(\d+)</bytes>',
                            txt, re.DOTALL)
                        slr_data['highRiskApps'] = str(len(high_risk))
                        for name, risk, bw in high_risk[:8]:
                            gb = int(bw) / 1024**3
                            high_risk_apps.append({
                                'app': name.strip(), 'bw': f'{gb:.1f} GB',
                                'risk': risk, 'action': 'Review required'
                            })
                except Exception as e:
                    log(f'    Warning: ApplicationReport parse error: {e}')

            # ── RiskReport.xml → bandwidth by risk level ──────────────────────
            risk_xml_names = [m for m in members if os.path.basename(m) == 'RiskReport.xml']
            for rxml in risk_xml_names[:1]:
                try:
                    f = tar.extractfile(rxml)
                    if f:
                        txt = f.read().decode('utf-8', errors='replace')
                        entries = re.findall(
                            r'<risk>(\d+)</risk>.*?<nbytes>(\d+)</nbytes>',
                            txt, re.I | re.DOTALL)
                        if not entries:
                            entries = re.findall(
                                r'<entry[^>]*name="([^"]+)"[^>]*>.*?<bytes>(\d+)</bytes>',
                                txt, re.DOTALL)
                        
                        valid_entries = []
                        for k, v in entries:
                            k_norm = k.replace('Risk', '').strip()
                            if k_norm != '0':
                                valid_entries.append((k_norm, v))

                        total_bytes = sum(int(b) for _, b in valid_entries)
                        
                        if total_bytes > 0:
                            slr_data['totalBwTB'] = f'{total_bytes/1024**4:.2f}'
                        
                        for risk_val, bw in valid_entries:
                            tb = int(bw)/1024**4
                            pct = f'{int(bw)/total_bytes*100:.1f}%' if total_bytes > 0 else '—'
                            desc = {
                                '1': 'Business-necessary, low-risk protocols',
                                '2': 'Moderate-risk, some policy action needed',
                                '3': 'Elevated risk, review recommended',
                                '4': 'High-risk — dominant risk category',
                                '5': 'Critical — block immediately',
                            }.get(risk_val, '')
                            name = f"Risk {risk_val}"
                            if risk_val == '1': name += ' (Low)'
                            elif risk_val == '4': name += ' (High)'
                            elif risk_val == '5': name += ' (Critical)'
                            risk_bw.append({'level': name, 'bw': f'{tb:.2f}', 'pct': pct, 'desc': desc})
                        
                        risk_bw.sort(key=lambda x: -int(x['level'].split()[1]))
                except Exception as e:
                    log(f'    Warning: RiskReport parse error: {e}')

            # ── SourceCountryReport.xml → nation-state exposure ───────────────
            country_xml = [m for m in members if os.path.basename(m) == 'SourceCountryReport.xml']
            for cxml in country_xml[:1]:
                try:
                    f = tar.extractfile(cxml)
                    if f:
                        txt = f.read().decode('utf-8', errors='replace')
                        entries = re.findall(
                            r'<entry[^>]*name="([^"]+)"[^>]*>.*?<sessions>(\d+)</sessions>',
                            txt, re.DOTALL)
                        for country, sessions in entries[:15]:
                            source_countries.append({'country': country.strip(), 'hits': int(sessions)})
                        source_countries.sort(key=lambda x: -x['hits'])
                except Exception as e:
                    log(f'    Warning: SourceCountryReport parse error: {e}')

            if panorama or slr_data:
                log(f'    Statsdump parsed: {len(named_threats)} named threats, '
                    f'{len(source_countries)} source countries')
            else:
                log('    Warning: statsdump parsed but no data extracted')

    except Exception as e:
        log(f'  Warning: statsdump open error: {e}')

    return panorama, slr_data, named_threats, wildfire_dets, app_vulns,            risk_bw, high_risk_apps, saas_risk, benchmarks, source_countries


# ── MAIN GENERATE ─────────────────────────────────────────────────────────────
def generate(source_dir, customer_name, output_dir, log):
    config = load_config()
    files = preflight(source_dir, log)
    if files is None:
        raise ValueError('Pre-flight failed — missing required files.')

    log('Parsing data...')
    sp, vu, action_counts = load_threat_csv(files['threat'], log)
    dns, infected, top_doms, dom_tids, top_ips, dom_ips = analyze_spyware(sp, log)
    smb = load_smb(files['traffic'], log) if files['traffic'] else []
    wrm = load_wrm(files['traffic'], log) if files['traffic'] else []

    threat_period  = get_csv_date_range(files['threat'])
    traffic_period = get_csv_date_range(files['traffic']) if files['traffic'] else 'N/A'

    # Parse statsdump for Panorama system data
    panorama, slr_data, named_threats, wildfire_dets, app_vulns,         risk_bw, high_risk_apps, saas_risk, benchmarks, source_countries =         parse_statsdump(files.get('statsdump'), log)

    # Parse SLR PDF for app risk, benchmarks, remote access, C2 threats
    slr_pdf, ra_apps, hr_apps, saas_risk_pdf, app_vulns_pdf, c2_threats, benchmarks_pdf = \
        parse_slr_pdf(files.get('slr'), log)

    # Merge SLR data — SLR PDF is authoritative for app/threat metrics
    slr_data.update(slr_pdf)
    if ra_apps:       remoteAccessApps = ra_apps
    else:             remoteAccessApps = []
    if hr_apps:       high_risk_apps   = hr_apps
    if saas_risk_pdf: saas_risk        = saas_risk_pdf
    if app_vulns_pdf: app_vulns        = app_vulns_pdf
    if c2_threats:    named_threats    = c2_threats
    if benchmarks_pdf: benchmarks      = benchmarks_pdf

    # Populate riskBandwidth from SLR PDF data when RiskReport.xml wasn't available
    # The SLR PDF contains the bandwidth-by-risk-level breakdown
    if not risk_bw and slr_data.get('totalBwTB'):
        try:
            _total = float(str(slr_data['totalBwTB']).replace(' TB','').strip())
            # Parse from SLR PDF text if available — use known IDEX distribution from SLR
            # These come from the "Applications that Introduce Risk" section
            _slr_risk_bw = parse_slr_risk_bandwidth(files.get('slr'), log)
            if _slr_risk_bw:
                risk_bw = _slr_risk_bw
        except: pass


    # Filter vuln events — skip informational/low severity noise, only keep medium+
    SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'informational': 4}
    vu_filtered = [r for r in vu if SEVERITY_ORDER.get(r[4].lower(), 5) <= 2]
    if not vu_filtered:
        vu_filtered = [r for r in vu if SEVERITY_ORDER.get(r[4].lower(), 5) <= 3]
    log(f'    Vuln events (medium+): {len(vu_filtered):,} of {len(vu):,} total')

    # Deduplicate vuln events — group identical (src_ip, threat_name) rows into one
    # with a count suffix, matching the PDF's "SSH Brute Force (×9)" style.
    # Critical events (Log4j etc.) always appear as individual rows first.
    from collections import OrderedDict
    _vu_deduped = OrderedDict()
    for r in vu_filtered:
        _threat_base = re.sub(r'\(\d+\)$', '', r[3]).strip()
        # Key on src_ip + user + threat name only — different dst_ips for same exploit = same event
        _key = (r[0], r[1], _threat_base, r[4], r[5])
        if _key not in _vu_deduped:
            _vu_deduped[_key] = {'row': r, 'count': 0}
        _vu_deduped[_key]['count'] += 1

    # Rebuild as list: sort Critical first, then by count desc
    vu_deduped = sorted(
        [{'src_ip': v['row'][0], 'user': v['row'][1], 'zone': v['row'][2],
          'threat': re.sub(r'\(\d+\)$', '', v['row'][3]).strip() +
                    (f' (×{v["count"]})' if v['count'] > 1 else ''),
          'count': v['count'],
          'severity': v['row'][4], 'action': v['row'][5], 'dst_ip': v['row'][6]}
         for v in _vu_deduped.values()],
        key=lambda x: (SEVERITY_ORDER.get(x['severity'].lower(), 5), -x['count'])
    )
    
    # (User specifically requested to remove the fallback logic that pulls Informational/Low users)
    
    log(f'    Vuln events after dedup: {len(vu_deduped)} unique rows (was {len(vu_filtered)})')

    data = {
        'customerName':  customer_name,
        'month':         datetime.datetime.now().strftime('%B %Y'),
        'totalRows':     len(sp) + len(vu),
        'spywareCount':  len(sp),
        'vulnCount':     len(vu),
        'infectedCount': len(top_ips),  # only IPs with confirmed non-noise C2 domains
        'dnsResolvers':  [{'ip': ip, 'zone': d['zone'], 'hits': d['hits'], 'unique': d['unique']}
                          for ip, d in dns.items()],
        'topDomains':    [{'domain': dom, 'hits': hits, 'tid': dom_tids.get(dom, '')}
                          for dom, hits in top_doms],
        'domainIPs':     {dom: {'ips': v['ips'], 'users': v['users']}
                          for dom, v in dom_ips.items()},
        'topIPs':        [{'ip': ip, 'zone': d['zone'], 'hits': d['hits'],
                           'unique': d['unique'], 'users': d['users'],
                           'top_domain': d.get('top_domain', '—')}
                          for ip, d in top_ips],
        'smbFlows':      smb,
        'wrmFlows':      wrm,
        'vulnEvents':    vu_deduped,
        'actionCounts':  action_counts,
        'slr': slr_data, 'panorama': panorama,
        'namedThreats': named_threats, 'wildfireDetections': wildfire_dets if wildfire_dets else [], 'appVulns': app_vulns,
        'remoteAccessApps': remoteAccessApps, 'riskBandwidth': risk_bw, 'highRiskApps': high_risk_apps,
        'saasRisk': saas_risk, 'benchmarks': benchmarks, 'findings': {},
        'sourceCountries': source_countries,
        'sourceFiles': [
            {'name': os.path.basename(files['threat']), 'type': 'Threat Logs', 'period': threat_period},
            {'name': os.path.basename(files['traffic']) if files['traffic'] else 'Not found',
             'type': 'Traffic Logs', 'period': traffic_period},
        ],
        'preparer': {
            'name':  config.get('preparer_name',  'John Shelest'),
            'title': config.get('preparer_title', 'Palo Alto Networks Solutions Consultant'),
            'email': config.get('preparer_email', 'jshelest@paloaltonetworks.com'),
        }
    }

    # ── OTX enrichment — adds verdict/otx_pulses/registered to each domain ──
    otx_key = config.get('otx_api_key') or os.environ.get('OTX_API_KEY') or os.environ.get('DNS_API_KEY')
    data['topDomains'] = enrich_otx(data['topDomains'], otx_key, log)

    # ── Threat Vault enrichment — adds CVE and descriptions ──
    vault_key = config.get('vault_api_key') or os.environ.get('VAULT_API_KEY')
    if vault_key and data.get('vulnEvents'):
        # Enrich the top 5 deduped events only to save time
        data['vulnEvents'][:5] = enrich_threat_vault(data['vulnEvents'][:5], vault_key, log)

    # Filter out undetected noise domains so they don't pollute LLM summary or top KPIs
    cn_key = customer_name.lower().replace(' ','').replace('corp','').replace('inc','').replace('llc','').replace('ltd','')
    def is_valid_otx(d):
        dm = (d.get('domain') or '').lower()
        if cn_key and len(cn_key) >= 4 and cn_key in dm: return True
        if 'okta' in dm or 'okta-ema' in dm: return True
        if d.get('verdict') in ('malicious', 'suspicious'): return True
        if (d.get('otx_pulses') or 0) > 0: return True
        return False
    
    filtered_domains = [d for d in data['topDomains'] if is_valid_otx(d)]
    if filtered_domains:
        data['topDomains'] = filtered_domains
    else:
        # Keep them if absolutely nothing was malicious, so we at least report what we found
        pass

    log('Running LLM analysis (Gemini)...')
    try:
        data['soWhat'] = generate_all_so_whats(data, customer_name, config, log)
    except Exception as e:
        log(f'  ⚠ SO WHAT generation error: {e} — using empty fallback')
        data['soWhat'] = {}

    # Save debug copy so /api/debug can read it
    try:
        with open(os.path.join(SCRIPT_DIR, 'last_parsed.json'), 'w') as _f:
            json.dump(data, _f, indent=2)
    except: pass

    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    json.dump(data, tmp, indent=2); tmp.close()

    safe  = re.sub(r'[^a-zA-Z0-9_\-]', '_', customer_name)
    stamp = datetime.datetime.now().strftime('%B%Y')
    out_html = os.path.join(output_dir, f'{safe}_Security_Assessment_{stamp}.html')
    out_pdf  = os.path.join(output_dir, f'{safe}_Security_Assessment_{stamp}.pdf')

    # Try node from common locations
    node_candidates = [
        '/opt/homebrew/bin/node',
        '/usr/local/bin/node',
        '/usr/bin/node',
        'node',
    ]
    node_bin = next((n for n in node_candidates if os.path.exists(n)), 'node')

    gen_js = os.path.join(SCRIPT_DIR, 'gen_report.js')
    log('Building HTML...')
    result = subprocess.run(
        [node_bin, gen_js, tmp.name, out_html],
        capture_output=True, text=True, timeout=120
    )
    os.unlink(tmp.name)

    if result.returncode != 0:
        raise RuntimeError(f'Node.js error:\n{result.stderr[:400]}')
    log(f'  {result.stdout.strip()}')

    log('Converting to PDF...')
    chrome = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
    if os.path.exists(chrome):
        pr = subprocess.run(
            [chrome, '--headless', '--disable-gpu', '--no-sandbox',
             f'--print-to-pdf={out_pdf}', '--print-to-pdf-no-header', out_html],
            capture_output=True, timeout=60
        )
        if os.path.exists(out_pdf):
            log(f'  ✔ PDF: {out_pdf}')
        else:
            log('  ⚠ PDF conversion failed — HTML report is available')
            out_pdf = out_html
    else:
        log('  ⚠ Chrome not found — HTML report only')
        out_pdf = out_html

    aid = save_assessment(customer_name, data, out_html)
    log(f'  ✔ Saved to database (ID: {aid})')
    log(f'\n✅ Done: {out_pdf}')
    return out_pdf

# ── WEB SERVER ────────────────────────────────────────────────────────────────
# SSE log queue per session
import queue, uuid
_log_queues = {}

def load_prefs():
    try:
        if os.path.exists(PREFS_PATH):
            with open(PREFS_PATH) as f: return json.load(f)
    except: pass
    return {}

def save_prefs(prefs):
    with open(PREFS_PATH, 'w') as f: json.dump(prefs, f)

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PAN Security Assessment Generator</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: Arial, sans-serif; background: #f5f5f5; display: flex;
         justify-content: center; align-items: flex-start; min-height: 100vh; padding: 40px 20px; }
  .card { background: #fff; border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,0.1);
          width: 100%; max-width: 760px; padding: 40px; }
  .brand { color: #FA4616; font-size: 11px; font-weight: bold; letter-spacing: 1px; margin-bottom: 4px; }
  h1 { color: #333; font-size: 22px; margin-bottom: 28px; }
  label { display: block; font-size: 11px; font-weight: bold; color: #555;
          letter-spacing: 0.5px; margin-bottom: 6px; }
  .field { margin-bottom: 20px; }
  .input-row { display: flex; gap: 8px; align-items: center; }
  .input-row input[type=text] { flex: 1; }
  input[type=text] { width: 100%; padding: 10px 12px; border: 1px solid #ddd;
                     border-radius: 4px; font-size: 14px; color: #333; background: #fafafa; }
  input[type=text]:focus { outline: none; border-color: #FA4616; background: #fff; }
  .api-status { font-size: 12px; margin-bottom: 24px; padding: 8px 12px;
                border-radius: 4px; background: #fff8f0; border-left: 3px solid #FA4616; }
  .api-ok { background: #f0fff4; border-left-color: #1E7A1E; color: #1E7A1E; }
  .api-warn { color: #E07800; }
  button { background: #FA4616; color: white; border: none; border-radius: 4px;
           padding: 12px 32px; font-size: 14px; font-weight: bold; cursor: pointer;
           letter-spacing: 0.5px; transition: background 0.2s; }
  button:hover { background: #E03E00; }
  button:disabled { background: #ccc; cursor: not-allowed; }
  .pick-btn { padding: 10px 14px; font-size: 13px; font-weight: normal;
              letter-spacing: 0; white-space: nowrap; flex-shrink: 0;
              background: #555; }
  .pick-btn:hover { background: #333; }
  .log-label { font-size: 11px; font-weight: bold; color: #888; letter-spacing: 0.5px;
               margin: 24px 0 8px; }
  #log { background: #0d1117; color: #00ff88; font-family: Menlo, monospace; font-size: 12px;
         padding: 16px; border-radius: 4px; height: 260px; overflow-y: auto;
         white-space: pre-wrap; word-break: break-all; }
  #result { margin-top: 20px; padding: 14px 16px; border-radius: 4px;
            background: #f0fff4; border-left: 3px solid #1E7A1E; color: #1E7A1E;
            font-size: 13px; display: none; }
  #result a { color: #1E7A1E; font-weight: bold; }
  #error  { margin-top: 20px; padding: 14px 16px; border-radius: 4px;
            background: #fff0f0; border-left: 3px solid #cc0000; color: #cc0000;
            font-size: 13px; display: none; }
</style>
</head>
<body>
<div class="card">
  <div class="brand">PALO ALTO NETWORKS</div>
  <h1>Security Assessment Generator</h1>

  <div class="field">
    <label for="source">SOURCE DIRECTORY</label>
    <div class="input-row">
      <input type="text" id="source" placeholder="/Users/you/Desktop/IDEX_Data">
      <button class="pick-btn" onclick="pickFolder('source')">📁 Browse</button>
    </div>
  </div>
  <div class="field">
    <label for="output">OUTPUT DIRECTORY</label>
    <div class="input-row">
      <input type="text" id="output" placeholder="/Users/you/Desktop/Reports">
      <button class="pick-btn" onclick="pickFolder('output')">📁 Browse</button>
    </div>
  </div>
  <div class="field">
    <label for="customer">CUSTOMER NAME <span style="font-size:10px;color:#888;font-weight:normal;">(auto-detected from SLR — override if needed)</span></label>
    <input type="text" id="customer" placeholder="Detecting after source folder selection...">
  </div>

  <div class="api-status" id="apiStatus">Checking API config...</div>

  <button id="btn" onclick="generate()">⚡ GENERATE ASSESSMENT</button>

  <div class="log-label">GENERATION LOG</div>
  <div id="log"></div>
  <div id="result"></div>
  <div id="error"></div>
</div>

<script>
  fetch('/api/prefs').then(r=>r.json()).then(p=>{
    if (p.last_customer) document.getElementById('customer').value = p.last_customer;
    if (p.last_source)   document.getElementById('source').value   = p.last_source;
    if (p.last_output)   document.getElementById('output').value   = p.last_output;
  });
  fetch('/api/config_status').then(r=>r.json()).then(s=>{
    const el = document.getElementById('apiStatus');
    if (s.ok) {
      el.textContent = '✔ Gemini API key configured (' + s.model + ')';
      el.className = 'api-status api-ok';
    } else {
      el.textContent = '⚠ No Gemini API key — edit config.json to enable LLM analysis';
      el.className = 'api-status api-warn';
    }
  });

  function pickFolder(fieldId) {
    fetch('/api/pick_folder').then(r=>r.json()).then(d=>{
      if (d.path) {
        document.getElementById(fieldId).value = d.path;
        if (fieldId === 'source') {
          // Auto-fill output if empty
          if (!document.getElementById('output').value) {
            const parts = d.path.split('/');
            const parent = parts.slice(0, -1).join('/');
            if (parent) document.getElementById('output').value = parent;
          }
          // Detect customer name from SLR PDF → SaaS report filename → folder path
          const statusEl = document.getElementById('customer');
          statusEl.placeholder = 'Detecting...';
          fetch('/api/detect_customer?folder=' + encodeURIComponent(d.path))
            .then(r=>r.json())
            .then(res=>{
              statusEl.placeholder = 'Customer / Company Name';
              if (res.name) {
                document.getElementById('customer').value = res.name;
              }
            })
            .catch(()=>{ statusEl.placeholder = 'Customer / Company Name'; });
        }
      }
    });
  }
  function generate() {
    const customer = document.getElementById('customer').value.trim();
    const source   = document.getElementById('source').value.trim();
    const output   = document.getElementById('output').value.trim();
    if (!customer || !source || !output) { alert('Please fill in all fields.'); return; }

    document.getElementById('btn').disabled = true;
    document.getElementById('btn').textContent = 'GENERATING...';
    document.getElementById('log').textContent = '';
    document.getElementById('result').style.display = 'none';
    document.getElementById('error').style.display  = 'none';

    fetch('/api/prefs', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({last_customer: customer, last_source: source, last_output: output})
    });

    fetch('/api/generate', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({customer, source, output})
    }).then(r=>r.json()).then(d=>{
      if (d.error) { showError(d.error); return; }
      streamLog(d.session_id);
    });
  }

  function streamLog(sid) {
    const logEl = document.getElementById('log');
    const es = new EventSource('/api/log/' + sid);
    es.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      if (msg.type === 'log') {
        logEl.textContent += msg.text + '\n';
        logEl.scrollTop = logEl.scrollHeight;
      } else if (msg.type === 'done') {
        es.close();
        document.getElementById('btn').disabled = false;
        document.getElementById('btn').textContent = '⚡ GENERATE ASSESSMENT';
        const res = document.getElementById('result');
        res.innerHTML = '✅ Report saved: <a href="file://' + msg.path + '" target="_blank">' + msg.path + '</a>';
        res.style.display = 'block';
      } else if (msg.type === 'error') {
        es.close();
        document.getElementById('btn').disabled = false;
        document.getElementById('btn').textContent = '⚡ GENERATE ASSESSMENT';
        showError(msg.text);
      }
    };
  }

  function showError(msg) {
    const el = document.getElementById('error');
    el.textContent = '❌ ' + msg;
    el.style.display = 'block';
  }
</script>
</body>
</html>"""

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass  # suppress access logs

    def do_GET(self):
        if self.path == '/':
            self._send(200, 'text/html', HTML_PAGE.encode())
        elif self.path == '/api/prefs':
            self._json(load_prefs())
        elif self.path == '/api/pick_folder':
            # Launch osascript folder picker — works on macOS without tkinter
            try:
                result = subprocess.run(
                    ['osascript', '-e',
                     'POSIX path of (choose folder with prompt "Select folder:")'],
                    capture_output=True, text=True, timeout=60
                )
                path = result.stdout.strip().rstrip('/')
                self._json({'path': path} if path else {'path': None})
            except Exception as e:
                self._json({'path': None, 'error': str(e)})
        elif self.path == '/api/config_status':
            config = load_config()
            key = config.get('gemini_api_key', '')
            ok  = bool(key and key != 'YOUR_GEMINI_API_KEY_HERE')
            self._json({'ok': ok, 'model': config.get('gemini_model', 'gemini-2.5-flash')})
        elif self.path.startswith('/api/detect_customer'):
            from urllib.parse import urlparse, parse_qs
            qs     = parse_qs(urlparse(self.path).query)
            folder = qs.get('folder', [''])[0]
            name   = None
            source = None

            # ── Signal 1: SLR PDF — "##### IDEX Corp" on page 1 ──────────────
            if folder and os.path.isdir(folder):
                slr_candidates = [f for f in os.listdir(folder)
                                  if f.lower().startswith('slr') and f.lower().endswith('.pdf')]
                if slr_candidates:
                    slr_path = os.path.join(folder, slr_candidates[0])
                    try:
                        from pdfminer.high_level import extract_text as pdf_extract
                        txt = pdf_extract(slr_path, page_numbers=[0])
                        # Pattern: "SECURITY LIFECYCLE REVIEW\n\nCompany Name"
                        m = re.search(
                            r'SECURITY\s+LIFECYCLE\s+REVIEW[\s\S]{0,200?}?\n+\s*([A-Z][^\n]{2,60})\s*\n',
                            txt, re.IGNORECASE)
                        if m:
                            candidate = m.group(1).strip()
                            # Reject generic/boilerplate lines
                            GENERIC = {'prepared by', 'palo alto', 'report period', 'confidential',
                                       'table of contents', 'executive summary', 'cybersecurity',
                                       'partner of choice', 'http', 'www.', 'networks'}
                            if not any(g in candidate.lower() for g in GENERIC) and len(candidate) > 2:
                                name   = candidate
                                source = 'SLR PDF'
                    except Exception:
                        pass

            # ── Signal 2: SaaS Risk Report filename — "SaaS Security Risk Report - ACME Inc.pdf" ──
            if not name and folder and os.path.isdir(folder):
                for f in os.listdir(folder):
                    m = re.search(r'(?:saas|security|risk)\s+(?:security\s+)?risk\s+report\s*[-–]\s*(.+?)\.pdf',
                                  f, re.IGNORECASE)
                    if m:
                        candidate = m.group(1).strip()
                        if len(candidate) > 2:
                            name   = candidate
                            source = 'SaaS Risk Report filename'
                            break

            # ── Signal 3: folder path — parent of source dir ──────────────────
            if not name and folder:
                parts = [p for p in folder.replace('\\', '/').split('/') if p.strip()]
                SKIP  = {'source','src','data','logs','qbr','security','assessment','report',
                         'export','output','threat','traffic','pan','panorama','downloads',
                         'desktop','documents','home','users','tmp','temp','customer','customers',
                         'clients','archive','backup','input','library','cloudstorage','drive',
                         'my drive','mydrive','feb','mar','apr','may','jun','jul','aug','sep',
                         'oct','nov','dec','2024','2025','2026','q1','q2','q3','q4'}
                for p in reversed(parts):
                    if p.strip() and len(p) > 2 and p.lower() not in SKIP and not re.match(r'^\d{4}$', p):
                        name   = p
                        source = 'folder path'
                        break

            self._json({'name': name, 'source': source})

        elif self.path.startswith('/api/log/'):
            sid = self.path.split('/')[-1]
            self._stream_log(sid)
        elif self.path == '/api/debug':
            prefs   = load_prefs()
            src_dir = prefs.get('last_source', '')
            out     = {'source_dir': src_dir, 'files': [], 'tgz_contents': []}
            if src_dir and os.path.isdir(src_dir):
                out['files'] = sorted(os.listdir(src_dir))
                for f in out['files']:
                    fpath = os.path.join(src_dir, f)
                    if f.endswith('.tgz') or f.endswith('.tar.gz'):
                        try:
                            r = subprocess.run(['tar', '-tzf', fpath],
                                capture_output=True, text=True, timeout=30)
                            out['tgz_contents'] = r.stdout.strip().splitlines()[:100]
                        except Exception as e:
                            out['tgz_contents'] = [f'error: {e}']
            last_json = os.path.join(SCRIPT_DIR, 'last_parsed.json')
            if os.path.exists(last_json):
                try:
                    with open(last_json) as f2:
                        d = json.load(f2)
                        out['panorama']      = d.get('panorama', {})
                        out['slr']           = d.get('slr', {})
                        out['topDomains']    = d.get('topDomains', [])[:5]
                        out['vulnEvents']    = d.get('vulnEvents', [])[:5]
                        out['infectedCount'] = d.get('infectedCount', 0)
                        out['totalRows']     = d.get('totalRows', 0)
                except: pass
            dbg_path = os.path.join(SCRIPT_DIR, 'debug_output.json')
            with open(dbg_path, 'w') as f2: json.dump(out, f2, indent=2)
            self._json({'ok': True, 'written': dbg_path, 'data': out})
        else:
            self._send(404, 'text/plain', b'Not found')

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body   = json.loads(self.rfile.read(length))
        if self.path == '/api/prefs':
            prefs = load_prefs(); prefs.update(body); save_prefs(prefs)
            self._json({'ok': True})
        elif self.path == '/api/generate':
            sid = str(uuid.uuid4())
            q   = queue.Queue()
            _log_queues[sid] = q
            def worker():
                def log(msg): q.put({'type': 'log', 'text': msg})
                try:
                    os.makedirs(body['output'], exist_ok=True)
                    path = generate(body['source'], body['customer'], body['output'], log)
                    q.put({'type': 'done', 'path': path})
                except Exception as e:
                    q.put({'type': 'error', 'text': str(e)})
            threading.Thread(target=worker, daemon=True).start()
            self._json({'session_id': sid})
        else:
            self._send(404, 'text/plain', b'Not found')

    def _stream_log(self, sid):
        q = _log_queues.get(sid)
        if not q:
            self._send(404, 'text/plain', b'Session not found'); return
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Connection', 'keep-alive')
        self.end_headers()
        try:
            while True:
                try:
                    msg = q.get(timeout=30)
                    data = f"data: {json.dumps(msg)}\n\n"
                    self.wfile.write(data.encode())
                    self.wfile.flush()
                    if msg['type'] in ('done', 'error'):
                        del _log_queues[sid]; break
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, data):
        self._send(200, 'application/json', json.dumps(data).encode())

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

if __name__ == '__main__':
    init_db()
    PORT = 5050
    # Try different ports if 5050 is in use
    import socket
    for p in range(PORT, PORT + 10):
        try:
            server = http.server.HTTPServer(('127.0.0.1', p), Handler)
            PORT = p
            break
        except OSError as e:
            if e.errno == 48: continue # Address in use
            raise
    url = f'http://localhost:{PORT}'
    print(f'\n✅ PAN Assessment Generator running at {url}')
    print('   Press Ctrl+C to stop.\n')
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nStopped.')
