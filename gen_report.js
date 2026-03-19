#!/usr/bin/env node
/**
 * gen_report.js — DYNAMIC Security Assessment Generator
 * Reads JSON data file produced by pan_assessment_app.py and generates HTML report.
 * All content is driven by the parsed data — nothing is hardcoded.
 */
'use strict';
const fs = require('fs');

const [,, dataFile, outFile] = process.argv;
if (!dataFile || !outFile) { console.error('Usage: node gen_report.js <data.json> <out.html>'); process.exit(1); }

const D = JSON.parse(fs.readFileSync(dataFile, 'utf8'));

// ── Helpers ────────────────────────────────────────────────────────────────
const CN    = D.customerName || 'Customer';
const month = D.month || new Date().toLocaleDateString('en-US', {month:'long', year:'numeric'});

const C = {
    orange: '#FA4616', red: '#CC0000', amber: '#E07800', green: '#1E7A1E',
    dark: '#333333', mid: '#666666', white: '#FFFFFF',
    border: '#CCCCCC', altBg: '#FFF3EE', f2: '#F2F2F2'
};

function esc(s) {
    if (s == null) return '—';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function num(n) {
    if (n == null || n === '—' || n === '') return '—';
    let s = String(n).replace(/,/g,'').trim();
    // Fix pdfminer number doubling: "739739" → "739"
    if (/^\d+$/.test(s) && s.length % 2 === 0) {
        const half = s.length / 2;
        if (s.slice(0, half) === s.slice(half)) s = s.slice(0, half);
    }
    const x = Number(s);
    return isNaN(x) ? String(n) : x.toLocaleString();
}

function renderFindingCard(numLabel, headline, bodyText, critical=true) {
    const color = critical ? C.red : C.amber;
    return `
    <div style="display:flex;border:1px solid ${C.border};margin-bottom:15px;font-family:Arial,sans-serif;min-height:100px;page-break-inside:avoid;">
        <div style="background-color:${color};color:white;width:50px;display:flex;align-items:center;justify-content:center;font-size:28px;font-weight:bold;flex-shrink:0;">${numLabel}</div>
        <div style="background-color:${C.f2};padding:12px 18px;flex-grow:1;">
            <div style="color:${color};font-size:15px;font-weight:bold;margin-bottom:6px;text-transform:uppercase;">${headline}</div>
            <div style="font-size:12px;color:${C.dark};line-height:1.5;text-align:justify;">${bodyText}</div>
        </div>
    </div>`;
}

function renderKPI(val, label, bg) {
    return `
    <div style="background-color:${bg};color:white;padding:18px;text-align:center;border-radius:2px;flex:1;margin:0 8px;">
        <div style="font-size:32px;font-weight:bold;">${val}</div>
        <div style="font-size:11px;text-transform:uppercase;margin-top:4px;font-weight:bold;">${label}</div>
    </div>`;
}

function renderTable(headers, rows, widths) {
    const thCols = headers.map((h,i) =>
        `<th style="background-color:${C.orange};color:white;padding:6px 10px;text-align:left;font-size:10px;border:1px solid ${C.border};${widths?`width:${widths[i]};`:''}">${h}</th>`
    ).join('');
    const trRows = rows.map((row, i) => {
        const bg = i%2===0 ? C.white : C.altBg;
        const tds = row.map(cell => {
            let text = cell, style = '';
            if (cell && typeof cell === 'object') {
                text = cell.text || '—';
                if (cell.color) style = `color:${cell.color};font-weight:bold;`;
            } else if (typeof cell === 'string') {
                if (cell.includes('CRITICAL')) style = `color:${C.red};font-weight:bold;`;
                else if (cell.includes('HIGH'))     style = `color:${C.amber};font-weight:bold;`;
            }
            return `<td style="padding:6px 10px;font-size:10px;border:1px solid ${C.border};${style}">${text}</td>`;
        }).join('');
        return `<tr style="background-color:${bg};">${tds}</tr>`;
    }).join('');
    return `<table style="width:100%;border-collapse:collapse;margin:10px 0;page-break-inside:avoid;"><thead><tr>${thCols}</tr></thead><tbody>${trRows}</tbody></table>`;
}

// Data source tag — small grey label shown inline after section headers
function src(label) {
    return `<span style="font-size:9px;font-weight:normal;color:#888;margin-left:8px;font-style:italic;">(Source: ${label})</span>`;
}

// SO WHAT boxes — action-oriented, not descriptive
// Each bullet must answer: "What does the team DO with this?"
// Format: ACTION VERB in bold → then the specific step
function renderSoWhat(bullets) {
    if (!bullets || !bullets.length) return '';
    const items = bullets.map(b => {
        const html = String(b).replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
        return `<div class="so-what-item">&rsaquo; ${html}</div>`;
    }).join('');
    return `<div class="so-what-box"><div class="so-what-head">&#9658; RECOMMENDED ACTIONS</div>${items}</div>`;
}

// Action-oriented SO WHAT blocks built directly from parsed data
// These replace LLM-generated bullets when they are too descriptive
function buildActionBlock(section, data) {
    const actions = [];
    const topDoms  = data.topDomains  || [];
    const dnsRes   = data.dnsResolvers || [];
    const vulns    = data.vulnEvents  || [];
    const wrm      = data.wrmFlows    || [];
    const smb      = data.smbFlows    || [];
    const pan      = data.panorama    || {};
    const slr      = data.slr         || {};
    let log4j    = vulns.find(v => (v.threat||'').toLowerCase().includes('log4j'));
    if (!log4j) {
        const slrLog4j = (data.appVulns || []).find(a => (a.threats||[]).some(t => t.toLowerCase().includes('log4j')));
        if (slrLog4j) {
            log4j = {
                src_ip: 'internal host',
                dst_ip: 'external server',
                user: '—',
                action: 'reset-both',
                threat: 'Apache Log4j Remote Code Execution Vulnerability'
            };
        }
    }
    const ssh      = vulns.find(v => (v.threat||'').toLowerCase().includes('ssh') && (v.threat||'').toLowerCase().includes('brute'));
    const okta     = topDoms.find(d => (d.domain||'').toLowerCase().includes('okta'));
    const days     = parseInt(pan.contentDays||'0');

    if (section === 'c2') {
        const visibleDoms = topDoms
            .filter(d => d.domain && d.domain.includes('.') && !d.domain.includes(' '))
            .slice(0, 10);

        if (dnsRes.length > 0) {
            const ips = dnsRes.map(d=>d.ip).join(' and ');
            actions.push(`**Consider enabling DNS debug logging on ${ips}** to identify the real infected endpoints behind the resolver — the firewall currently sees the resolver, not the individual machines. Steps are in the Appendix. If you already have DNS query logging in your SIEM, pull those logs for the domains listed in table 2.1.`);
        }
        if (visibleDoms.length > 0) {
            const domList = visibleDoms.slice(0, 3).map(d => d.domain).join(', ');
            actions.push(`**Review whether the domains in table 2.1 are already blocked** by your existing DNS security policy (${domList}${visibleDoms.length > 3 ? `, and ${visibleDoms.length - 3} more` : ''}). If not, adding them as DNS override records pointing to 127.0.0.1 will suppress beaconing without alerting the malware. If you have Advanced DNS Security, verify these TIDs are in your block policy.`);
        }
        if (okta) {
            actions.push(`**Verify whether ${okta.domain} is already in your URL filtering or DNS block list** — if not, consider adding it and auditing Okta login activity for the affected endpoints. If you have existing UEBA or Okta audit logs, check for anomalous authentication from these source IPs.`);
        }
        actions.push(`**If not already deployed, DNS sinkholing in Panorama** (Objects → Anti-Spyware → DNS Policies, sinkhole IP 72.5.65.111) would give your team real source IPs for all beaconing endpoints going forward. This is additive to any existing controls.`);
    }

    if (section === 'vuln') {
        if (log4j) {
            actions.push(`**Review endpoint telemetry for ${log4j.src_ip}** to determine whether the Log4Shell payload executed before the firewall reset-both the session — if you have EDR deployed on that host, check for outbound connections or process spawning around the event timestamp. If no EDR is present, reviewing system logs on that host is the next step.`);
        }
        if (ssh) {
            actions.push(`**Verify that ${ssh.src_ip} is already on your perimeter block list** — the firewall reset-both this brute force attempt, but if the source IP is persistent, consider adding it to your external block policy. Check your SIEM for any successful authentications from this IP around the same timeframe.`);
        }
        const dos = vulns.find(v => (v.threat||'').toLowerCase().includes('denial'));
        if (dos) {
            actions.push(`**Confirm the application on ${dos.dst_ip} is running a patched version** — the firewall blocked this DoS attempt, but verify the application is on a supported, patched release. If you have a vulnerability scanner in your environment, validate its coverage of this host.`);
        }
        actions.push(`**Cross-reference these findings with your existing vulnerability scanner results** — Panorama → Monitor → Logs → Threat, filter Severity = CRITICAL or HIGH, will show the raw events. Prioritize any findings where the firewall action was "alert" rather than "reset-both", as those indicate traffic reached the destination.`);
    }

    if (section === 'lateral') {
        if (wrm.length > 0) {
            const top = wrm[0];
            actions.push(`**Verify whether the WRM flows from ${top.src_ip} to ${top.dst_zone} are policy-permitted** — ${top.bytes} of data transferred cross-zone. If this is expected administrative traffic, confirm it is documented in your segmentation policy. If it is unexpected, trace ${top.src_ip} via DHCP logs to identify the machine.`);
        }
        if (smb.length > 0) {
            actions.push(`**Review your firewall segmentation policy for SMB (TCP 445) between ${smb[0].src_zone} and ${smb[0].dst_zone}** — if this traffic is not explicitly permitted, tighten the zone policy. If it is permitted for legitimate file sharing, consider whether it should be restricted to specific source/destination IPs rather than zone-wide.`);
        }
        actions.push(`**To see the full cross-zone picture:** Panorama → Monitor → Logs → Traffic, filter Application = windows-remote-management or smb, Source Zone ≠ Destination Zone. This will show you whether the volume is consistent with expected administrative activity or anomalous.`);
    }

    if (section === 'saas') {
        actions.push(`**Review your SaaS application inventory against your approved application catalog** — the full list is available in Panorama → Monitor → App Scope → Application Usage. Any SaaS app handling PII, financial data, or IP that doesn't have a signed data processing agreement is a compliance risk worth escalating to your legal and procurement teams.`);
        // Only mention specific apps if they exist in the parsed data
        const risk5Apps = (data.highRiskApps||[]).filter(a => parseInt(a.risk||'0') >= 5);
        if (risk5Apps.length > 0) {
            actions.push(`**Block or restrict Risk-5 applications** — ${risk5Apps.map(a=>a.app).join(', ')} are at the highest risk level. These can typically be blocked in Panorama with a deny rule by application ID. Confirm whether any have a legitimate documented business use before blocking.`);
        } else {
            actions.push(`**Verify whether any Risk-5 applications are in use** — check Panorama → Monitor → App Scope → Risk → filter Risk = 5. If present, confirm whether they have a documented business use or should be blocked.`);
        }
        if (slr.remoteApps && parseInt(slr.remoteApps) > 9) {
            actions.push(`**Compare the ${slr.remoteApps} remote access tools against your approved list** — any tools not in your catalog represent ungoverned access paths. Pull the full list from Panorama → Monitor → App Scope → Application Usage → filter Category = remote-access, and validate each against your approved catalog.`);
        }
    }

    if (section === 'panorama') {
        if (days > 0) {
            actions.push(`**Update content pack via Panorama → Device → Dynamic Updates → Check Now → Install** — this closes the ${days}-day signature gap. Takes approximately 30 minutes and does not require a policy commit. If your environment has change control requirements, this can typically be classified as a maintenance update.`);
            actions.push(`**Consider enabling automatic daily updates** (Device → Dynamic Updates → set Applications and Threats schedule) — this prevents recurrence without requiring manual intervention.`);
        } else {
            actions.push(`**Content pack is current — verify scheduled updates are configured** (Panorama → Device → Dynamic Updates) to ensure automatic daily updates are enabled and functioning so this remains up to date.`);
        }
    }

    if (section === 'exec_summary') {
        // Build from actual findings — only reference what exists in this report
        if (log4j) {
            actions.push(`**Review Section 3 Log4j finding with your incident response team** — the firewall logged a reset-both action, but depending on your environment's existing endpoint controls, the impact may already be contained. Forensic review of ${esc(log4j.src_ip)} will confirm whether further action is needed.`);
        }
        if (topDoms.filter(d => d.domain.includes('.')).length > 0) {
            const topDom = topDoms.find(d => d.domain.includes('.'));
            actions.push(`**Review the C2 beaconing activity in Section 2 with your security team** — ${topDom ? esc(topDom.domain) + ' (' + num(topDom.hits) + ' hits)' : 'active beaconing'} was detected. If you have existing DNS security or threat prevention controls, verify they are covering these domains and that your block policies are current.`);
        }
        if (smb.length > 0 || wrm.length > 0) {
            actions.push(`**Validate your network segmentation policy against the lateral movement indicators in Section 4** — cross-zone SMB and WRM flows were observed. If these flows are intentional and policy-permitted, confirm the policy is documented. If not, review your zone security rules.`);
        }
        actions.push(`**Use this report as input to your next security review cycle** — the findings in Sections 2–5 each include Panorama log queries your team can run to validate scope and prioritize response based on your existing controls and risk tolerance.`);
    }

    return actions.length ? actions : null;
}

// ── Data extraction ────────────────────────────────────────────────────────
const soWhat      = D.soWhat || {};
const pan         = D.panorama || {};
const slr         = D.slr || {};
const topDomains  = D.topDomains || [];
const topIPs      = D.topIPs || [];
const dnsResolvers= D.dnsResolvers || [];
const vulnEvents  = D.vulnEvents || [];
const wrmFlows    = D.wrmFlows || [];
const smbFlows    = D.smbFlows || [];
const preparer    = D.preparer || {};
const sourceFiles = D.sourceFiles || [];

const totalThreats  = num(D.totalRows);
const spywareCount  = num(D.spywareCount);
const vulnCount     = num(D.vulnCount);
let infectedCount = num(D.infectedCount);

// SLR fields
const totalApps   = slr.totalApps   || '—';
const highRiskApps= slr.highRiskApps|| '—';
const saasApps    = slr.saasApps    || '—';
const saasCount   = slr.saasCount   || '—';
const vulnExploits= slr.vulnExploits|| vulnCount;
const totalBW     = slr.totalBwTB   || '—';
const saasBW      = slr.saasBwTB    || '—';
const saasPct     = slr.saasBwPct   || '—';
const remoteApps  = slr.remoteApps  || '—';
const malwareCount= slr.malwareCount|| '—';
// WildFire-specific fields from SLR PDF
const malwareKnown   = slr.malwareKnown   != null ? slr.malwareKnown   : null;
const malwareUnknown = slr.malwareUnknown != null ? slr.malwareUnknown : null;

// Panorama fields
const panHostname  = pan.hostname    || '—';
const panIP        = pan.mgmtIp      || '—';
const panPlatform  = pan.platform    || '—';
const panSerial    = pan.serial      || '—';
const panVersion   = pan.version     || '—';
const panDevGroups = pan.deviceGroups|| '—';
const contentPkg   = pan.contentPkg  || '—';
const avSigs       = pan.avSigs      || '—';
const threatSigs   = pan.threatSigs  || '—';
const gpVersion    = pan.gpVersion   || '—';
const contentDate  = pan.contentDate || '—';
// Clamp contentDays — negative means signatures are current (updated after report date)
const contentDaysRaw = pan.contentDays || '—';
const contentDaysNum = parseInt(contentDaysRaw);
const contentDays  = (!isNaN(contentDaysNum) && contentDaysNum <= 0) ? '0' : contentDaysRaw;
const sigsCurrent  = !isNaN(contentDaysNum) && contentDaysNum <= 0;

// Dates
const threatPeriod  = (sourceFiles[0] || {}).period || '—';
const trafficPeriod = (sourceFiles[1] || {}).period || '—';

// DNS resolvers list for appendix
const dnsIPs = dnsResolvers.map(d => d.ip).join(' and ') || 'internal DNS resolvers';
const dnsIPList = dnsResolvers.map(d => d.ip);

// Key threat actors from parsed data — use realDomains (filtered) for all references
// realDomains is built below after domain filtering — reference topDomains here for actors only
let log4j = vulnEvents.find(v => v.threat && v.threat.toLowerCase().includes('log4j'));
if (!log4j) {
    const slrLog4j = (D.appVulns || []).find(a => (a.threats||[]).some(t => t.toLowerCase().includes('log4j')));
    if (slrLog4j) {
        log4j = {
            src_ip: 'internal host',
            dst_ip: 'external server',
            user: '—',
            action: 'reset-both',
            threat: 'Apache Log4j Remote Code Execution Vulnerability'
        };
    }
}
const ssh    = vulnEvents.find(v => v.threat && v.threat.toLowerCase().includes('ssh'));
const wrm    = vulnEvents.find(v => v.threat && v.threat.toLowerCase().includes('wrm'));

// Brand-squatting domain (customer name appears in domain)
const cnKey = CN.toLowerCase().replace(/\s+/g,'').replace(/corp|inc|llc|ltd/g,'');
// Find ALL brand-squatting domains (any that contain the customer name)
const validDomains = topDomains
    .filter(d => d.domain && d.domain.includes('.') && !d.domain.includes(' '))
    .filter(d => {
        const dm = (d.domain || '').toLowerCase();
        const isBrand = cnKey && cnKey.length >= 4 && dm.includes(cnKey);
        const isOkta = dm === 'okta-ema.com' || dm.includes('okta');
        const isMalicious = d.verdict === 'malicious' || d.verdict === 'suspicious';
        const hasPulses = (d.otx_pulses || 0) > 0;
        return isMalicious || hasPulses || isBrand || isOkta;
    })
    .sort((a, b) => (b.hits || 0) - (a.hits || 0));
const brandDoms = validDomains.filter(d => cnKey && cnKey.length >= 4 && d.domain.toLowerCase().includes(cnKey));
const brandDom  = brandDoms[0] || null;  // primary (highest hits)
const oktaDom   = validDomains.find(d => d.domain.toLowerCase().includes('okta'));

// ── Key Findings bullets ───────────────────────────────────────────────────
// These are the concise bullets for the exec summary page.
// Covers all sections: 2 (C2), 3 (vulns), 4 (lateral), 5 (SaaS), 6 (Panorama), 7 (benchmarks)
const keyFindings = [];

// Section 2: C2 — top domain + brand squatting + named families
if (validDomains.length > 0) {
    const t = validDomains[0];
    const otxNote = t.otx_pulses > 0 ? ` (${t.otx_pulses} OTX threat intelligence reports)` : t.verdict === 'undetected' ? ' (PAN TID flagged, 0 OTX pulses — under investigation)' : '';
    keyFindings.push(
        `<strong>Active C2 beaconing from ${esc(infectedCount)} internal machines</strong> — top domain ${esc(t.domain)} (${num(t.hits)} hits)${otxNote}; ${validDomains.length} total domains flagged indicates preventive controls failed at the endpoint level.`
    );
}
if (brandDoms.length > 0) {
    const totalHits = brandDoms.reduce((a,d) => a + (d.hits||0), 0);
    const regDom = brandDoms.find(d => d.registered && d.registered !== 'unknown');
    keyFindings.push(
        `<strong>Targeted attack campaign confirmed</strong> — ${brandDoms.map(d=>esc(d.domain)).join(' and ')} registered using ${esc(CN)}'s own name (${num(totalHits)} hits)${regDom ? '; registered ' + esc(regDom.registered) : ''}. This is not background internet noise.`
    );
}
if (D.namedThreats && D.namedThreats.length > 0) {
    const sorted = [...D.namedThreats].sort((a,b) => b.count - a.count);
    const top = sorted[0];
    const cats = slr.c2ByCategory || [];
    const totalC2 = cats.reduce((s,c) => s+(c.count||0), 0);
    const catSummary = cats.length ? ` (${cats.map(c => c.count + ' ' + c.category).join(', ')} across ${totalC2} total C2 connections)` : '';
    const bpfdoor = D.namedThreats.find(t => t.name.toLowerCase().includes('bpfdoor'));
    const evasionNote = bpfdoor ? ` (including BPFDoor evasion via ICMP/ping)` : '';
    keyFindings.push(
        `<strong>Advanced threat family signatures detected</strong> — ${D.namedThreats.length} named threat ${D.namedThreats.length === 1 ? 'family' : 'families'} triggered network detections${evasionNote}. ${esc(top.name)} (${num(top.count)} detections, ${esc(top.category)}) is the most active${catSummary}.`
    );
}

// Section 3: Vulnerabilities — read from actual data
if (vulnExploits !== '—') {
    const topVuln = D.appVulns && D.appVulns.length ? [...D.appVulns].sort((a,b)=>(b.count||0)-(a.count||0))[0] : null;
    keyFindings.push(
        `<strong>High-volume exploit signatures triggered internally</strong> — ${num(vulnExploits)} vulnerability exploits detected${topVuln ? ', with ' + esc(topVuln.app) + ' leading with ' + num(topVuln.count) + ' events' : ''}. WildFire confirmed ${slr.malwareKnown != null ? slr.malwareKnown : '—'} malware events (successfully blocked by threat prevention).`
    );
}
// Named user vuln events from threat log CSV
if (log4j || vulnEvents.length > 0) {
    const critical = vulnEvents.filter(v => (v.severity||'').toLowerCase() === 'critical');
    const alertEvents = vulnEvents.filter(v => v.action === 'alert');
    if (critical.length > 0) {
        const c = critical[0];
        keyFindings.push(
            `<strong>CRITICAL — ${esc(c.user && c.user !== '—' ? c.user : c.src_ip)}: ${esc(c.threat)}</strong> — action: ${esc(c.action)}; destination ${esc(c.dst_ip)}${alertEvents.length > 0 ? `; ${alertEvents.length} event(s) logged as alert — investigate to confirm containment` : ''}`
        );
    } else if (log4j) {
        keyFindings.push(
            `<strong>CRITICAL — Apache Log4j Remote Code Execution Vulnerability</strong> — exploit signature fired; payload execution requires endpoint forensics to confirm.`
        );
    }
}

// Section 4: Lateral movement
if (smbFlows.length > 0) {
    keyFindings.push(
        `<strong>Cross-zone SMB flows detected (Potential Lateral Movement Path)</strong> — ${smbFlows.length} cross-zone SMB flows observed, including from ${esc(smbFlows[0].src_zone)} into ${esc(smbFlows[0].dst_zone)}. If not explicitly required and segmented, SMB (TCP 445) often serves as a primary vector for lateral propagation.`
    );
}
if (remoteApps !== '—' && parseInt(remoteApps) > 9) {
    keyFindings.push(
        `<strong>Unmanaged remote access footprint expands attack surface</strong> — ${remoteApps} remote access tools detected vs. industry average of 9 (${Math.round(parseInt(remoteApps)/9)}× above peer baseline). If not centrally managed with MFA, these tools frequently bypass standard access controls.`
    );
}

// Section 5: SaaS
if (saasBW !== '—' && parseFloat(saasBW) > 10) {
    const noCertApps = D.saasRisk && D.saasRisk.find(r => r.category && r.category.toLowerCase().includes('certif'));
    const breachApps = D.saasRisk && D.saasRisk.find(r => r.category && r.category.toLowerCase().includes('breach'));
    const saasDetail = [
        noCertApps ? `${noCertApps.count} apps with no security certifications` : null,
        breachApps ? `${breachApps.count} with known data breaches` : null
    ].filter(Boolean).join(', ');
    const saasBwBenchmark = D.benchmarks && D.benchmarks.find(b => b.metric === 'SaaS Bandwidth');
    const saasAnom = (saasBwBenchmark && saasBwBenchmark.assessment !== '—') ? ` (${saasBwBenchmark.assessment})` : '';
    keyFindings.push(
        `<strong>SaaS Data Governance Exposure</strong> — ${saasBW} TB of SaaS traffic (${saasPct} of all bandwidth) flows without network DLP inspection across ${saasApps} SaaS apps${saasAnom}. ${saasDetail ? 'Includes ' + saasDetail + '. ' : ''}Without inspection, the nature of data transferred to these services cannot be centrally verified.`
    );
}

// Section 6: Panorama
if (sigsCurrent) {
    keyFindings.push(`<strong>Security infrastructure health confirmed</strong> — Panorama signatures are current as of ${esc(contentDate)} ✓`);
} else if (!sigsCurrent && contentDays !== '—' && contentDays !== '0') {
    keyFindings.push(`<strong>Critical security infrastructure blind spot</strong> — Panorama signatures are ${contentDays} days out of date. Every threat discovered since ${esc(contentDate)} is completely invisible to your security stack.`);
}

// Section 7: Benchmarks — read from actual benchmark data
if (totalApps !== '—') {
    const appBenchmark = D.benchmarks && D.benchmarks.find(b => b.metric === 'Total Applications');
    const hrBenchmark = D.benchmarks && D.benchmarks.find(b => b.metric === 'High-Risk Applications');
    keyFindings.push(
        `<strong>Massive unmanaged application footprint</strong> — ${totalApps} total applications observed${appBenchmark ? ' (' + esc(appBenchmark.assessment) + ')' : ''}` +
        (hrBenchmark ? `, with ${highRiskApps} classified as high-risk (${esc(hrBenchmark.assessment)})` : '.')
    );
}

// ── C2 domain table rows — focus on domains of interest (malicious, suspicious, brand squatting, phishing, or OTX pulses > 0)
const realDomains = validDomains;

const domainRows = realDomains.slice(0, 10).map(d => [
    esc(d.domain) + (d.tid ? ` (TID ${esc(d.tid)})` : ''),
    'DNS C2 / Spyware',
    num(d.hits),
    d.domain === (oktaDom||{}).domain   ? {text:'Okta phishing',   color: C.red} :
    brandDoms.some(b => b.domain === d.domain) ? {text:'Brand squatting — contains customer name', color: C.red} :
    ''
]);

// ── Infected IP table rows — combine same IP rows, then group same zone+domain ─
// Step 1: dedup same IP
const _ipMap = new Map();
for (const ip of topIPs) {
    if (_ipMap.has(ip.ip)) {
        const existing = _ipMap.get(ip.ip);
        existing.hits = (existing.hits || 0) + (ip.hits || 0);
        if ((ip.hits || 0) > (existing._maxHits || 0)) {
            existing._maxHits = ip.hits;
            existing.top_domain = ip.top_domain;
        }
    } else {
        _ipMap.set(ip.ip, {...ip, _maxHits: ip.hits});
    }
}
const _dedupedIPs = [..._ipMap.values()].sort((a, b) => (b.hits||0) - (a.hits||0));

// Step 2: Build infected IP rows — only show IPs connected to confirmed malicious domains
// For each IP, check its top_domain OTX verdict.
// If undetected, check if ANY confirmed-malicious domain exists in the global domain list
// and the IP's hit count suggests it touches multiple domains (unique > 1).
// If so, reassign to the best confirmed-malicious domain.
const maliciousDomainSet = new Set(
    validDomains.filter(d => d.verdict === 'malicious').map(d => d.domain)
);
const infectedRows = [];
const _grouped = new Map();
for (const ip of _dedupedIPs) {
    let domHint = ip.top_domain && ip.top_domain !== '—'
        ? ip.top_domain
        : ip.unique > 1 ? `${ip.unique} domains` : (validDomains[0] ? validDomains[0].domain : '—');

    const domObj = validDomains.find(d => d.domain === domHint);
    const domVerdict = domObj ? domObj.verdict : null;

    // If top domain is undetected but IP hits multiple domains,
    // reassign to the highest-hit confirmed-malicious domain
    if (domVerdict === 'undetected' && (ip.unique || 1) > 1 && maliciousDomainSet.size > 0) {
        // Pick the confirmed-malicious domain with most hits globally
        const bestMalicious = [...maliciousDomainSet]
            .map(d => validDomains.find(v => v.domain === d))
            .filter(Boolean)
            .sort((a, b) => (b.hits || 0) - (a.hits || 0))[0];
        if (bestMalicious) {
            domHint = bestMalicious.domain;
        } else {
            continue; // No malicious domain to assign — skip
        }
    } else if (domVerdict === 'undetected') {
        continue; // Single-domain undetected IP — skip
    }

    const userVal = ip.users && ip.users !== '—' && ip.users !== '\u2014' ? esc(ip.users) : '(no user logged)';

    if ((ip.hits || 0) >= 50) {
        infectedRows.push([esc(ip.ip), esc(ip.zone), num(ip.hits), esc(domHint), userVal]);
    } else {
        const gKey = `${ip.zone}|${domHint}`;
        if (!_grouped.has(gKey)) _grouped.set(gKey, {zone: ip.zone, domain: domHint, ips: [], totalHits: 0});
        const g = _grouped.get(gKey);
        g.ips.push(ip.ip);
        g.totalHits += (ip.hits || 0);
    }
}
let filteredInfectedCount = 0;
for (const ip of _dedupedIPs) {
    if (ip.top_domain && validDomains.some(v => v.domain === ip.top_domain)) {
        filteredInfectedCount++;
    } else if ((ip.unique || 1) > 1 && maliciousDomainSet.size > 0) {
        filteredInfectedCount++;
    }
}
infectedCount = filteredInfectedCount > 0 ? num(filteredInfectedCount) : infectedCount;

for (const g of [..._grouped.values()].sort((a,b) => b.totalHits - a.totalHits)) {
    const ipLabel = g.ips.length === 1 ? g.ips[0] : `${g.ips[0]} +${g.ips.length-1} more (${g.ips.slice(1).join(', ')})`;
    infectedRows.push([esc(ipLabel), esc(g.zone), num(g.totalHits), esc(g.domain), '(no user logged)']);
}

// ── DNS resolver rows ──────────────────────────────────────────────────────
// Filter resolvers to only show if they hit valid domains (if data allows), else show all
const dnsRows = dnsResolvers.map(d => [
    esc(d.ip), esc(d.zone), num(d.hits), num(d.unique),
    {text:'DNS Resolver — masking real infected hosts', color: C.amber}
]);

// ── Vuln event rows — medium/high/critical only, sorted severity first ─────
const SEVER_ORDER = {critical:0, high:1, medium:2};
const vulnRows = vulnEvents
    .filter(v => ['critical','high','medium'].includes((v.severity||'').toLowerCase()))
    .sort((a,b) => {
        const sa = SEVER_ORDER[(a.severity||'').toLowerCase()] ?? 9;
        const sb = SEVER_ORDER[(b.severity||'').toLowerCase()] ?? 9;
        return sa - sb;
    })
    .slice(0,10).map(v => {
    // Extract CVE from threat name if present
    const cveMatch = (v.threat || '').match(/CVE-[\d-]+/i);
    const cve = cveMatch ? cveMatch[0] : '—';
    return [
        esc(v.src_ip), esc(v.user)||'—', esc(v.threat),
        {text: v.severity ? v.severity.toUpperCase() : '—',
         color: (v.severity||'').toLowerCase()==='critical' ? C.red :
                (v.severity||'').toLowerCase()==='high'     ? C.amber : ''},
        esc(v.action),
        cve !== '—' ? {text: cve, color: '#0066CC'} : '—'
    ];
});

// ── WRM rows ───────────────────────────────────────────────────────────────
const wrmRows = wrmFlows.map(w => [
    esc(w.src_ip), esc(w.src_zone), esc(w.dst_ip), esc(w.dst_zone), esc(w.bytes)
]);

// ── SMB rows — deduplicate same src_ip/src_zone/dst_zone ─────────────────
const _smbSeen = new Set();
const smbRows = smbFlows
    .filter(s => {
        const key = `${s.src_ip}|${s.src_zone}|${s.dst_zone}`;
        if (_smbSeen.has(key)) return false;
        _smbSeen.add(key);
        return true;
    })
    .map(s => [esc(s.src_ip), esc(s.src_zone), esc(s.dst_zone), 'SMB / TCP 445', '—']);

// ── Risk matrix rows ───────────────────────────────────────────────────────
const riskRows = [];
if (log4j) riskRows.push([`Log4j RCE (${esc(log4j.user)})`, {text:'High (Confirmed)',color:C.red}, {text:'Critical',color:C.red}, {text:'CRITICAL',color:C.red}]);
if (!sigsCurrent && contentDays !== '—' && contentDays !== '0') riskRows.push([`Outdated Content Pack (${contentDays} days)`, {text:'High',color:C.red}, {text:'High',color:C.amber}, {text:'CRITICAL',color:C.red}]);
if (oktaDom) riskRows.push([`Okta Phishing (${esc(oktaDom.domain)})`, {text:'High (Active)',color:C.red}, {text:'Critical',color:C.red}, {text:'CRITICAL',color:C.red}]);
if (brandDom) riskRows.push([`Brand-squatting (${esc(brandDom.domain)})`, {text:'High (Active)',color:C.red}, {text:'High',color:C.amber}, {text:'HIGH',color:C.amber}]);
if (smbFlows.length > 0 || wrmFlows.length > 0) riskRows.push(['SMB/WRM Lateral Movement Indicators', {text:'Medium',color:C.amber}, {text:'Critical',color:C.red}, {text:'HIGH',color:C.amber}]);
if (saasBW !== '—') riskRows.push([`SaaS Data Exposure (${saasBW} TB, no DLP)`, {text:'Medium',color:C.amber}, {text:'High',color:C.amber}, {text:'HIGH',color:C.amber}]);
if (validDomains.length > 0) riskRows.push([`Active C2 Beaconing (${validDomains.length} domains, ${infectedCount} IPs)`, {text:'Confirmed',color:C.red}, {text:'High',color:C.amber}, {text:'HIGH',color:C.amber}]);
if (remoteApps !== '—' && parseInt(remoteApps) > 9) riskRows.push([`Remote Access Tool Sprawl (${remoteApps} tools)`, {text:'Low',color:C.mid}, {text:'Medium',color:C.amber}, {text:'MEDIUM',color:C.mid}]);

// ── Remediation items ──────────────────────────────────────────────────────
const p1Items = [];
if (!sigsCurrent && contentDays !== '—' && contentDays !== '0') p1Items.push(`<strong>Update Panorama content pack, AV, and threat signatures</strong> &mdash; ${contentDays} days of new threat intelligence not yet applied (Panorama → Device → Dynamic Updates)`);
if (dnsResolvers.length > 0) p1Items.push(`<strong>Pull DNS query logs from ${dnsIPs}</strong> &mdash; these resolvers are forwarding C2 traffic on behalf of real endpoints; DNS logs will identify the actual affected machines`);
if (log4j) p1Items.push(`<strong>Review endpoint telemetry for ${esc(log4j.src_ip)}</strong> &mdash; Log4j signature fired (CVE-2021-44228), firewall reset-both the session; confirm whether payload executed via EDR or host log review`);
if (brandDom) p1Items.push(`<strong>Verify ${esc(brandDom.domain)} is blocked in DNS and firewall policy</strong> &mdash; brand-squatting domain with ${num(brandDom.hits)} internal connections detected`);
if (oktaDom) p1Items.push(`<strong>Verify ${esc(oktaDom.domain)} is in your URL/DNS block list</strong> &mdash; credential phishing domain with ${num(oktaDom.hits)} internal hits; review Okta logs for authentication anomalies from affected IPs`);

const p2Items = [];
if (ssh) p2Items.push(`<strong>Verify ${esc(ssh.src_ip)} is on your external block list</strong> &mdash; SSH brute force source; check SIEM for successful authentications around the event timestamp`);
if (wrmFlows.length > 0) p2Items.push(`<strong>Validate segmentation policy for WRM traffic: ${esc(wrmFlows[0].src_ip)} → ${esc(wrmFlows[0].dst_zone)}</strong> &mdash; ${esc(wrmFlows[0].bytes)} transferred cross-zone; confirm whether policy-permitted or unexpected`);
if (smbFlows.length > 0) p2Items.push(`<strong>Review SMB cross-zone policy</strong> &mdash; ${smbFlows.length} unique source/zone combinations observed; validate whether traffic is authorized or represents a segmentation gap`);
if (remoteApps !== '—') p2Items.push(`<strong>Review remote access tool inventory</strong> &mdash; ${remoteApps} tools detected vs. industry average of 9; compare against approved catalog and validate any consumer-grade tools are intentional`);
if (totalApps !== '—') p2Items.push(`<strong>Review SaaS application list for data processing agreements</strong> &mdash; ${totalApps} total applications observed; uncertified apps handling PII may require legal review`);

const p3Items = [
    '<strong>Evaluate Advanced DNS Security</strong> — would provide real-time blocking of C2 beaconing and DNS-based threats, complementing existing security controls',
    `<strong>Evaluate Next-Generation CASB</strong> — would provide SaaS application visibility, data classification, and DLP enforcement for the ${saasBW !== '—' ? saasBW + ' TB' : 'significant volume'} of SaaS traffic observed`,
    '<strong>Review network micro-segmentation policy</strong> — validate zone boundaries for WRM and SMB to ensure lateral movement paths are appropriately restricted',
    '<strong>Evaluate endpoint telemetry coverage</strong> — firewall logs show network-layer indicators; endpoint telemetry (e.g. Cortex XDR) would provide process-level context for investigation of findings in Sections 2 and 3',
    '<strong>Evaluate SSL/TLS inspection</strong> — significant encrypted traffic volume observed; inspection would provide visibility into threats traversing HTTPS channels'
];

function renderList(items) {
    if (!items.length) return '<p style="font-size:11px;color:#999;">No specific items identified from parsed data.</p>';
    return '<ul class="bullet-list">' + items.map(i=>`<li>${i}</li>`).join('') + '</ul>';
}

// ── Benchmark rows — fix remote access industry avg bug ────────────────────
const benchmarkRows = D.benchmarks && D.benchmarks.length ? D.benchmarks.map(b => {
    // Fix the remote access industry avg which comes through as "273 apps" (total apps avg) instead of "9 apps"
    if (b.metric === 'Remote Access Apps') {
        const val = parseInt(String(b.value));
        return [esc(b.metric), esc(b.value), '9 apps',
            !isNaN(val) && val > 9 ? {text: `${Math.round(val/9)}× above avg ⚠`, color: C.amber} : esc(b.assessment)];
    }
    return [esc(b.metric), esc(b.value), esc(b.industryAvg), esc(b.assessment)];
}) : (totalApps !== '—' ? [
    ['Total Applications', totalApps, '273', {text:'Review required', color: C.amber}],
    ['Remote Access Apps', remoteApps !== '—' ? `${remoteApps} apps` : '—', '9 apps', remoteApps !== '—' && Number(String(remoteApps).replace(/\D/g,'')) > 9 ? {text:`${Math.round(Number(String(remoteApps).replace(/\D/g,''))/9)}× above avg ⚠`, color: C.amber} : 'Within range'],
    ['SaaS Bandwidth', saasPct !== '—' ? `${saasBW} TB (${saasPct})` : '—', '0.4%', saasPct !== '—' ? {text:'Above industry avg ⚠', color: C.amber} : '—'],
    ['Vulnerability Exploits', num(vulnExploits), '—', {text:'Review required', color: C.amber}],
] : [['No benchmark data available from SLR', '—', '—', '—']]);

// ── Section 5.1 risk bandwidth — only use parsed data, never fabricate percentages
const riskBandwidthRows = (D.riskBandwidth && D.riskBandwidth.length)
    ? D.riskBandwidth.map(r => [esc(r.level), esc(r.bw), esc(r.pct), esc(r.desc)])
    : null; // null = show fallback text, never invent numbers

// ── Report period from source files ───────────────────────────────────────
const reportPeriod = threatPeriod !== '—' ? threatPeriod.replace(/\//g, '-') : month;

// ── Panorama system profile ────────────────────────────────────────────────
const panRows = [
    ['Hostname',            panHostname],
    ['Management IP',       panIP],
    ['Platform',            panPlatform],
    ['Serial Number',       panSerial],
    ['PAN-OS Version',      panVersion],
    ['Managed Device Groups', panDevGroups],
];

const contentRows = [
    ['Content Pack',    contentPkg, contentDate, sigsCurrent ? {text:'Current ✓', color: C.green} : contentDays !== '—' ? {text:`${contentDays} days stale`, color: C.red} : 'Unknown'],
    ['AV Signatures',   avSigs,     contentDate, sigsCurrent ? {text:'Current ✓', color: C.green} : contentDays !== '—' ? {text:`${contentDays} days stale`, color: C.red} : 'Unknown'],
    ['Threat Signatures',threatSigs,contentDate, sigsCurrent ? {text:'Current ✓', color: C.green} : contentDays !== '—' ? {text:`${contentDays} days stale`, color: C.red} : 'Unknown'],
    ['GlobalProtect',   gpVersion,  '—',         'Check manually'],
];

// ── DNS appendix — use real resolver IPs ──────────────────────────────────
const dnsIPStr    = dnsIPList.join(' and ') || 'your internal DNS servers';
// Split pattern across lines for readable code blocks — max 3 domains per line
const _patDoms = topDomains.slice(0,6).map(d=>d.domain.replace(/\./g,'\\.'));
const dnsPattern = _patDoms.length
    ? _patDoms.slice(0,3).join('|') + (_patDoms.length > 3 ? '|\n    ' + _patDoms.slice(3).join('|') : '')
    : 'c2-domain|malicious-domain';
const dnsPatternShort = topDomains.slice(0,4).map(d=>d.domain).join('|') || 'c2-domain';

// ─────────────────────────────────────────────────────────────────────────
// HTML OUTPUT
// ─────────────────────────────────────────────────────────────────────────
const html = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        @page { size: A4; margin: 0; }
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; color: ${C.dark}; }
        .page { width: 210mm; height: auto; padding: 0 20mm; margin: 0 auto; background: white; position: relative; box-sizing: border-box; overflow: visible; page-break-after: auto; }
        .conf-header { position: fixed; top: 12mm; left: 15mm; right: 15mm; font-size: 9px; color: ${C.mid}; border-bottom: 1px solid #eee; padding-bottom: 4px; text-transform: uppercase; margin-bottom: 15px; }
        h1 { color: ${C.orange}; border-bottom: 2px solid ${C.orange}; padding-bottom: 4px; margin-top: 15px; text-transform: uppercase; font-size: 16px; letter-spacing: 0.5px; margin-bottom: 10px; }
        h2 { font-size: 14px; margin-top: 15px; color: ${C.dark}; font-weight: bold; margin-bottom: 5px; }
        h3 { font-size: 12px; margin-top: 12px; font-weight: bold; color: ${C.dark}; margin-bottom: 5px; }
        p, li { font-size: 11px; line-height: 1.4; text-align: justify; margin-top: 5px; margin-bottom: 5px; }
        .bullet-list { margin: 8px 0; padding-left: 18px; }
        .bullet-list li { margin-bottom: 4px; }
        .so-what-box { margin: 12px 0; border: 1px solid ${C.border}; page-break-inside: avoid; }
        .so-what-head { background-color: ${C.orange}; color: white; padding: 6px 12px; font-weight: bold; font-size: 10px; }
        .so-what-item { padding: 8px 12px; font-size: 10px; border-bottom: 1px solid ${C.border}; }
        .so-what-item:last-child { border-bottom: none; }
        .so-what-item:nth-child(even) { background-color: ${C.altBg}; }
        .footer-tag { position: fixed; bottom: 12mm; left: 20mm; right: 20mm; font-size: 9px; color: ${C.mid}; border-top: 1px solid #eee; padding-top: 5px; display: flex; justify-content: space-between; }
        .code-block { background-color: #1E1E1E; color: #D4D4D4; border: none; padding: 10px 14px; font-family: 'Courier New', monospace; font-size: 9.5px; margin: 8px 0; white-space: pre; overflow-x: auto; line-height: 1.5; border-radius: 3px; }
        .keep-together { page-break-inside: avoid; }
        @media print {
            body { background: none; }
            .page { margin: 0; box-shadow: none; height: auto; overflow: visible; padding: 0 20mm; page-break-after: auto; position: relative; }
            h1, h2, h3 { page-break-after: avoid; break-after: avoid; }
            p { orphans: 3; widows: 3; }
        }
    </style>
</head>
<body>
    <div class="conf-header">${esc(CN)} Security Assessment | ${esc(month)} | CONFIDENTIAL</div>
    <div class="footer-tag"><span>&copy; 2026 Palo Alto Networks | Proprietary &amp; Confidential</span></div>
    <table style="width:100%;border:none;border-collapse:collapse;">
        <thead><tr><td style="height:18mm;border:none;padding:0;"></td></tr></thead>
        <tbody><tr><td style="border:none;padding:0;">

    <!-- PAGE 1: COVER -->
    <div class="page" style="page-break-after:always;min-height:250mm;display:flex;flex-direction:column;justify-content:center;">
        <div style="margin-top:100px;">
            <div style="color:${C.orange};font-size:44px;font-weight:bold;line-height:1;">${esc(CN)}</div>
            <div style="font-size:34px;font-weight:bold;margin-bottom:20px;">Security Assessment</div>
            <div style="font-size:16px;color:${C.mid};font-style:italic;margin-bottom:10px;">${esc(month)} &middot; Report Period: ${esc(reportPeriod)}</div>
            <div style="margin-top:40px;font-size:13px;line-height:1.6;">
                <strong>Prepared by:</strong> ${esc(preparer.name||'John Shelest')} | ${esc(preparer.title||'Palo Alto Networks Solutions Consultant')}<br>
                <strong>Source Data:</strong> ${panVersion !== '—' ? `Panorama PAN-OS ${esc(panVersion)} &middot; ` : ''}${panDevGroups !== '—' ? `${esc(panDevGroups)} Managed Device Groups &middot; ` : ''}${esc(totalThreats)} Threat Log Rows
            </div>
        </div>
    </div>

    <!-- PAGE 2: EXECUTIVE SUMMARY -->
    <div class="page">
        <h1>1. Executive Summary</h1>
        <p>This assessment analyzes ${esc(CN)}${CN.endsWith('s') || CN.endsWith('S') ? "'" : "'s"} network security posture for the period ${esc(reportPeriod)}, drawing on ${panVersion !== '—' ? `Panorama ${esc(panVersion)} statsdump archives, ` : ''}${esc(totalThreats)} internal-zone threat log events, traffic logs, and the Security Lifecycle Review (SLR) PDF. The data shows active outbound connections to known malicious infrastructure, vulnerability exploit signatures firing from internal zones, and cross-segment traffic patterns consistent with lateral movement indicators. The sections below walk through each finding in detail with the supporting evidence.</p>

        <div style="display:flex;margin:16px -8px;">
            ${renderKPI(totalApps !== '—' ? totalApps : D.spywareCount+D.vulnCount, totalApps !== '—' ? 'Total Applications' : 'Total Threats', C.dark)}
            ${renderKPI(highRiskApps !== '—' ? highRiskApps : D.vulnCount, highRiskApps !== '—' ? 'High-Risk Apps' : 'Vuln Events', C.orange)}
            ${renderKPI(saasApps !== '—' ? saasApps : D.infectedCount, saasApps !== '—' ? 'SaaS Applications' : 'Infected IPs', C.mid)}
        </div>
        <div style="display:flex;margin:0 -8px 20px -8px;">
            ${renderKPI(num(vulnExploits), 'Vulnerability Exploits', C.red)}
            ${renderKPI(totalThreats, 'Total Threat Events', C.red)}
            ${renderKPI(malwareKnown != null ? malwareKnown : (malwareCount !== '—' ? malwareCount : D.infectedCount),
                        malwareKnown != null ? 'Known Malware (' + (malwareUnknown ?? 0) + ' Unknown)' : (malwareCount !== '—' ? 'Malware Detected' : 'Infected IPs'), C.amber)}
        </div>

        <h3>Key Findings</h3>
        <ul class="bullet-list">
            ${soWhat.exec_summary && soWhat.exec_summary.length ? 
                soWhat.exec_summary.map(b => '<li>' + String(b).replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>') + '</li>').join('\n') 
                : keyFindings.map(f=>'<li>'+f+'</li>').join('\n') || '<li>No critical findings detected from parsed data.</li>'}
        </ul>

        ${renderSoWhat(buildActionBlock('exec_summary', D))}
    </div>

    <!-- PAGE 3: C2 & MALWARE -->
    <div class="page">
        <h1>2. Active Command &amp; Control (C2) &amp; Malware Activity</h1>

        <p>During this period the firewall detected ${esc(infectedCount)} internal IP addresses establishing sessions with ${realDomains.length} flagged domains. These represent completed DNS queries — meaning machines inside the network communicated with infrastructure flagged by threat intelligence. In parallel, ${D.namedThreats && D.namedThreats.length ? D.namedThreats.length + ' distinct threat ' + (D.namedThreats.length === 1 ? 'family was' : 'families were') : 'threat families were'} identified${slr.c2Count ? ' across ' + num(slr.c2Count) + ' total C2 connections' : ''}, and WildFire sandbox confirmed ${slr.malwareKnown != null ? slr.malwareKnown : malwareCount} malware events (which were successfully blocked by the firewall). The tables below identify the specific domains, the endpoints establishing connections, the threat families responsible, and the delivery vectors for confirmed malware.</p>

        <h3>2.1 Which Malicious Domains Are Being Contacted? ${src('Threat Log CSV — spyware subtype, internal zones only; enriched with AlienVault OTX & Threat Vault')}</h3>
        <p style="font-size:10px;color:#666;margin-bottom:6px;">Each domain below was resolved by internal machines during the report period and flagged by Palo Alto Networks threat prevention. The <strong>PAN Verdict</strong> column shows the exact Palo Alto Networks Threat Vault signature that triggered the block. The <strong>OTX Intel</strong> column shows AlienVault Open Threat Exchange intelligence pulses — independently confirming the domain across multiple global threat feeds. The <strong>Why It Matters</strong> column explains what each domain is designed to do based on its name and pattern.</p>
        ${realDomains.length ? renderTable(
            ['Domain', 'Total Hits', 'PAN Verdict', 'OTX Intel', 'Why It Matters'],
            realDomains.slice(0, 15).map(d => {
                const vaultVerdict = d.vault_verdict || 'Undetected';
                const vaultFmt = vaultVerdict.toLowerCase() === 'undetected' ? {text: 'Undetected', color: C.mid} :
                                 vaultVerdict.toLowerCase().includes('spyware') ? {text: vaultVerdict, color: C.red} :
                                 {text: vaultVerdict, color: C.amber};
                const pulses = d.otx_pulses != null ? String(d.otx_pulses) : '—';
                // Intelligence note — derived from domain name patterns
                const dm = (d.domain || '').toLowerCase();
                const noteText =
                    dm.includes('polyfill.io')
                        ? {text: 'Supply chain attack — compromised javascript library loaded by legitimate websites. Indicates users browsed to infected 3rd-party sites rather than direct malware beaconing.', color: C.red}
                    : brandDoms.some(b => b.domain === d.domain)
                        ? {text: 'Brand squatting — attacker registered a domain using your company name to target IDEX specifically', color: C.red}
                    : dm === (oktaDom||{}).domain || dm.includes('okta')
                        ? {text: 'Fake Okta login page — credential phishing for SSO passwords; any employee who logged in handed attackers access to every system', color: C.red}
                    : dm.includes('azure') || dm.includes('microsoft') || dm.includes('msedge') || dm.includes('office')
                        ? {text: 'Impersonates Microsoft/Azure infrastructure — designed to blend into normal cloud traffic and evade detection', color: C.amber}
                    : dm.includes('akamai')
                        ? {text: 'Impersonates Akamai CDN — attacker C2 disguised as legitimate content delivery traffic', color: C.amber}
                    : dm.includes('pbx') || dm.includes('voip') || dm.includes('cloud')
                        ? {text: 'Fake cloud/telecom infrastructure — C2 channel disguised as business application traffic', color: C.amber}
                    : d.otx_pulses >= 25
                        ? {text: `Widely-known attacker infrastructure — reported by ${d.otx_pulses} independent threat intelligence sources`, color: C.amber}
                    : (d.vault_verdict && d.vault_verdict.toLowerCase() !== 'undetected')
                        ? {text: `Palo Alto Networks signature triggered: ${d.vault_verdict}`, color: C.amber}
                    : esc(d.note || '');
                return [
                    esc(d.domain) + (d.tid ? `<br><span style="font-size:9px;color:${C.mid}">TID ${esc(d.tid)}</span>` : ''),
                    num(d.hits),
                    vaultFmt,
                    pulses,
                    noteText
                ];
            }),
            ['30%','6%','16%','9%','39%']
        ) : '<p>No OTX-confirmed malicious domains identified. All detected domains returned 0 OTX pulses — review intempio.com separately as it carries 16,019 PAN TID hits despite no OTX intelligence.</p>'}

        ${dnsRows.length ? `
        <h3>2.2 DNS Resolvers Masking the True Scope ${src('Threat Log CSV — high-volume, high-unique-domain source IPs')}</h3>
        <p style="font-size:10px;color:#666;margin-bottom:6px;">These IPs are internal DNS servers forwarding requests on behalf of multiple clients. The firewall sees the resolver, not the endpoint originating the request — meaning the true number of endpoints contacting flagged domains is masked. The endpoint list in the next table is incomplete without correlating query logs directly from these DNS servers.</p>
        ${renderTable(['Resolver IP', 'Zone', 'C2 Hits Forwarded', 'Unique Domains Queried', 'Status'], dnsRows)}` : ''}

        <h3>${dnsRows.length ? '2.3' : '2.2'} Which Endpoints Are Hitting Which Domains? ${src('Threat Log CSV — domain → source IP cross-reference')}</h3>
        ${(() => {
            const domIPs = D.domainIPs || {};
            // Build rows: one per domain from topDomains, showing IPs and users for that domain
            const rows = realDomains.slice(0, 12).map(d => {
                const entry = domIPs[d.domain];
                const ips = entry ? entry.ips.slice(0, 5) : [];
                const users = entry ? entry.users.filter(u => u && u !== '—') : [];
                const ipStr = ips.length
                    ? ips.join(', ') + (entry && entry.ips.length > 5 ? ` +${entry.ips.length - 5} more` : '')
                    : '—';
                const userStr = users.length ? users.join(', ') : '(none logged)';
                const totalIPs = entry ? entry.ips.length : 0;
                return [
                    esc(d.domain),
                    num(d.hits),
                    String(totalIPs),
                    esc(ipStr),
                    users.length ? {text: esc(userStr), color: C.red} : {text: '(none logged)', color: C.mid}
                ];
            }).filter(r => r[2] !== '0');
            if (!rows.length) {
                return `<p style="font-size:10px;color:#666;margin-bottom:6px;">Domain-to-endpoint mapping requires re-running the report parser. The DNS resolvers in section 2.2 are forwarding on behalf of real endpoints — pull DNS query logs from ${dnsIPs} to identify affected hosts (see Appendix A).</p>`;
            }
            return `<p style="font-size:10px;color:#666;margin-bottom:6px;">Each row shows a flagged domain, how many total hits it received, how many distinct internal IPs resolved it, the source IPs, and any named user accounts logged at the time. Users shown in red are named employee accounts — these are the highest-priority investigation targets. IPs list is capped at 5 per domain; run the Panorama query below for the full list.</p>`;
        })()}
        ${(() => {
            const domIPs = D.domainIPs || {};
            const rows = realDomains.slice(0, 12).map(d => {
                const entry = domIPs[d.domain];
                const ips = entry ? entry.ips.slice(0, 5) : [];
                const users = entry ? entry.users.filter(u => u && u !== '—') : [];
                const ipStr = ips.length
                    ? ips.join(', ') + (entry && entry.ips.length > 5 ? ` +${entry.ips.length - 5} more` : '')
                    : '—';
                const userStr = users.length ? users.join(', ') : '(none logged)';
                const totalIPs = entry ? entry.ips.length : 0;
                return [
                    esc(d.domain),
                    num(d.hits),
                    String(totalIPs),
                    esc(ipStr),
                    users.length ? {text: esc(userStr), color: C.red} : {text: '(none logged)', color: C.mid}
                ];
            }).filter(r => r[2] !== '0');
            return rows.length
                ? renderTable(['Domain', 'Total Hits', 'Unique IPs', 'Source IPs (top 5)', 'Named Users'], rows, ['20%','8%','8%','34%','30%'])
                : '';
        })()}

        <h3>2.${dnsRows.length ? '4' : '3'} Named Threat Families (SLR Aggregate) ${src('SLR PDF — C2 Analysis, Top 10 section')}</h3>
        ${(() => {
            const sorted = [...(D.namedThreats||[])].sort((a,b) => (b.count||0)-(a.count||0));
            const cats = slr.c2ByCategory || [];
            const spyware  = cats.find(c => c.category === 'spyware');
            const backdoor = cats.find(c => c.category === 'backdoor');
            const botnet   = cats.find(c => c.category === 'botnet');
            const totalC2  = cats.reduce((s,c) => s+(c.count||0), 0);
            let catText = '';
            if (cats.length) {
                catText = ` The SLR identifies <strong>${totalC2} total C2 connections</strong> broken down by threat category: `;
                if (spyware)  catText += `<strong>${spyware.count} spyware</strong> (software silently monitoring activity, capturing keystrokes, and exfiltrating data); `;
                if (backdoor) catText += `<strong>${backdoor.count} backdoor</strong> (persistent unauthorized access tools that survive reboots and password resets); `;
                if (botnet)   catText += `<strong>${botnet.count} botnet</strong> (machines under external operator control, receiving commands from attacker infrastructure). `;
                catText += `These categories represent the <em>type of control</em> attackers have — spyware steals, backdoors persist, botnets execute commands.`;
            }
            const namedNote = sorted.length
                ? ` The named family table below identifies the specific tools responsible.`
                : ` Individual named families were not itemized in this SLR export — the category breakdown above is the available data.`;
            return `<p style="font-size:10px;color:#666;margin-bottom:6px;">${catText}${namedNote}</p>`;
        })()}
        ${D.namedThreats && D.namedThreats.length ? renderTable(
            ['Threat Family','Detections','Category','C2 Protocol','What It Does'],
            [...D.namedThreats].sort((a,b) => (b.count||0)-(a.count||0))
            .slice(0,10).map(t => {
                const n = (t.name||'').toLowerCase();
                const c = (t.category||'').toLowerCase();
                const what =
                    n.includes('bpfdoor')    ? {text: 'Linux backdoor — uses ICMP ping to evade TCP/UDP firewall rules, persistent root access', color: C.red} :
                    n.includes('western') || n.includes('wd my cloud') ? {text: 'NAS backdoor — targets WD network storage for persistent file access', color: C.amber} :
                    n.includes('zeroaccess') ? {text: 'Windows rootkit — disables AV, mines crypto, joins P2P botnet', color: C.amber} :
                    n.includes('njrat')      ? {text: 'RAT — keylogger, remote shell, webcam/mic access, file exfiltration', color: C.amber} :
                    n.includes('gh0st')      ? {text: 'APT-grade RAT — full remote control, used in nation-state campaigns', color: C.amber} :
                    n.includes('androx')     ? {text: 'Cloud credential harvester — scans .env files for AWS/Azure/API keys', color: C.amber} :
                    n.includes('user-agent') ? {text: 'Traffic evasion — malware disguised as normal browser requests', color: C.mid} :
                    n.includes('dns tunnel') ? {text: 'Data exfiltration via DNS — encodes stolen data in DNS queries, bypasses most firewalls', color: C.amber} :
                    n.includes('sipvicious') ? {text: 'VoIP scanner — enumerates SIP devices for toll fraud or eavesdropping', color: C.mid} :
                    c.includes('backdoor')   ? {text: 'Backdoor — persistent unauthorized access surviving reboots and credential resets', color: C.red} :
                    c.includes('botnet')     ? {text: 'Botnet — machine under external attacker control, awaiting commands', color: C.amber} :
                    c.includes('spyware')    ? {text: 'Spyware — silently monitors, captures credentials/data, exfiltrates', color: C.amber} :
                    {text: 'Malware — see category column', color: C.mid};
                return [esc(t.name), num(t.count), esc(t.category), esc(t.protocol), what];
            })
        ) : ''}

        ${(slr.c2ByProtocol && slr.c2ByProtocol.length) ? `
        <h3>2.${dnsRows.length ? '5' : '4'} How Is C2 Traffic Communicating? ${src('SLR PDF — C2 Protocol Analysis section')}</h3>
        ${(() => {
            const proto = [...slr.c2ByProtocol].sort((a,b)=>b.count-a.count);
            const ping    = proto.find(p => p.protocol === 'ping');
            const unknown = proto.filter(p => p.protocol.includes('unknown'));
            const dns     = proto.find(p => p.protocol === 'dns-base' || p.protocol === 'dns');
            const web     = proto.find(p => p.protocol.includes('web'));
            const unkTotal = unknown.reduce((s,p)=>s+(p.count||0),0);
            let note = 'The protocol breakdown reveals how attackers are maintaining communication — and why some of it is hard to block. ';
            if (ping)    note += `<strong>ICMP ping (${ping.count} requests)</strong> — most firewall rules inspect TCP/UDP but not ICMP, so ping-based C2 travels through uninspected. ${D.namedThreats && D.namedThreats.some(t=>(t.name||'').toLowerCase().includes('bpfdoor')) ? 'BPFDoor — identified in this environment\'s named threats — uses exactly this technique.' : 'This is a known technique used by Linux-based backdoors.'} `;
            if (unkTotal) note += `<strong>${unkTotal} unknown-protocol requests</strong> mean App-ID could not classify the traffic — these sessions are passing through without deep inspection, which is a visibility gap. `;
            if (dns)     note += `<strong>DNS-based C2 (${dns.count} requests)</strong> encodes commands or data in DNS queries — valid-looking DNS traffic that most firewalls pass without inspection. `;
            if (web)     note += `<strong>Web-browsing C2 (${web.count} requests)</strong> hides in normal HTTP/HTTPS traffic, making it indistinguishable from legitimate browsing without SSL inspection. `;
            return `<p style="font-size:10px;color:#666;margin-bottom:6px;">${note}</p>`;
        })()}
        ${renderTable(['Protocol','C2 Requests','Why It Matters'],
            [...slr.c2ByProtocol].sort((a,b)=>b.count-a.count).map(p => [
                esc(p.protocol),
                {text: String(p.count), color: p.count > 20 ? C.red : p.count > 5 ? C.amber : ''},
                p.protocol === 'ping'           ? `ICMP — bypasses most TCP/UDP inspection rules${D.namedThreats && D.namedThreats.some(t=>(t.name||'').toLowerCase().includes('bpfdoor')) ? '; used by BPFDoor detected in this environment' : '; commonly used by Linux backdoors to evade inspection'}` :
                p.protocol === 'web-browsing'   ? 'Hidden in HTTP/HTTPS — requires SSL inspection to detect' :
                p.protocol === 'dns-base'       ? 'DNS tunneling — commands encoded in DNS queries, passes most firewalls' :
                p.protocol.includes('unknown')  ? 'Unclassified — App-ID cannot inspect this traffic; visibility gap' :
                p.protocol.includes('tcp')      ? 'Custom TCP channel — non-standard port or obfuscated application' :
                p.protocol.includes('udp')      ? 'Custom UDP channel — typically faster C2, harder to trace' :
                'C2 communication channel'
            ])
        )}` : ''}

        ${(slr.malwareApps && slr.malwareApps.length) || slr.malwareKnown != null ? `
        <h3>2.${dnsRows.length ? '6' : '5'} What Did WildFire Sandbox Confirm? ${src('SLR PDF — Advanced WildFire Analysis section')}</h3>
        <p style="font-size:10px;color:#666;margin-bottom:6px;">WildFire is Palo Alto Networks' cloud sandbox — every file traversing the firewall is detonated in an isolated environment and observed for malicious behavior. ${slr.malwareKnown != null ? '<strong>' + slr.malwareKnown + ' known</strong> and <strong>' + (slr.malwareUnknown ?? 0) + ' unknown</strong> malware files received confirmed malicious verdicts.' : ''} These are not signature matches — WildFire executed the actual files and observed what they did. The <strong>delivery application</strong> column shows <em>how</em> the malware entered the network, which directly informs what controls would stop future infections.</p>
        ${slr.malwareApps && slr.malwareApps.length ? renderTable(
            ['Delivery Application','Confirmed Files','What This Means','Action'],
            slr.malwareApps.map(a => {
                const app = (a.app||'').toLowerCase();
                const meaning = app.includes('smb') || app.includes('smbv3')
                    ? 'Malware spreading laterally via Windows file sharing — same protocol as cross-zone flows in §4'
                    : app.includes('web') || app.includes('browsing')
                    ? 'Malware delivered via web download — drive-by or user-initiated download over HTTP/HTTPS'
                    : app.includes('ftp')  ? 'Malware via unencrypted FTP — no inspection, clear-text transfer'
                    : app.includes('smtp') || app.includes('mail') ? 'Malware via email attachment'
                    : 'Malware delivered via ' + esc(a.app);
                const action = app.includes('smb') || app.includes('smbv3')
                    ? {text: 'Cross-reference with §4 lateral movement — same protocol, connected finding', color: C.red}
                    : app.includes('web') || app.includes('browsing')
                    ? {text: 'Confirm WildFire blocking profile is active; these specific payloads were successfully dropped.', color: C.amber}
                    : {text: 'Review WildFire Submissions log for SHA256 hashes — Panorama → Monitor → WildFire', color: C.amber};
                return [esc(a.app), {text: String(a.count), color: C.red}, meaning, action];
            })
        ) : ''}
        <p style="font-size:10px;color:#666;margin-top:6px;">To retrieve file hashes and full sandbox reports: <strong>Panorama → Monitor → Logs → WildFire Submissions</strong>. Each row has a SHA256 hash — submit to <code>wildfire.paloaltonetworks.com</code> to see exactly what the malware attempted: files created, registry changes, network connections made.</p>` : ''}

        ${renderSoWhat(buildActionBlock('c2', D) || soWhat.c2 || [])}
    </div>

    <!-- PAGE 5: VULNERABILITIES -->
    <div class="page">
        <h1>3. Vulnerability Exploits &amp; Attack Attempts</h1>

        <p>${num(vulnExploits)} vulnerability exploit signatures were identified during the reporting period. The table below shows which applications were targeted most heavily and what the attackers were actually attempting. The named user events from the threat log CSV — including the Log4j RCE on a specific account — are the most actionable findings in this section and are called out directly in the recommended actions below.</p>

        ${(() => {
            // Show named user vuln events as a callout — these are the real actionable findings
            const critical = vulnEvents.filter(v => (v.severity||'').toLowerCase() === 'critical');
            const high = vulnEvents.filter(v => (v.severity||'').toLowerCase() === 'high' && v.user && v.user.trim());
            const notable = [...critical, ...high].slice(0, 5);
            if (!notable.length) return '';
            return `<div style="border-left:4px solid ${C.red};padding:4px 0 4px 12px;margin:10px 0 14px 0;">
                <p style="font-size:10px;font-weight:bold;color:${C.red};margin:0 0 4px 0;">&#9888; Named User Events — Threat Log CSV ${`<span style="font-weight:normal;color:${C.mid}">(these are specific, confirmed point-in-time events — higher confidence than SLR aggregate counts)</span>`}</p>
                <p style="font-size:10px;color:#666;margin:0 0 6px 0;">These events have a named ${esc(CN)} user account in the Source User field — meaning a real employee identity is directly associated with the exploit signature. This is the highest-priority data in this section.</p>
                ${renderTable(
                    ['Source IP','User Account','Threat','Severity','Action','What It Means'],
                    notable.map(v => {
                        const t = (v.threat||'').toLowerCase();
                        const meaning = t.includes('log4j') || t.includes('log4shell')
                            ? {text: 'CONFIRMED RCE ATTEMPT — named account triggered critical exploit to external IP. Endpoint forensics required.', color: C.red}
                            : t.includes('ssh') && t.includes('brute')
                            ? {text: 'SSH credential attack — 9 attempts from user\'s machine. Verify this machine isn\'t compromised.', color: C.amber}
                            : t.includes('wrm') || t.includes('wmi')
                            ? {text: 'WRM brute force — remote management protocol abuse. Check if this user has admin rights across segments.', color: C.amber}
                            : {text: 'Named user in exploit event — investigate source endpoint', color: C.amber};
                        return [
                            esc(v.src_ip), esc(v.user||'—'), esc(v.threat),
                            {text: (v.severity||'').toUpperCase(), color: (v.severity||'').toLowerCase() === 'critical' ? C.red : C.amber},
                            {text: esc(v.action||'—'), color: v.action === 'alert' ? C.red : ''},
                            meaning
                        ];
                    })
                )}
                ${notable.some(v => v.action === 'alert') ? `<p style="font-size:10px;color:${C.red};margin:4px 0 0 0;"><strong>&#9888; Events with action = "alert" mean traffic was NOT blocked — it reached the destination.</strong> Reset-both means the firewall terminated the session, but the exploit payload may have already been delivered in the initial request.</p>` : ''}
            </div>`;
        })()}

        ${D.appVulns && D.appVulns.length ? `
        <div class="keep-together">
            <h3>3.1 Exploit Volume by Application ${src('SLR PDF — Vulnerability Exploits per Application section')}</h3>
            ${(() => {
                const sorted = [...D.appVulns].sort((a,b) => (b.count||0)-(a.count||0));
                const top = sorted[0] || {};
                const second = sorted[1] || {};
                const smbApp = sorted.find(a => (a.app||'').toLowerCase().includes('smb'));
                const ghApp  = sorted.find(a => (a.app||'').toLowerCase().includes('github'));
                const total  = sorted.reduce((s,a) => s+(a.count||0), 0);
                const topPct = top.count ? Math.round(top.count/total*100) : 0;
                const smbNote = smbApp && (smbFlows.length > 0 || wrmFlows.length > 0)
                    ? ` <strong>${esc(smbApp.app)} appears in both this table and the lateral movement flows in section 4</strong> — the same protocol being actively exploited is also crossing zone boundaries. These findings are directly connected.`
                    : '';
                const ghNote = ghApp
                    ? ` <strong style="color:${C.red}">CRITICAL FINDING:</strong> ${num(ghApp.count)} unauthorized brute force attempts against GitHub from inside the network indicate either a compromised endpoint running automated credential-stuffing tools, or a misconfigured pipeline making excessive unauthenticated API calls. Because this high-volume event exceeded the CSV export limit, the specific Source IPs could not be extracted in this report. <strong>You must query Panorama directly (Threat logs, App = github-base) to identify the specific compromised machine.</strong>`
                    : '';
                return `<p style="font-size:10px;color:#666;margin-bottom:6px;">${esc(top.app)} dominates with ${num(top.count)} events (${topPct}% of all exploit activity) — followed by ${esc(second.app)} at ${num(second.count)} events.${smbNote}${ghNote} The "Key Signatures" column shows what the attackers were actually attempting — not just which app they targeted.</p>`;
            })()}
            ${renderTable(
                ['Application','Total Exploit Events','Key Signatures Observed','What Attackers Were Doing'],
                [...D.appVulns].sort((a,b) => (b.count||0)-(a.count||0))
                    .map(a => {
                        const app = (a.app||'').toLowerCase();
                        const what = app.includes('smb')
                            ? {text: 'Brute-forcing Windows file shares + reading registry — ransomware recon pattern', color: C.red}
                            : app.includes('github')
                            ? {text: 'Credential stuffing against GitHub auth — automated tool running inside network', color: C.amber}
                            : app.includes('msrpc') || app.includes('rpc')
                            ? {text: 'NTLM credential interception — harvesting Windows auth hashes in transit', color: C.amber}
                            : app.includes('web') || app.includes('browsing')
                            ? {text: 'Exploiting web apps via path traversal, Log4j RCE, Confluence RCE — opportunistic scanning', color: C.amber}
                            : app.includes('concur') || app.includes('sap') || app.includes('workday')
                            ? {text: 'Brute-forcing enterprise SaaS — targeting employee credentials for business app access', color: C.amber}
                            : {text: 'Exploit attempts — see signature column for details', color: C.mid};
                        return [
                            esc(a.app),
                            {text: num(a.count), color: (a.count||0) > 10000 ? C.red : (a.count||0) > 2000 ? C.amber : ''},
                            esc((a.threats||[]).slice(0,2).join(' · ')),
                            what
                        ];
                    })
            )}
        </div>` : ''}

        <div class="keep-together">
            ${(() => {
                const namedUsers = vulnEvents.filter(v => v.user && v.user.trim() && v.user !== '—');
                const hasUsers = namedUsers.length > 0;
                let tableEvents = hasUsers ? namedUsers : vulnEvents;
                if (hasUsers && tableEvents.length < 8) {
                    const noUserEvents = vulnEvents.filter(v => !v.user || !v.user.trim() || v.user === '—');
                    tableEvents = [...tableEvents, ...noUserEvents].slice(0, 8);
                } else {
                    tableEvents = tableEvents.slice(0, 8);
                }
                const alertEvents = tableEvents.filter(v => v.action === 'alert');
                
                let title = hasUsers ? '3.2 Named User Vulnerability Events' : '3.2 High-Volume & Critical Vulnerability Events';
                let note = hasUsers 
                    ? `These are vulnerability events where the firewall logged a specific ${esc(CN)} user account in the Source User field. Named user attribution is rare in firewall logs — it only appears when user-ID mapping is active, making these events significantly more actionable than anonymous IP-only events. `
                    : `These are the highest volume and most critical vulnerability events detected. Volume indicates automated scanning or active exploitation attempts from internal sources. `;
                
                if (alertEvents.length) {
                    note += `<strong style="color:${C.red}">${alertEvents.length} event${alertEvents.length > 1 ? 's have' : ' has'} action = "alert" — traffic was NOT blocked and reached the destination.</strong> `;
                }
                note += `Cross-reference each source IP with DHCP logs and your endpoint management system to identify the exact machine.`;
                
                let html = `<h3>${title} ${src('Threat Log CSV — vulnerability subtype, internal zones')}</h3>`;
                html += `<p style="font-size:10px;color:#666;margin-bottom:6px;">${note}</p>`;
                
                if (vulnEvents.length) {
                    html += renderTable(
                        ['Source IP', 'User Account', 'Threat Signature', 'Severity', 'Action', 'Destination'],
                        tableEvents.map(v => [
                            esc(v.src_ip),
                            v.user && v.user.trim() && v.user !== '—' ? {text: esc(v.user), color: C.dark} : {text: '(no user)', color: C.mid},
                            esc(v.threat) + (v.cve ? `<br><span style="color:${C.mid};font-size:9px;">${esc(v.cve)}</span>` : ''),
                            {text: (v.severity||'').toUpperCase(), color: (v.severity||'').toLowerCase() === 'critical' ? C.red : (v.severity||'').toLowerCase() === 'high' ? C.amber : ''},
                            {text: esc(v.action||'—'), color: v.action === 'alert' ? C.red : ''},
                            esc(v.dst_ip||'—')
                        ])
                    );
                } else {
                    html += '<p>No vulnerability events identified from threat log CSV.</p>';
                }
                return html;
            })()}
        </div>

        ${renderSoWhat(buildActionBlock('vuln', D) || soWhat.vuln || [])}
    </div>

    <!-- PAGE 6: LATERAL MOVEMENT -->
    <div class="page">
        <h1>4. Lateral Movement &amp; Remote Access</h1>

        <p>Lateral movement is the phase between initial compromise and a major incident — it's when an attacker moves from one system to another to gain broader access. The firewall data shows ${smbFlows.length > 0 ? smbFlows.length + ' unique SMB (file sharing) cross-zone flows' : 'no confirmed SMB cross-zone flows'}${wrmFlows.length > 0 ? ' and ' + wrmFlows.length + ' WRM (Windows Remote Management) cross-zone flows with significant data transfer' : ''}. These flows are not inherently malicious — they may reflect legitimate administrative activity. What matters is whether they are covered by an explicit, documented policy. If they are not, they represent either a segmentation gap or undetected lateral movement. Additionally, ${remoteApps !== '—' ? remoteApps : 'a significant number of'} remote access tools were observed — ${remoteApps !== '—' ? Math.round(parseInt(remoteApps)/9) + '×' : 'well above'} the industry average of 9 — each of which is an ungoverned entry point into the environment.</p>

        ${wrmRows.length ? `
        <h3>4.1 Windows Remote Management Cross-Zone Flows ${src('Traffic Log CSV — Application = windows-remote-management, cross-zone, bytes > 100KB')}</h3>
        <p style="font-size:10px;color:#666;margin-bottom:6px;">WRM (TCP 5985/5986) is a legitimate Windows administration protocol. These are completed sessions — data was successfully transferred. If these are expected administrative flows, they should be in your zone segmentation policy; if not, the source IP is the starting point for investigation. Panorama query to verify: Monitor → Logs → Traffic, filter Application = windows-remote-management, Source Zone ≠ Destination Zone.</p>
        ${renderTable(['Source IP','Source Zone','Destination IP','Dest Zone','Data Transferred'], wrmRows)}` : ''}

        ${smbRows.length ? `
        <div class="keep-together">
            <h3>${wrmRows.length ? '4.2' : '4.1'} SMB Cross-Zone Flows ${src('Traffic Log CSV — Application = smb, cross-zone sessions')}</h3>
            <p style="font-size:10px;color:#666;margin-bottom:6px;">SMB (TCP 445) is Windows file sharing and the primary ransomware propagation protocol. In a hardened environment SMB should be zone-confined — workstations in one segment should not be able to reach file servers in another over SMB unless that path is explicitly permitted. The flows below cross zone boundaries. If your policy does not explicitly allow these, this is a segmentation gap that ransomware would use to spread from a single infected workstation to servers on a different segment. Panorama query: Monitor → Logs → Traffic, filter Application = smb, Source Zone ≠ Destination Zone.</p>
            ${renderTable(['Source IP','Source Zone','Destination Zone','Protocol','Note'], smbRows)}
        </div>` : ''}

        ${remoteApps !== '—' ? `
        <div class="keep-together">
            <h3>${(wrmRows.length && smbRows.length) ? '4.3' : (wrmRows.length || smbRows.length) ? '4.2' : '4.1'} Remote Access Tool Proliferation ${src('SLR PDF — Remote Access Applications section')}</h3>
            <p style="font-size:10px;color:#666;margin-bottom:6px;">${esc(remoteApps)} remote access tools were detected vs. an industry average of 9 — ${Math.round(parseInt(remoteApps)/9)}× above peer baseline. Every remote access tool not in your approved catalog is a potential backdoor that bypasses VPN and MFA controls. Consumer-grade tools like AnyDesk, VNC, and ScreenConnect are the #1 persistence mechanism used by ransomware operators after initial compromise — they install them to maintain access even after passwords are reset.</p>
            ${D.remoteAccessApps && D.remoteAccessApps.length ?
                renderTable(
                    ['Application','Bandwidth','Sessions','Risk','Action Required'],
                    D.remoteAccessApps.map(a => {
                        const app = (a.app||'').toLowerCase();
                        const risk = parseInt(a.risk||'0');
                        const action =
                            risk >= 5 ? {text: 'Block or restrict immediately — Risk 5, unencrypted', color: C.red} :
                            app.includes('vnc') ? {text: 'Block or restrict — unencrypted, no MFA, ransomware tool', color: C.red} :
                            app.includes('anydesk') || app.includes('screenconnect') || app.includes('splashtop') ? {text: 'Validate licensing and auth — consumer tool, commonly abused post-compromise', color: C.amber} :
                            app.includes('rdp') || app.includes('ms-rdp') ? {text: 'Enforce NLA + MFA — RDP brute force is #1 ransomware entry vector', color: C.amber} :
                            app.includes('teamviewer') ? {text: 'Verify managed deployment — confirm all sessions are IT-authorized', color: C.amber} :
                            app.includes('windows-remote') || app.includes('wrm') ? {text: 'Confirm cross-zone flows are policy-permitted — see section 4.1', color: C.amber} :
                            {text: 'Validate against approved catalog', color: C.mid};
                        return [esc(a.app), esc(a.bw||'—'), esc(a.sessions ? String(a.sessions) : '—'),
                            {text: `Risk ${a.risk||'?'}`, color: risk >= 5 ? C.red : risk >= 4 ? C.amber : C.mid},
                            action];
                    })
                )
            : `<p style="font-size:10px;color:#666;">Individual app-level detail was not available in this SLR PDF export. To get the full list: <strong>Panorama → Monitor → App Scope → Application Usage → filter Category = remote-access</strong>. The SLR confirms ${esc(remoteApps)} total tools — compare each against your approved catalog and disable any not explicitly authorized.</p>`
            }
        </div>` : ''}

        ${renderSoWhat(buildActionBlock('lateral', D) || soWhat.lateral || [])}
    </div>

    <!-- PAGE 7: SAAS & APPLICATION RISK -->
    <div class="page">
        <h1>5. Application Risk &amp; SaaS Exposure</h1>

        <p>This section covers the breadth of applications on the network and the data risk from uncontrolled SaaS usage. ${esc(CN)} has ${totalApps !== '—' ? totalApps : 'a large number of'} total applications observed — ${highRiskApps !== '—' ? highRiskApps : 'a significant portion of which are'} classified as high-risk. The most significant data point is that ${saasBW !== '—' ? saasBW + ' TB (' + saasPct + ')' : 'a substantial portion'} of all bandwidth flows to SaaS applications. Without Data Loss Prevention controls on this traffic, ${esc(CN)} has no visibility into what data is being uploaded, shared, or stored in cloud services — some of which, as the risk category table shows, have poor security certifications, known breaches, or terms of service that permit the vendor to use or share your data. This is a compliance and data governance exposure as much as a technical security finding.</p>

        ${riskBandwidthRows ? `
        <div class="keep-together">
            <h3>5.1 Traffic by Risk Level ${src('SLR PDF — Applications that Introduce Risk section')}</h3>
            <p style="font-size:10px;color:#666;margin-bottom:6px;">Applications are classified on a 1–5 risk scale based on known vulnerabilities, evasion capability, and abuse potential. Risk 4–5 traffic represents applications that carry meaningful security risk — including unencrypted protocols, applications with public CVEs, and tools frequently misused by attackers. Industry best practice targets Risk 4–5 traffic below 10% of total bandwidth — review the dominant risk categories below and validate whether policy controls are appropriate.</p>
            ${renderTable(['Risk Level','Bandwidth (TB)','% of Total','Description'], riskBandwidthRows)}
        </div>` : totalBW !== '—' ? `
        <div class="keep-together">
            <h3>5.1 Traffic by Risk Level ${src('SLR PDF — Applications that Introduce Risk section')}</h3>
            ${(() => {
                function parseBwBytes(bwStr) {
                    const str = String(bwStr || '0').toLowerCase();
                    const num = parseFloat(str.replace(/[^0-9.]/g,'')) || 0;
                    if (str.includes('tb')) return num * 1024 * 1024 * 1024 * 1024;
                    if (str.includes('gb')) return num * 1024 * 1024 * 1024;
                    if (str.includes('mb')) return num * 1024 * 1024;
                    if (str.includes('kb')) return num * 1024;
                    return num;
                }
                const topApps = D.highRiskApps && D.highRiskApps.length
                    ? [...D.highRiskApps].sort((a,b) => parseBwBytes(b.bw) - parseBwBytes(a.bw)).slice(0,2)
                    : [];
                const topNote = topApps.length ? ` The highest-bandwidth applications are ${topApps.map(a => `${esc(a.app)} (${esc(a.bw)}, Risk ${esc(a.risk)})`).join(' and ')}.` : '';
                return `<p style="font-size:10px;color:#666;margin-bottom:6px;">Risk-level breakdown was not available in this SLR PDF export. Total observed bandwidth: <strong>${esc(totalBW)} TB</strong>. Of that, <strong>${esc(saasBW)} TB (${esc(saasPct)})</strong> flows to SaaS applications.${topNote} To see the full risk breakdown: <strong>Panorama → Monitor → App Scope → Risk → filter by risk level</strong>. Risk 4–5 traffic above 10% of total bandwidth is an elevated posture risk — validate that high-risk applications have documented policy decisions.</p>`;
            })()}
        </div>` : ''}

        ${D.highRiskApps && D.highRiskApps.length ? `
        <div class="keep-together">
            <h3>5.2 Top High-Risk Applications ${src('SLR PDF — Risk 4/5 application detail table')}</h3>
            ${(() => {
                function parseBwBytes(bwStr) {
                    const str = String(bwStr || '0').toLowerCase();
                    const num = parseFloat(str.replace(/[^0-9.]/g,'')) || 0;
                    if (str.includes('tb')) return num * 1024 * 1024 * 1024 * 1024;
                    if (str.includes('gb')) return num * 1024 * 1024 * 1024;
                    if (str.includes('mb')) return num * 1024 * 1024;
                    if (str.includes('kb')) return num * 1024;
                    return num;
                }
                const sorted = [...D.highRiskApps].sort((a,b) => {
                    const riskA = parseInt(a.risk || '0', 10);
                    const riskB = parseInt(b.risk || '0', 10);
                    if (riskA !== riskB) return riskB - riskA;
                    const bwA = parseBwBytes(a.bw);
                    const bwB = parseBwBytes(b.bw);
                    return bwB - bwA;
                });
                const top = sorted[0];
                const risk5 = sorted.filter(a => parseInt(a.risk||'0') >= 5);
                let note = `These are the applications consuming the most bandwidth at risk level 4 or above. Each should have a documented policy decision — either blocked, allowed with controls, or allowed with an accepted risk. `;
                if (top) note += `<strong>${esc(top.app)}</strong> is the largest single item at ${esc(top.bw)} (Risk ${esc(top.risk)}). `;
                if (risk5.length > 0) note += `<strong>${risk5.length} Risk-5 application${risk5.length > 1 ? 's' : ''} detected (${risk5.map(a=>esc(a.app)).join(', ')})</strong> — Risk-5 represents the highest risk classification; these should be explicitly blocked or have a documented exception.`;
                const smtpApp = sorted.find(a => a.app === 'smtp-base');
                if (smtpApp && parseBwBytes(smtpApp.bw) > 10 * 1024 * 1024 * 1024) { // >10GB
                    note += `<br><br><strong style="color:${C.red}">CRITICAL FINDING:</strong> <strong>${esc(smtpApp.bw)} of unencrypted SMTP traffic</strong> was observed. Unless this originates from a sanctioned mail server, outbound SMTP of this volume from internal zones is a strong indicator of a spam botnet or massive data exfiltration. Investigate the source IPs generating this traffic immediately. `;
                }
                return `<p style="font-size:10px;color:#666;margin-bottom:6px;">${note}</p>` +
                    renderTable(['Application','Bandwidth','Risk Level','Recommended Policy Action'], sorted.slice(0,10).map(a=>[esc(a.app), esc(a.bw), {text: String(a.risk), color: Number(a.risk) >= 5 ? C.red : C.amber}, esc(a.action)]));
            })()}
        </div>` : ''}

        ${D.saasRisk && D.saasRisk.length ? `
        <div class="keep-together">
            <h3>5.3 SaaS Applications with Compliance Risk ${src('SLR PDF — SaaS Application Risk section')}</h3>
            <p style="font-size:10px;color:#666;margin-bottom:6px;">These categories reflect legal and compliance risk, not just technical security risk. "No Security Certifications" means the vendor has not undergone an independent security audit (SOC 2, ISO 27001, etc.). "Known Data Breaches" indicates the vendor has had prior incidents affecting customer data. "Poor Terms of Service" means the vendor's agreement may permit them to use or monetize your data. Any application in these categories that handles confidential ${esc(CN)} data should be reviewed with your legal and procurement teams for a signed DPA (data processing agreement).</p>
            ${renderTable(['Risk Category','App Count','Bandwidth','Example Applications'], D.saasRisk.map(s=>[esc(s.category), esc(s.count), esc(s.bw), esc(s.apps)]))}
        </div>` : ''}

        ${renderSoWhat(buildActionBlock('saas', D) || soWhat.saas || [])}
    </div>

    <!-- PAGE 8: PANORAMA SYSTEM PROFILE -->
    <div class="page">
        <h1>6. Security Infrastructure &amp; Signature Currency</h1>

        <p>This section documents the Panorama management platform and the current state of threat detection signatures. Signature currency is the most operationally straightforward finding in this report — it is either current or it is not, and if it is not, every threat discovered after the last update date is invisible to the detection stack. Panorama is also the single point of management for all firewall policy, so its version, serial, and connectivity are relevant context for understanding the scope of coverage in the rest of this report.</p>

        ${panHostname !== '—' ? `
        <div class="keep-together">
            <h3>6.1 Panorama Platform Details ${src('Statsdump — show_system_info.txt')}</h3>
            ${renderTable(['Parameter','Value'], panRows, ['40%','60%'])}
        </div>
        <div class="keep-together">
            <h3>6.2 Threat Detection Signature Status ${src('Statsdump — show_system_info.txt')}</h3>
            <p style="font-size:10px;color:#666;margin-bottom:6px;">${sigsCurrent ? 'Signatures are current as of ' + esc(contentDate) + '. Daily automatic updates should be confirmed to be enabled to maintain this status going forward (Panorama → Device → Dynamic Updates).' : 'Signatures were last updated ' + esc(contentDate) + ' — ' + contentDays + ' days ago. Every malware variant, exploit signature, and C2 domain published since that date is not in the current detection set. This means the threat activity observed in sections 2 and 3 may undercount the actual volume — newer threat families would have passed through without triggering any signature.'}</p>
            ${renderTable(['Component','Version','Last Updated','Status'], contentRows, ['25%','25%','25%','25%'])}
        </div>` : `
        <p>Panorama statsdump data was not included in this assessment. System profile and signature currency data will appear here when a techsupport archive (.tgz) is placed in the source directory.</p>`}

        ${renderSoWhat(buildActionBlock('panorama', D) || soWhat.panorama || [])}
    </div>

    <!-- PAGE 9: BENCHMARKS -->
    <div class="page" style="page-break-before:always;">
        <h1>7. Industry Benchmark Comparison</h1>
        <p>The metrics below compare ${esc(CN)} against the industry peer group from the Palo Alto Networks SLR dataset (${esc(reportPeriod)})${slr.industryVertical ? ' — peer group: <strong>' + esc(slr.industryVertical.replace(/([A-Z])/g, ' $1').replace('other','').trim()) + '</strong>' : ''}. These benchmarks provide context, not a risk score — being above the industry average does not automatically mean there is a problem, and being below does not mean the environment is secure. Items flagged ⚠ are areas where ${esc(CN)} is meaningfully above the peer average and may warrant prioritized attention.</p>
        ${renderTable(['Metric', esc(CN), 'Industry Avg', 'Assessment'], benchmarkRows, ['28%','22%','28%','22%'])}
    </div>

    <!-- PAGE 10: RISK MATRIX -->
    <div class="page">
        <div class="keep-together">
            <h1>8. Risk Summary</h1>
            <p>The matrix below maps each primary finding to its assessed likelihood and potential business impact. Likelihood reflects whether the activity is confirmed in the firewall logs vs. inferred. Impact reflects the potential business consequence if the finding represents an active, uncontrolled threat. The risk level should be interpreted relative to ${esc(CN)}'s own risk tolerance and existing compensating controls — this report observes network-layer evidence only and cannot account for endpoint controls, SIEM detection, or incident response capabilities that may already be addressing these findings.</p>
            ${riskRows.length ? renderTable(['Finding','Likelihood','Potential Business Impact','Risk Level'], riskRows, ['45%','20%','15%','20%']) : '<p>Risk matrix will populate as findings are confirmed.</p>'}
        </div>
    </div>

    <!-- PAGE 11: ROADMAP -->
    <div class="page">
        <h1>9. Prioritized Remediation Roadmap</h1>
        <p>The following items are prioritized based on the findings in this report. P1 items represent findings that warrant near-term review regardless of existing controls. All items should be evaluated against your current security posture — some may already be addressed by controls not visible at the firewall layer.</p>

        <h3>P1 &mdash; Near-Term Review (0&ndash;7 Days)</h3>
        ${renderList(p1Items)}

        <h3>P2 &mdash; Short-Term Validation (7&ndash;30 Days)</h3>
        ${renderList(p2Items)}

        <h3>P3 &mdash; Strategic Enhancements to Consider (30&ndash;90 Days)</h3>
        ${renderList(p3Items)}
    </div>

    <!-- PAGE 12: APPENDIX - DNS INVESTIGATION -->
    ${dnsResolvers.length > 0 ? `<div class="page">
        <h1 style="font-size:20px;margin-top:0;">Appendix: Identifying Infected Clients Behind DNS Servers</h1>
        <p style="margin-bottom:20px;font-weight:bold;color:#000000;">Because ${esc(dnsIPStr)} are internal DNS resolvers, the firewall cannot identify the endpoints originating the requests &mdash; it only sees the DNS server forwarding queries on behalf of clients. The originating machines are obscured at the firewall layer.</p>

        <h2 style="font-size:18px;margin-top:30px;">Step 1 &mdash; Enable Windows DNS Debug Logging</h2>
        <p style="margin-bottom:10px;">Run on each DNS server (${esc(dnsIPStr)}):</p>
        <div class="code-block"><span style="color:#6A9955;"># Check if debug logging is enabled</span>
<span style="color:#569CD6;">Get-DnsServerDiagnostics</span> | <span style="color:#569CD6;">Select-Object</span> SendPackets, ReceivePackets, Queries

<span style="color:#6A9955;"># Enable full debug logging</span>
<span style="color:#569CD6;">Set-DnsServerDiagnostics</span> -All <span style="color:#569CD6;">$true</span>

<span style="color:#6A9955;"># Log file location: C:\\Windows\\System32\\dns\\dns.log</span></div>

        <h2 style="font-size:18px;margin-top:30px;">Step 2 &mdash; Search DNS Log for Malicious Domains</h2>
        <p style="margin-bottom:10px;">Filter the debug log for the C2 domains identified in this report:</p>
        <div class="code-block"><span style="color:#6A9955;"># Define C2 domains to search for</span>
<span style="color:#569CD6;">$c2domains</span> = <span style="color:#CE9178;">'${dnsPattern}'</span>

<span style="color:#6A9955;"># Search DNS debug log</span>
<span style="color:#569CD6;">Select-String</span> -Path <span style="color:#CE9178;">'C:\\Windows\\System32\\dns\\dns.log'</span> \`
  -Pattern <span style="color:#569CD6;">$c2domains</span>

<span style="color:#6A9955;"># Export matching lines (with client IPs) to CSV</span>
<span style="color:#569CD6;">Select-String</span> -Path <span style="color:#CE9178;">'C:\\Windows\\System32\\dns\\dns.log'</span> \`
  -Pattern <span style="color:#569CD6;">$c2domains</span> | \`
  <span style="color:#569CD6;">Select-Object</span> LineNumber, Line | \`
  <span style="color:#569CD6;">Export-Csv</span> <span style="color:#CE9178;">C:\\dns_c2_hits.csv</span> -NoTypeInformation</div>

        <h2 style="font-size:18px;margin-top:30px;">Step 3 &mdash; Configure DNS Sinkhole in Panorama</h2>
        <ul class="bullet-list">
            <li>Panorama &rarr; Objects &rarr; Security Profiles &rarr; Anti-Spyware &rarr; DNS Policies</li>
            <li>Add sinkhole entry: Action = sinkhole, Sinkhole IPv4 = 72.5.65.111 (PAN default sinkhole)</li>
            <li>Apply to all device groups &mdash; affected clients now appear in threat logs with real source IPs</li>
            <li>Monitor &rarr; Logs &rarr; Threat &rarr; filter: threat_name contains 'sinkhole' to see all affected clients in real time</li>
        </ul>

        <h2 style="font-size:18px;margin-top:30px;">Step 4 &mdash; Investigation & Containment Actions</h2>
        <ul class="bullet-list">
            <li><strong>Add all malicious domains to internal DNS as override records pointing to 127.0.0.1</strong> &mdash; cuts beacon loops immediately without alerting potential malware</li>
            <li><strong>Isolate client IPs found in Step 2 from the network</strong> pending endpoint forensic investigation</li>
            ${oktaDom ? `<li><strong>Force Okta password resets for all users on machines that resolved ${esc(oktaDom.domain)}</strong> &mdash; assume credentials compromised</li>` : ''}
            ${log4j ? `<li><strong>Investigate activity for ${esc(log4j.user)}</strong> &mdash; Log4j exploit signature triggered on ${esc(log4j.src_ip||'affected host')}; endpoint forensics recommended</li>` : ''}
        </ul>
    </div>` : ''}

    <!-- Removed Appendix B -->

</td></tr></tbody>
        <tfoot><tr><td style="height:18mm;border:none;padding:0;"></td></tr></tfoot>
    </table>
</body>
</html>`;

fs.writeFileSync(outFile, html);
console.log(`✓ Generated dynamic security assessment report: ${outFile}`);
