/* =========================================================
   Windows Security Event Log Triage Tool — script.js
   ---------------------------------------------------------
   All processing happens locally in the browser. No data is
   uploaded, transmitted, or stored anywhere.
   ========================================================= */
'use strict';

// ---------- DOM references ----------
const $ = (id) => document.getElementById(id);
const dropZone = $('drop-zone');
const fileInput = $('file-input');
const uploadBtn = $('upload-btn');
const uploadStatus = $('upload-status');
const dashboard = $('dashboard');
const filtersSection = $('filters-section');

// ---------- Event ID definitions ----------
const EVENT_DEFS = {
  4624: {
    name: 'Successful Logon', type: 'Authentication', severity: 'Informational',
    why: 'Successful logons are not malicious on their own. They become important context when correlated with other events, such as repeated failed logons.',
    benign: 'Normal, expected authentication for the account and device.',
    investigation: ['Confirm the account and source are expected.', 'Check whether this logon followed any failed attempts.', 'Correlate with other activity from the same source.']
  },
  4625: {
    name: 'Failed Logon', type: 'Authentication', severity: 'Informational',
    why: 'A single failed logon is normally low priority, but repeated failures can indicate password guessing or brute-force attempts.',
    benign: 'Forgotten or mistyped password, stale service credentials, or an application using outdated credentials.',
    investigation: ['Identify the source system and IP.', 'Check how many failures occurred.', 'Determine whether the failures were followed by a successful login.']
  },
  4688: {
    name: 'Process Created', type: 'Process Activity', severity: 'Informational',
    why: 'Process creation provides visibility into what ran on a system. In Version 1 it is used mainly as context, not for malware detection.',
    benign: 'Routine execution of normal applications and system processes.',
    investigation: ['Review the process name, parent process, and command line.', 'Note anything unusual for later correlation.']
  },
  4720: {
    name: 'User Account Created', type: 'Account Management', severity: 'Medium',
    why: 'Account creation may be completely legitimate administrative activity, but it should be verified because attackers create accounts for persistence.',
    benign: 'Routine onboarding or service-account creation by an administrator.',
    investigation: ['Confirm the account creation was authorised.', 'Identify the administrator who created it.', 'Review activity performed by the new account.']
  },
  4726: {
    name: 'User Account Deleted', type: 'Account Management', severity: 'Low',
    why: 'Deleting an account can be legitimate administration, or part of suspicious account manipulation to cover tracks.',
    benign: 'Normal offboarding or cleanup of unused accounts.',
    investigation: ['Confirm the deletion was authorised.', 'Check whether the account had recent activity before deletion.']
  },
  4728: {
    name: 'Member Added to Global Security Group', type: 'Group / Privilege', severity: 'Medium',
    why: 'Adding users to groups is routine, but privileged groups grant extra power and deserve higher scrutiny.',
    benign: 'Normal group-membership management by an administrator.',
    investigation: ['Confirm the change was authorised.', 'If the group is privileged, review it more closely.', 'Check for related account-creation events.']
  },
  4732: {
    name: 'Member Added to Local Security Group', type: 'Group / Privilege', severity: 'Medium',
    why: 'Adding a user to a local group such as Administrators can be routine, or a sign of privilege escalation.',
    benign: 'Normal local group management by an administrator.',
    investigation: ['Confirm the change was authorised.', 'If the group is privileged, review it more closely.', 'Check for related account-creation events.']
  },
  1102: {
    name: 'Security Audit Log Cleared', type: 'Audit / Log Management', severity: 'High',
    why: 'Clearing the security log can happen during legitimate maintenance, but attackers often clear logs to remove evidence, so it should normally be investigated.',
    benign: 'Legitimate maintenance or log rotation by an administrator.',
    investigation: ['Confirm who cleared the log and why.', 'Check what activity occurred immediately before the clearing.', 'Review other log sources for the same time period.']
  },
  4104: {
    name: 'PowerShell Script Block Logging', type: 'PowerShell', severity: 'Informational',
    why: 'PowerShell script block logging can provide valuable visibility into commands and scripts executed on the endpoint.',
    benign: 'Normal PowerShell use, including scheduled tasks and administrative scripts.',
    investigation: ['Review the script block text.', 'Look for encoded or heavily obfuscated commands.']
  },
  7045: {
    name: 'Service Installed', type: 'Service', severity: 'Medium',
    why: 'Creating a new Windows service can be legitimate software installation or potentially persistence-related activity.',
    benign: 'Normal software installation or update that registers a service.',
    investigation: ['Confirm the service is expected.', 'Review the service name and image path.', 'Check whether the service auto-starts.']
  }
};

const CATEGORIES = ['Authentication', 'Account Management', 'Group / Privilege', 'Audit / Log Management', 'Process Activity', 'PowerShell', 'Service'];
const PRIVILEGED_GROUPS = [
  'administrators', 'domain admins', 'enterprise admins', 'schema admins',
  'account operators', 'server operators', 'backup operators', 'dnsadmins',
  'remote desktop users', 'group policy creator owners'
];

const NOTEWORTHY_IDS = [4625, 4720, 4726, 4728, 4732, 1102, 7045];

const SEVERITY_ORDER = { High: 3, Medium: 2, Low: 1, Informational: 0 };

// ---------- Utilities ----------
// Escape user-controlled text before inserting into HTML (prevents XSS).
function esc(v) {
  if (v == null) return '';
  return String(v).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function norm(s) { return String(s == null ? '' : s).trim().toLowerCase(); }

function escapeRe(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function isPrivilegedGroup(name) {
  if (!name) return false;
  const n = String(name).toLowerCase();
  return PRIVILEGED_GROUPS.some((g) => n.includes(g));
}

// Parse a Windows Event Viewer timestamp. Tolerates "MM/DD/YYYY h:mm:ss AM/PM".
function parseTimestamp(str) {
  if (!str) return null;
  const s = String(str).trim();
  if (!s) return null;
  const d = new Date(s);
  if (!isNaN(d.getTime())) return d;
  const m = s.match(/(\d{1,2})\/(\d{1,2})\/(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})(?:\s*(AM|PM))?/i);
  if (m) {
    let hr = parseInt(m[4], 10);
    const ap = m[7] ? m[7].toUpperCase() : '';
    if (ap === 'PM' && hr !== 12) hr += 12;
    if (ap === 'AM' && hr === 12) hr = 0;
    return new Date(parseInt(m[3], 10), parseInt(m[1], 10) - 1, parseInt(m[2], 10), hr, parseInt(m[5], 10), parseInt(m[6], 10));
  }
  return null;
}

// Quote-aware CSV parser (handles quoted fields, escaped quotes, and newlines inside quotes).
function parseCSV(text) {
  const rows = [];
  let row = [], field = '', inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; }
        else inQuotes = false;
      } else field += c;
    } else {
      if (c === '"') inQuotes = true;
      else if (c === ',') { row.push(field); field = ''; }
      else if (c === '\n' || c === '\r') {
        if (c === '\r' && text[i + 1] === '\n') i++;
        row.push(field); field = '';
        if (row.some((v) => v !== '')) rows.push(row);
        row = [];
      } else field += c;
    }
  }
  if (field !== '' || row.length) { row.push(field); if (row.some((v) => v !== '')) rows.push(row); }
  return rows;
}

// Map flexible column names to canonical keys.
const COLUMN_ALIASES = {
  level: ['level'],
  datetime: ['dateandtime', 'timecreated', 'datetime', 'timestamp', 'date', 'time'],
  source: ['source', 'providername', 'provider'],
  eventid: ['eventid', 'id'],
  taskcategory: ['taskcategory', 'taskdisplayname', 'task'],
  user: ['user', 'accountname', 'username'],
  computer: ['computer', 'machinename', 'hostname', 'host'],
  keywords: ['keywords', 'keywordsdisplaynames'],
  message: ['message', 'details', 'description', 'text']
};

function normalizeKey(key) {
  return String(key == null ? '' : key).replace(/^\uFEFF/, '').trim().toLowerCase().replace(/[^a-z0-9]/g, '');
}

function mapColumns(header) {
  const map = {};
  header.forEach((h, i) => {
    const k = normalizeKey(h);
    for (const canon in COLUMN_ALIASES) {
      if (COLUMN_ALIASES[canon].indexOf(k) !== -1) { map[canon] = i; break; }
    }
  });
  return map;
}

function getCell(cols, row, canon) {
  const idx = cols[canon];
  if (idx == null) return '';
  return row[idx] == null ? '' : String(row[idx]).trim();
}

// Extract "Label: value" fields from a Message string (Windows format or ;-separated demo format).
function extractField(msg, labels, mode) {
  const text = String(msg || '');
  const parts = text.split(/\r?\n|;/);
  const found = [];
  for (const label of labels) {
    const re = new RegExp('^\\s*' + escapeRe(label) + '\\s*:\\s*(.*)$', 'i');
    for (const part of parts) {
      const m = part.match(re);
      if (m && m[1].trim() !== '') found.push(m[1].trim());
    }
    if (found.length) break;
  }
  if (!found.length) return '';
  return mode === 'last' ? found[found.length - 1] : found[0];
}

function looksObfuscated(text) {
  if (!text) return false;
  const s = String(text).trim();
  if (s.length < 60) return false;
  const lower = s.toLowerCase();
  if (/frombase64string|-enc\b|-encodedcommand|-windowstyle\s+hidden|iex\b|invoke-expression|downloadstring|downloadfile/.test(lower)) return true;
  const compact = s.replace(/\s+/g, '');
  if (compact.length >= 100 && /^[A-Za-z0-9+/=]+$/.test(compact)) return true;
  return false;
}
// ---------- Extract context from a Message string ----------
function extractContext(ev) {
  const m = ev.message || '';
  const c = {
    account: '', subjectUser: '', sourceIp: '', workstation: '', logonType: '',
    processName: '', parentProcess: '', commandLine: '', groupName: '', serviceName: '', scriptBlock: ''
  };
  if (!m) return c;
  c.sourceIp = extractField(m, ['Source Network Address', 'Network Address', 'Source IP'], 'first');
  c.workstation = extractField(m, ['Workstation Name', 'Workstation'], 'first');
  c.logonType = extractField(m, ['Logon Type'], 'first');
  c.processName = extractField(m, ['New Process Name', 'Process Name'], 'first');
  c.parentProcess = extractField(m, ['Creator Process Name', 'Parent Process Name'], 'first');
  c.commandLine = extractField(m, ['Process Command Line', 'Command Line'], 'first');
  c.groupName = extractField(m, ['Group Name', 'Security Group Name'], 'first');
  c.serviceName = extractField(m, ['Service Name'], 'first');
  c.scriptBlock = extractField(m, ['ScriptBlock Text', 'Script Block Text'], 'first');

  switch (ev.eventId) {
    case 4624:
    case 4625:
      c.account = extractField(m, ['Account Name'], 'last');
      c.subjectUser = extractField(m, ['Account Name'], 'first');
      break;
    case 4720:
    case 4726:
      c.account = extractField(m, ['New Account Name', 'Target Account Name', 'Account Name'], 'first');
      c.subjectUser = extractField(m, ['Subject User'], 'first');
      break;
    case 4728:
    case 4732:
      c.account = extractField(m, ['Member Name', 'Account Name'], 'first');
      c.subjectUser = extractField(m, ['Subject User'], 'first');
      break;
    case 1102:
      c.account = extractField(m, ['Account Name', 'Subject User'], 'first');
      break;
    case 4688:
      c.account = extractField(m, ['Account Name'], 'last');
      break;
    case 7045:
      c.account = extractField(m, ['Account Name'], 'first');
      break;
    default:
      c.account = extractField(m, ['Account Name', 'User Name', 'Caller User Name'], 'first');
  }
  return c;
}

// ---------- Parse rows into normalised events ----------
function parseEvents(rows) {
  const warnings = [];
  if (!rows.length) throw new Error('The file appears to be empty.');
  const header = rows[0];
  const cols = mapColumns(header);
  if (!('eventid' in cols)) {
    throw new Error('Could not find an "Event ID" column. Please check that the CSV header includes an Event ID column.');
  }
  if (!('message' in cols)) warnings.push('No "Message" column found, so account names and source IPs may be missing from the results.');
  if (!('datetime' in cols)) warnings.push('No "Date and Time" column found, so the timeline and time-window analysis will be limited.');

  const events = [];
  for (let i = 1; i < rows.length; i++) {
    const r = rows[i];
    if (!r.length) continue;
    const rawId = getCell(cols, r, 'eventid');
    const parsedId = parseInt(String(rawId).trim(), 10);
    const ev = {
      idx: i,
      level: getCell(cols, r, 'level'),
      timestamp: getCell(cols, r, 'datetime'),
      date: null,
      source: getCell(cols, r, 'source'),
      eventId: Number.isFinite(parsedId) ? parsedId : null,
      taskCategory: getCell(cols, r, 'taskcategory'),
      user: getCell(cols, r, 'user'),
      computer: getCell(cols, r, 'computer'),
      keywords: getCell(cols, r, 'keywords'),
      message: getCell(cols, r, 'message')
    };
    ev.date = parseTimestamp(ev.timestamp);
    const ctx = extractContext(ev);
    Object.assign(ev, ctx);
    if (!ev.account) ev.account = ev.user;
    events.push(ev);
  }
  return { events, warnings };
}

// ---------- Small helpers for analysis ----------
function groupByAccount(list) {
  const groups = {};
  for (const e of list) {
    const a = norm(e.account);
    if (!a) continue;
    (groups[a] = groups[a] || []).push(e);
  }
  return groups;
}

function mostCommon(arr) {
  const counts = {};
  let best = '', bestN = 0;
  for (const v of arr) {
    if (!v) continue;
    counts[v] = (counts[v] || 0) + 1;
    if (counts[v] > bestN) { bestN = counts[v]; best = v; }
  }
  return best;
}

function uniqueSorted(arr, cmp) {
  const u = Array.from(new Set(arr));
  u.sort(cmp);
  return u;
}

function uniqueAccounts(events) {
  const map = new Map();
  for (const e of events) {
    const a = e.account;
    if (a && !map.has(norm(a))) map.set(norm(a), a);
  }
  return Array.from(map.values()).sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
}

function totalScore(factors) { return factors.reduce((s, f) => s + f.points, 0); }

function isAfter(a, b) {
  if (a.date && b.date) return a.date > b.date;
  return a.idx > b.idx;
}

function fmtTime(e) { return e && e.timestamp ? e.timestamp : 'unknown time'; }

function fmtRange(list) {
  if (!list.length) return '';
  const sorted = list.slice().sort((a, b) => (a.date && b.date) ? a.date - b.date : a.idx - b.idx);
  const first = sorted[0].timestamp || '';
  const last = sorted[sorted.length - 1].timestamp || '';
  if (first && last && first !== last) return first + ' to ' + last;
  return first || last || 'unknown time';
}

function maxBurst(list, windowMs) {
  const sorted = list.filter((e) => e.date).slice().sort((a, b) => a.date - b.date);
  if (sorted.length < 2) return sorted.length;
  let max = 1;
  for (let i = 0; i < sorted.length; i++) {
    let j = i;
    while (j < sorted.length && (sorted[j].date - sorted[i].date) <= windowMs) j++;
    max = Math.max(max, j - i);
  }
  return max;
}
// ---------- Explainable scoring helpers ----------
function scoreFactorsFor(id, privileged) {
  switch (id) {
    case 4720: return [{ label: 'Account created', points: 10 }];
    case 4726: return [{ label: 'Account deleted', points: 5 }];
    case 4728:
    case 4732: return [{ label: privileged ? 'Privileged group membership change' : 'Group membership change', points: privileged ? 25 : 15 }];
    case 7045: return [{ label: 'Service installed', points: 10 }];
    default: return [];
  }
}

// ---------- Core analysis / correlation ----------
function analyze(events, settings) {
  const byId = {};
  for (const e of events) (byId[e.eventId] = byId[e.eventId] || []).push(e);

  const findings = [];
  const threshold = settings.failedLoginThreshold;
  const windowMs = (settings.failedLoginWindowMinutes || 0) * 60000;

  // --- Rule 1 & 2: repeated failed logons, and failures followed by success ---
  const fails = byId[4625] || [];
  const successes = byId[4624] || [];
  const failGroups = groupByAccount(fails);

  for (const account of Object.keys(failGroups)) {
    const failList = failGroups[account];
    if (failList.length < threshold) continue;

    const acctSuccesses = successes.filter((s) => norm(s.account) === account);
    const lastFail = failList.reduce((mx, f) => (isAfter(f, mx) ? f : mx), failList[0]);
    const successAfter = acctSuccesses.filter((s) => isAfter(s, lastFail));
    const ip = mostCommon(failList.map((f) => f.sourceIp).filter(Boolean));
    const ws = mostCommon(failList.map((f) => f.workstation).filter(Boolean));
    const range = fmtRange(failList);
    const burst = (windowMs > 0) ? maxBurst(failList, windowMs) : 0;
    const burstText = (burst && burst > 0) ? ` (peak: ${burst} failures within ${settings.failedLoginWindowMinutes} min)` : '';
    const displayAccount = failList[0].account || account;

    if (successAfter.length > 0) {
      findings.push({
        name: 'Possible Password Guessing Followed by Success',
        severity: 'High', type: 'Authentication',
        eventIds: [4625, 4624], account: displayAccount,
        sourceIp: ip, workstation: ws, timeRange: range,
        failedCount: failList.length, successAfter: true,
        observed: `${failList.length} failed logon attempt(s)${burstText} for account "${displayAccount}" were followed by a successful logon.`,
        why: 'Repeated failed authentication attempts followed by a successful login may indicate that a password was eventually guessed. It could also be a legitimate user eventually entering the correct password.',
        benign: 'The legitimate user may simply have entered the wrong password several times before typing it correctly.',
        investigation: [
          'Verify the source device and IP address.',
          'Determine whether the source IP is expected for this user.',
          'Review what happened after the successful login.',
          'Check whether other accounts experienced similar failures.',
          'Review endpoint or MFA telemetry where available.'
        ],
        score: 30,
        scoreFactors: [
          { label: 'Repeated failed logons', points: 10 },
          { label: 'Successful login following failures', points: 20 }
        ]
      });
    } else {
      findings.push({
        name: 'Repeated Failed Logons',
        severity: 'Medium', type: 'Authentication',
        eventIds: [4625], account: displayAccount,
        sourceIp: ip, workstation: ws, timeRange: range,
        failedCount: failList.length, successAfter: false,
        observed: `${failList.length} failed logon attempt(s)${burstText} for account "${displayAccount}".`,
        why: 'Repeated authentication failures may indicate password guessing, but could also be caused by a legitimate user entering the wrong password or an application using outdated credentials.',
        benign: 'Forgotten password, mistyped password, stale service credentials, or a misconfigured application.',
        investigation: [
          'Identify the source system.',
          'Review the affected account.',
          'Check whether the failures were followed by a successful login.',
          'Determine whether other accounts were targeted.',
          'Review MFA or endpoint telemetry if available.'
        ],
        score: 10,
        scoreFactors: [{ label: 'Repeated failed logons', points: 10 }]
      });
    }
  }
  // --- Rule 3: account created, then added to a group ---
  const created = byId[4720] || [];
  const privAdds = (byId[4728] || []).concat(byId[4732] || []);
  const correlatedAccounts = new Set();

  for (const c of created) {
    const acct = norm(c.account);
    if (!acct) continue;
    const adds = privAdds.filter((p) => norm(p.account) === acct);
    if (!adds.length) continue;
    const group = adds.map((a) => a.groupName).filter(Boolean)[0] || '';
    const privileged = adds.some((a) => isPrivilegedGroup(a.groupName));
    const seq = [4720].concat(adds.map((a) => a.eventId));
    correlatedAccounts.add(acct);
    findings.push({
      name: 'New Account Granted Privileges',
      severity: privileged ? 'High' : 'Medium', type: 'Group / Privilege',
      eventIds: seq, account: c.account, groupName: group,
      timeRange: fmtRange([c].concat(adds)),
      observed: `Account "${c.account}" was created and then added to ${group ? `group "${group}"` : 'a group'}.`,
      why: 'Creating an account and quickly granting it elevated privileges can be legitimate administration, but it may also indicate persistence or privilege escalation.',
      benign: 'Authorised onboarding of a new account that requires group membership.',
      investigation: [
        'Confirm whether the account creation was authorised.',
        'Identify the administrator responsible.',
        'Review activity performed by the account.',
        'Check whether the account is still required.'
      ],
      score: privileged ? 35 : 25,
      scoreFactors: [
        { label: 'Account created', points: 10 },
        { label: privileged ? 'Privileged group membership change' : 'Group membership change', points: privileged ? 25 : 15 }
      ]
    });
  }

  // --- Rule 4: security audit log cleared ---
  const cleared = byId[1102] || [];
  for (const e of cleared) {
    findings.push({
      name: 'Security Audit Log Cleared',
      severity: 'High', type: 'Audit / Log Management',
      eventIds: [1102], account: e.account, timeRange: fmtTime(e),
      observed: 'The Windows Security audit log was cleared.',
      why: 'This event means the Windows Security audit log was cleared. This can happen during legitimate maintenance, but because attackers may clear logs to remove evidence, it should normally be investigated.',
      benign: 'Legitimate maintenance or log-rotation performed by an administrator.',
      investigation: [
        'Confirm who cleared the log and when.',
        'Review activity immediately before the clearing.',
        'Check other log sources (endpoint, firewall, SIEM) for the same window.'
      ],
      score: 30,
      scoreFactors: [{ label: 'Security log cleared', points: 30 }]
    });
  }

  // --- Individual high-value event findings ---
  const individualIds = [4720, 4726, 4728, 4732, 7045];
  for (const id of individualIds) {
    const evs = byId[id] || [];
    const groups = groupByAccount(evs);
    const def = EVENT_DEFS[id];
    for (const account of Object.keys(groups)) {
      if ((id === 4720 || id === 4728 || id === 4732) && correlatedAccounts.has(account)) continue;
      const list = groups[account];
      const privileged = (id === 4728 || id === 4732) && list.some((e) => isPrivilegedGroup(e.groupName));
      const group = list.map((e) => e.groupName).filter(Boolean)[0] || '';
      const factors = scoreFactorsFor(id, privileged);
      findings.push({
        name: def.name,
        severity: privileged ? 'High' : def.severity,
        type: def.type,
        eventIds: [id],
        account: list[0].account,
        groupName: group,
        count: list.length,
        timeRange: fmtRange(list),
        observed: `${list.length} × ${def.name}${list[0].account ? ` for account "${list[0].account}"` : ''}${group ? ` (group "${group}")` : ''}.`,
        why: def.why,
        benign: def.benign,
        investigation: def.investigation,
        score: totalScore(factors),
        scoreFactors: factors
      });
    }
  }

  // --- Obfuscated PowerShell script blocks ---
  const ps = byId[4104] || [];
  const obf = ps.filter((e) => looksObfuscated(e.scriptBlock));
  if (obf.length) {
    findings.push({
      name: 'Obfuscated PowerShell Script Block',
      severity: 'Low', type: 'PowerShell',
      eventIds: [4104], account: obf[0].account, count: obf.length, timeRange: fmtRange(obf),
      observed: `${obf.length} PowerShell script block(s) appear encoded or heavily obfuscated.`,
      why: 'PowerShell script block logging can provide valuable visibility into commands and scripts executed on the endpoint. Heavily obfuscated or encoded commands deserve a closer look, though PowerShell itself is not suspicious.',
      benign: 'Legitimate administrative scripts sometimes use encoding or obfuscation for packaging.',
      investigation: ['Review the script block text.', 'Decode any Base64 content to understand what it does.', 'Check who ran the command and when.'],
      score: 10,
      scoreFactors: [{ label: 'Obfuscated PowerShell', points: 10 }]
    });
  }

  return { findings };
}
// ---------- Dashboard statistics ----------
function computeStats(events, findings) {
  const count = (id) => events.filter((e) => e.eventId === id).length;
  return {
    total: events.length,
    logonSuccess: count(4624),
    logonFailed: count(4625),
    accountsCreated: count(4720),
    privilege: count(4728) + count(4732),
    logClear: count(1102),
    process: count(4688),
    investigate: findings.filter((f) => f.severity !== 'Informational').length
  };
}

function topAccounts(events, limit) {
  const c = {};
  for (const e of events) { const a = norm(e.account); if (a) c[a] = (c[a] || 0) + 1; }
  return Object.entries(c).sort((a, b) => b[1] - a[1]).slice(0, limit || 8);
}

function topFailed(events, limit) {
  const c = {};
  for (const e of events) { if (e.eventId === 4625) { const a = norm(e.account); if (a) c[a] = (c[a] || 0) + 1; } }
  return Object.entries(c).sort((a, b) => b[1] - a[1]).slice(0, limit || 8);
}

function topEventIds(events, limit) {
  const c = {};
  for (const e of events) { if (e.eventId != null) c[e.eventId] = (c[e.eventId] || 0) + 1; }
  return Object.entries(c).sort((a, b) => b[1] - a[1]).slice(0, limit || 10);
}

function buildAdminSummary(events) {
  const counts = { 4720: 0, 4726: 0, 4728: 0, 4732: 0, 7045: 0, 1102: 0 };
  for (const e of events) { if (counts[e.eventId] != null) counts[e.eventId]++; }
  return counts;
}

function buildTimeline(events) {
  const list = events.filter((e) => NOTEWORTHY_IDS.indexOf(e.eventId) !== -1 || (e.eventId === 4104 && looksObfuscated(e.scriptBlock)));
  list.sort((a, b) => (a.date && b.date) ? a.date - b.date : a.idx - b.idx);
  return list;
}
// ---------- Rendering ----------
function renderStats(events, findings) {
  const s = computeStats(events, findings);
  $('stat-total').textContent = s.total;
  $('stat-logon-success').textContent = s.logonSuccess;
  $('stat-logon-failed').textContent = s.logonFailed;
  $('stat-accounts-created').textContent = s.accountsCreated;
  $('stat-privilege').textContent = s.privilege;
  $('stat-log-clear').textContent = s.logClear;
  $('stat-process').textContent = s.process;
  $('stat-investigate').textContent = s.investigate;
}

function renderList(el, entries, emptyText) {
  if (!entries.length) { el.innerHTML = `<li><span class="dim">${esc(emptyText)}</span></li>`; return; }
  el.innerHTML = entries.map(([k, n]) => `<li><span>${esc(k)}</span><span class="dim">${esc(n)}</span></li>`).join('');
}

function renderTopAccounts(events) { renderList($('list-top-accounts'), topAccounts(events), 'No account data found'); }
function renderTopFailed(events) { renderList($('list-top-failed'), topFailed(events), 'No failed logons found'); }

function renderTopEventIds(events) {
  const entries = topEventIds(events);
  const el = $('list-top-eventids');
  if (!entries.length) { el.innerHTML = '<li><span class="dim">No recognised events</span></li>'; return; }
  el.innerHTML = entries.map(([id, n]) => {
    const def = EVENT_DEFS[id];
    const label = def ? `${id} — ${def.name}` : `${id} — other`;
    return `<li><span>${esc(label)}</span><span class="dim">${esc(n)}</span></li>`;
  }).join('');
}

function renderAdminActivity(events) {
  const counts = buildAdminSummary(events);
  const rows = [];
  for (const id of Object.keys(counts)) {
    if (counts[id] > 0) rows.push({ id: +id, name: EVENT_DEFS[id].name, n: counts[id] });
  }
  const panel = $('admin-activity-panel');
  if (!rows.length) { panel.hidden = true; return; }
  panel.hidden = false;
  $('admin-activity').innerHTML = rows.map((r) => `<li><span>${esc(r.id)} · ${esc(r.name)}</span><span class="dim">${esc(r.n)}</span></li>`).join('');
}

function renderTimeline(events) {
  const list = buildTimeline(events);
  const el = $('timeline');
  if (!list.length) { el.innerHTML = '<li><span class="dim">No noteworthy activity with timestamps.</span></li>'; return; }
  el.innerHTML = list.map((e) => {
    const def = EVENT_DEFS[e.eventId];
    const desc = def ? def.name : 'Event';
    const label = e.account ? ` — ${esc(e.account)}` : '';
    return `<li><span class="time">${esc(e.timestamp || 'unknown time')}</span><br><span class="tag">${esc(e.eventId)}</span>${esc(desc)}${label}</li>`;
  }).join('');
}

function renderFinding(f) {
  const sev = f.severity.toLowerCase();
  const meta = [];
  if (f.account) meta.push(`<span><strong>Account:</strong> ${esc(f.account)}</span>`);
  if (f.eventIds && f.eventIds.length) meta.push(`<span><strong>Event ID(s):</strong> ${esc(f.eventIds.join(', '))}</span>`);
  if (f.timeRange) meta.push(`<span><strong>Time:</strong> ${esc(f.timeRange)}</span>`);
  if (f.sourceIp) meta.push(`<span><strong>Source IP:</strong> ${esc(f.sourceIp)}</span>`);
  if (f.workstation) meta.push(`<span><strong>Workstation:</strong> ${esc(f.workstation)}</span>`);
  if (f.groupName) meta.push(`<span><strong>Group:</strong> ${esc(f.groupName)}</span>`);
  if (f.failedCount != null) meta.push(`<span><strong>Failed logins:</strong> ${esc(f.failedCount)}</span>`);
  if (f.successAfter != null) meta.push(`<span><strong>Successful login:</strong> ${f.successAfter ? 'Yes' : 'No'}</span>`);
  const scoreHTML = (f.score > 0 && f.scoreFactors && f.scoreFactors.length) ? `
    <div class="score-badge">
      <strong>Investigation score:</strong> <span class="score-num">${esc(f.score)}</span>
      <ul class="score-factors">${f.scoreFactors.map((sf) => `<li>${esc(sf.points)} — ${esc(sf.label)}</li>`).join('')}</ul>
      <div class="score-note">Educational prioritisation, not a probability of compromise.</div>
    </div>` : '';
  const investigation = (f.investigation || []).map((x) => `<li>${esc(x)}</li>`).join('');
  return `
    <article class="alert alert-${sev}">
      <div class="alert-header">
        <span class="alert-title">${esc(f.name)}</span>
        <span class="severity-badge badge-${sev}">${esc(f.severity)}</span>
      </div>
      <div class="alert-body">
        <p class="kv">${meta.join(' &nbsp;·&nbsp; ')}</p>
        <p><strong>Observed activity:</strong> ${esc(f.observed)}</p>
        <div class="alert-section-title">Why this matters</div>
        <p>${esc(f.why)}</p>
        <div class="alert-section-title">Possible benign explanation</div>
        <p>${esc(f.benign)}</p>
        <div class="alert-section-title">Suggested investigation</div>
        <ol class="alert-list">${investigation}</ol>
        ${scoreHTML}
      </div>
    </article>`;
}

function renderFindings() {
  const data = window.currentData;
  const container = $('findings-container');
  if (!data) return;
  let list = data.findings.filter(matchesFilters);
  list.sort((a, b) => (SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]) || (b.score - a.score));
  if (!list.length) {
    container.innerHTML = '<div class="no-findings"><strong>No findings match the current filters.</strong></div>';
    return;
  }
  container.innerHTML = list.map(renderFinding).join('');
}
// ---------- Filters ----------
const filterState = { search: '', severity: '', eventType: '', account: '', sourceIp: '', eventId: '' };

function matchesFilters(f) {
  const s = filterState.search;
  if (s) {
    const hay = [f.name, f.account, f.severity, f.type, (f.eventIds || []).join(','), f.sourceIp, f.groupName, f.observed].join(' ').toLowerCase();
    if (hay.indexOf(s) === -1) return false;
  }
  if (filterState.severity && f.severity !== filterState.severity) return false;
  if (filterState.eventType && f.type !== filterState.eventType) return false;
  if (filterState.account && norm(f.account) !== filterState.account) return false;
  if (filterState.sourceIp && f.sourceIp !== filterState.sourceIp) return false;
  if (filterState.eventId) {
    const ids = (f.eventIds || []).map(String);
    if (ids.indexOf(String(filterState.eventId)) === -1) return false;
  }
  return true;
}

function eventMatchesFilters(e) {
  const s = filterState.search;
  if (s) {
    const hay = [e.account, e.sourceIp, e.computer, e.message, e.timestamp, e.level, String(e.eventId)].join(' ').toLowerCase();
    if (hay.indexOf(s) === -1) return false;
  }
  if (filterState.eventType) {
    const def = EVENT_DEFS[e.eventId];
    if (!def || def.type !== filterState.eventType) return false;
  }
  if (filterState.account && norm(e.account) !== filterState.account) return false;
  if (filterState.sourceIp && e.sourceIp !== filterState.sourceIp) return false;
  if (filterState.eventId && String(e.eventId) !== String(filterState.eventId)) return false;
  return true;
}

function renderEventsTable() {
  const data = window.currentData;
  const tbody = $('events-table-body');
  if (!data) return;
  const list = data.events.filter(eventMatchesFilters);
  const cap = 500;
  const shown = list.slice(0, cap);
  $('events-table-count').textContent = `Showing ${shown.length} of ${list.length} parsed event(s)${list.length > cap ? ' (table is capped for performance)' : ''}.`;
  if (!shown.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="dim">No events match the current filters.</td></tr>';
    return;
  }
  tbody.innerHTML = shown.map((e) => `
    <tr>
      <td>${esc(e.timestamp || '')}</td>
      <td>${e.eventId != null ? esc(e.eventId) : '?'}</td>
      <td>${esc(e.level || '')}</td>
      <td>${esc(e.account || '')}</td>
      <td>${esc(e.sourceIp || '')}</td>
      <td>${esc(e.computer || '')}</td>
      <td>${esc(e.message || '')}</td>
    </tr>`).join('');
}

function fillSelect(el, options, placeholder) {
  el.innerHTML = (placeholder ? [`<option value="">${esc(placeholder)}</option>`] : []).concat(
    options.map((o) => `<option value="${esc(o)}">${esc(o)}</option>`)
  ).join('');
}

function fillSelectPairs(el, pairs) {
  el.innerHTML = pairs.map((p) => `<option value="${esc(p.value)}">${esc(p.label)}</option>`).join('');
}

function populateFilters(events) {
  fillSelect($('filter-severity'), ['Informational', 'Low', 'Medium', 'High'], 'All severities');
  fillSelect($('filter-eventtype'), CATEGORIES, 'All event types');

  const accounts = uniqueAccounts(events);
  fillSelectPairs($('filter-account'), [{ value: '', label: 'All accounts' }].concat(accounts.map((a) => ({ value: norm(a), label: a }))));

  const ips = uniqueSorted(events.map((e) => e.sourceIp).filter(Boolean));
  fillSelectPairs($('filter-sourceip'), [{ value: '', label: 'All IPs' }].concat(ips.map((ip) => ({ value: ip, label: ip }))));

  const ids = uniqueSorted(events.filter((e) => e.eventId != null).map((e) => String(e.eventId)), (a, b) => parseInt(a, 10) - parseInt(b, 10));
  fillSelectPairs($('filter-eventid'), [{ value: '', label: 'All Event IDs' }].concat(ids.map((id) => {
    const def = EVENT_DEFS[id];
    return { value: id, label: def ? `${id} — ${def.name}` : id };
  })));
}
// ---------- File handling & top-level flow ----------
function readSettings() {
  const t = parseInt($('thresh-failed').value, 10);
  const w = parseInt($('thresh-window').value, 10);
  return {
    failedLoginThreshold: (Number.isFinite(t) && t >= 1) ? t : 5,
    failedLoginWindowMinutes: (Number.isFinite(w) && w >= 0) ? w : 10
  };
}

function showDashboard() {
  dashboard.hidden = false;
  filtersSection.hidden = false;
}

function renderAll() {
  const { events, findings } = window.currentData;
  renderStats(events, findings);
  renderTopAccounts(events);
  renderTopFailed(events);
  renderTopEventIds(events);
  renderAdminActivity(events);
  renderTimeline(events);
  populateFilters(events);
  renderFindings();
  renderEventsTable();
}

function processCSVText(text, filename) {
  const status = uploadStatus;
  let rows;
  try {
    rows = parseCSV(text);
  } catch (err) {
    status.innerHTML = `<span class="err">Could not read the CSV file: ${esc(err.message)}</span>`;
    return;
  }
  if (!rows.length) {
    status.innerHTML = '<span class="err">No data rows found. The file appears to be empty.</span>';
    return;
  }

  let parsed;
  try {
    parsed = parseEvents(rows);
  } catch (err) {
    status.innerHTML = `<span class="err">${esc(err.message)}</span>`;
    return;
  }

  const { events, warnings } = parsed;
  if (!events.length) {
    status.innerHTML = '<span class="err">No valid event rows were found in the file.</span>';
    return;
  }

  const settings = readSettings();
  const { findings } = analyze(events, settings);
  window.currentData = { events, findings, filename };

  const supported = events.filter((e) => EVENT_DEFS[e.eventId]).length;
  let html = `<span class="ok"><strong>&#10003; Parsed successfully.</strong></span>`;
  html += `<br><span class="info">File: <strong>${esc(filename)}</strong> &middot; Events: <strong>${esc(events.length)}</strong> &middot; Recognised event IDs: <strong>${esc(supported)}</strong></span>`;
  if (warnings.length) html += `<br><span class="info">${warnings.map((w) => esc(w)).join('<br>')}</span>`;
  status.innerHTML = html;

  showDashboard();
  renderAll();
}

function handleFile(file) {
  if (!file) return;
  const status = uploadStatus;
  status.innerHTML = '';
  const reader = new FileReader();
  reader.onerror = () => { status.innerHTML = '<span class="err">Could not read the file. Please try again.</span>'; };
  reader.onload = () => { processCSVText(String(reader.result), file.name); };
  reader.readAsText(file);
}

function reanalyzeIfLoaded() {
  if (window.currentData) {
    const settings = readSettings();
    const { findings } = analyze(window.currentData.events, settings);
    window.currentData.findings = findings;
    renderAll();
  }
}

function clearFilters() {
  filterState.search = '';
  filterState.severity = '';
  filterState.eventType = '';
  filterState.account = '';
  filterState.sourceIp = '';
  filterState.eventId = '';
  $('search-input').value = '';
  $('filter-severity').value = '';
  $('filter-eventtype').value = '';
  $('filter-account').value = '';
  $('filter-sourceip').value = '';
  $('filter-eventid').value = '';
  renderFindings();
  renderEventsTable();
}
// ---------- Demo data (embedded so demo buttons work offline / via file://) ----------
const HDR = 'Level,Date and Time,Source,Event ID,Task Category,User,Computer,Keywords,Message';

function demoNormalCSV() {
  return `${HDR}
Information,10/13/2026 8:05:12 AM,Microsoft-Windows-Security-Auditing,4624,Logon,N/A,DC01,Audit Success,"An account was successfully logged on.; Account Name: jsmith; Account Domain: CORP; Logon Type: 2; Workstation Name: WS-042"
Information,10/13/2026 8:12:44 AM,Microsoft-Windows-Security-Auditing,4624,Logon,N/A,DC01,Audit Success,"An account was successfully logged on.; Account Name: alincoln; Account Domain: CORP; Logon Type: 2; Workstation Name: WS-017"
Information,10/13/2026 8:20:03 AM,Microsoft-Windows-Security-Auditing,4624,Logon,N/A,FS01,Audit Success,"An account was successfully logged on.; Account Name: svc-backup; Account Domain: CORP; Logon Type: 3; Workstation Name: FS01; Source Network Address: 10.0.0.12"
Information,10/13/2026 8:31:20 AM,Microsoft-Windows-Security-Auditing,4688,Process Creation,N/A,WS-042,Audit Success,"A new process has been created.; Account Name: jsmith; New Process Name: C:\\Windows\\System32\\notepad.exe; Creator Process Name: C:\\Windows\\explorer.exe; Process Command Line: notepad.exe C:\\Users\\jsmith\\notes.txt"
Information,10/13/2026 9:02:11 AM,Microsoft-Windows-Security-Auditing,4624,Logon,N/A,DC01,Audit Success,"An account was successfully logged on.; Account Name: mturner; Account Domain: CORP; Logon Type: 2; Workstation Name: WS-028"
Information,10/13/2026 9:15:50 AM,Microsoft-Windows-Security-Auditing,4720,User Account Management,N/A,DC01,Audit Success,"A user account was created.; Account Name: intern1; Account Domain: CORP; Subject User: helpdesk"
Information,10/13/2026 9:16:02 AM,Microsoft-Windows-Security-Auditing,4728,Security Group Management,N/A,DC01,Audit Success,"A member was added to a security-enabled global group.; Account Name: rparks; Account Domain: CORP; Group Name: IT Support; Subject User: helpdesk"
Information,10/13/2026 9:40:31 AM,Microsoft-Windows-Security-Auditing,4624,Logon,N/A,DC01,Audit Success,"An account was successfully logged on.; Account Name: rparks; Account Domain: CORP; Logon Type: 2; Workstation Name: WS-005"
Information,10/13/2026 10:05:09 AM,Microsoft-Windows-Security-Auditing,4688,Process Creation,N/A,WS-028,Audit Success,"A new process has been created.; Account Name: mturner; New Process Name: C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE; Creator Process Name: C:\\Windows\\explorer.exe; Process Command Line: WINWORD.EXE"
Information,10/13/2026 10:22:47 AM,Microsoft-Windows-Security-Auditing,4624,Logon,N/A,DC01,Audit Success,"An account was successfully logged on.; Account Name: helpdesk; Account Domain: CORP; Logon Type: 2; Workstation Name: WS-101"
Information,10/13/2026 10:45:33 AM,Microsoft-Windows-Security-Auditing,4624,Logon,N/A,FS01,Audit Success,"An account was successfully logged on.; Account Name: svc-backup; Account Domain: CORP; Logon Type: 3; Workstation Name: FS01; Source Network Address: 10.0.0.12"`;
}

function demoPasswordCSV() {
  const times = ['2:00:05', '2:00:33', '2:01:02', '2:01:47', '2:02:15', '2:02:58', '2:03:41', '2:04:20'];
  const lines = [HDR];
  for (const t of times) {
    lines.push(`Information,10/13/2026 ${t} PM,Microsoft-Windows-Security-Auditing,4625,Logon,N/A,DC01,Audit Failure,"An account failed to log on.; Account Name: jsmith; Account Domain: CORP; Logon Type: 3; Workstation Name: 192.168.1.99; Source Network Address: 192.168.1.99; Failure Reason: Unknown user name or bad password."`);
  }
  lines.push(`Information,10/13/2026 2:05:10 PM,Microsoft-Windows-Security-Auditing,4624,Logon,N/A,DC01,Audit Success,"An account was successfully logged on.; Account Name: jsmith; Account Domain: CORP; Logon Type: 3; Workstation Name: 192.168.1.99; Source Network Address: 192.168.1.99"`);
  return lines.join('\n');
}
function demoPersistenceCSV() {
  return `${HDR}
Information,10/13/2026 11:00:00 PM,Microsoft-Windows-Security-Auditing,4720,User Account Management,N/A,DC01,Audit Success,"A user account was created.; Account Name: temp-admin; Account Domain: CORP; Subject User: unknown"
Information,10/13/2026 11:00:12 PM,Microsoft-Windows-Security-Auditing,4732,Security Group Management,N/A,DC01,Audit Success,"A member was added to a security-enabled local group.; Account Name: temp-admin; Account Domain: CORP; Group Name: Administrators; Subject User: unknown"
Information,10/13/2026 11:01:05 PM,Microsoft-Windows-Security-Auditing,4624,Logon,N/A,DC01,Audit Success,"An account was successfully logged on.; Account Name: temp-admin; Account Domain: CORP; Logon Type: 10; Workstation Name: WS-099; Source Network Address: 172.16.0.44"`;
}

function demoMixedCSV() {
  return `${HDR}
Information,10/13/2026 3:00:10 PM,Microsoft-Windows-Security-Auditing,4625,Logon,N/A,DC01,Audit Failure,"An account failed to log on.; Account Name: jdoe; Account Domain: CORP; Logon Type: 3; Workstation Name: 10.0.0.200; Source Network Address: 10.0.0.200; Failure Reason: Unknown user name or bad password."
Information,10/13/2026 3:00:44 PM,Microsoft-Windows-Security-Auditing,4625,Logon,N/A,DC01,Audit Failure,"An account failed to log on.; Account Name: jdoe; Account Domain: CORP; Logon Type: 3; Workstation Name: 10.0.0.200; Source Network Address: 10.0.0.200; Failure Reason: Unknown user name or bad password."
Information,10/13/2026 3:01:18 PM,Microsoft-Windows-Security-Auditing,4625,Logon,N/A,DC01,Audit Failure,"An account failed to log on.; Account Name: jdoe; Account Domain: CORP; Logon Type: 3; Workstation Name: 10.0.0.200; Source Network Address: 10.0.0.200; Failure Reason: Unknown user name or bad password."
Information,10/13/2026 3:01:52 PM,Microsoft-Windows-Security-Auditing,4625,Logon,N/A,DC01,Audit Failure,"An account failed to log on.; Account Name: jdoe; Account Domain: CORP; Logon Type: 3; Workstation Name: 10.0.0.200; Source Network Address: 10.0.0.200; Failure Reason: Unknown user name or bad password."
Information,10/13/2026 3:02:26 PM,Microsoft-Windows-Security-Auditing,4625,Logon,N/A,DC01,Audit Failure,"An account failed to log on.; Account Name: jdoe; Account Domain: CORP; Logon Type: 3; Workstation Name: 10.0.0.200; Source Network Address: 10.0.0.200; Failure Reason: Unknown user name or bad password."
Information,10/13/2026 3:03:00 PM,Microsoft-Windows-Security-Auditing,4625,Logon,N/A,DC01,Audit Failure,"An account failed to log on.; Account Name: jdoe; Account Domain: CORP; Logon Type: 3; Workstation Name: 10.0.0.200; Source Network Address: 10.0.0.200; Failure Reason: Unknown user name or bad password."
Information,10/13/2026 3:04:15 PM,Microsoft-Windows-Security-Auditing,4624,Logon,N/A,DC01,Audit Success,"An account was successfully logged on.; Account Name: jdoe; Account Domain: CORP; Logon Type: 3; Workstation Name: 10.0.0.200; Source Network Address: 10.0.0.200"
Information,10/13/2026 3:10:00 PM,Microsoft-Windows-Security-Auditing,4720,User Account Management,N/A,DC01,Audit Success,"A user account was created.; Account Name: svc-admin; Account Domain: CORP; Subject User: srvadmin"
Information,10/13/2026 3:10:15 PM,Microsoft-Windows-Security-Auditing,4732,Security Group Management,N/A,DC01,Audit Success,"A member was added to a security-enabled local group.; Account Name: svc-admin; Account Domain: CORP; Group Name: Administrators; Subject User: srvadmin"
Information,10/13/2026 3:12:40 PM,Microsoft-Windows-Security-Auditing,7045,Service Control Manager,N/A,DC01,Audit Success,"A service was installed in the system.; Service Name: UpdaterSvc; Image Path: C:\\Windows\\Temp\\updater.exe; Account Name: SYSTEM"
Information,10/13/2026 3:20:05 PM,Microsoft-Windows-Security-Auditing,1102,Other Logon/Logoff Events,N/A,DC01,Audit Success,"The audit log was cleared.; Account Name: srvadmin; Account Domain: CORP"`;
}
// ---------- Event listeners & init ----------
uploadBtn.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', (e) => handleFile(e.target.files[0]));

dropZone.addEventListener('click', (e) => {
  if (e.target.closest('#upload-btn') || e.target.closest('#file-input')) return;
  fileInput.click();
});
dropZone.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); }
});
['dragover', 'dragenter'].forEach((ev) => dropZone.addEventListener(ev, (e) => { e.preventDefault(); dropZone.classList.add('dragover'); }));
['dragleave', 'drop'].forEach((ev) => dropZone.addEventListener(ev, (e) => { e.preventDefault(); dropZone.classList.remove('dragover'); }));
dropZone.addEventListener('drop', (e) => { if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]); });

$('btn-normal').addEventListener('click', () => processCSVText(demoNormalCSV(), 'Demo: normal-windows-events.csv'));
$('btn-password').addEventListener('click', () => processCSVText(demoPasswordCSV(), 'Demo: password-guessing.csv'));
$('btn-persistence').addEventListener('click', () => processCSVText(demoPersistenceCSV(), 'Demo: account-persistence.csv'));
$('btn-mixed').addEventListener('click', () => processCSVText(demoMixedCSV(), 'Demo: suspicious-admin-activity.csv'));

$('btn-reset').addEventListener('click', () => {
  $('thresh-failed').value = 5;
  $('thresh-window').value = 10;
  reanalyzeIfLoaded();
});
$('thresh-failed').addEventListener('change', reanalyzeIfLoaded);
$('thresh-window').addEventListener('change', reanalyzeIfLoaded);

$('search-input').addEventListener('input', (e) => { filterState.search = e.target.value.trim().toLowerCase(); renderFindings(); renderEventsTable(); });
$('filter-severity').addEventListener('change', (e) => { filterState.severity = e.target.value; renderFindings(); });
$('filter-eventtype').addEventListener('change', (e) => { filterState.eventType = e.target.value; renderFindings(); renderEventsTable(); });
$('filter-account').addEventListener('change', (e) => { filterState.account = e.target.value; renderFindings(); renderEventsTable(); });
$('filter-sourceip').addEventListener('change', (e) => { filterState.sourceIp = e.target.value; renderFindings(); renderEventsTable(); });
$('filter-eventid').addEventListener('change', (e) => { filterState.eventId = e.target.value; renderFindings(); renderEventsTable(); });
$('btn-clear-filters').addEventListener('click', clearFilters);











