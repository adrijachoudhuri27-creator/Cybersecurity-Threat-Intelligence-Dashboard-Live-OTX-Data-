import Database from 'better-sqlite3';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { classifyAndNormalizeToken, computeRobustZScores } from './normalize.ts';
import type { FeedSourceType, IndicatorType, ThreatSeverity, ThreatStatus } from '../src/types.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');

export const DB_PATH = path.resolve(ROOT_DIR, 'threat_intel.db');
export const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS threat_pulses (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    source TEXT NOT NULL,
    author TEXT NOT NULL,
    created_at TEXT NOT NULL,
    tlp TEXT NOT NULL,
    adversary TEXT NOT NULL,
    tags TEXT NOT NULL,
    raw_indicator_count INTEGER NOT NULL,
    cleaned_indicator_count INTEGER NOT NULL,
    is_live INTEGER NOT NULL DEFAULT 0,
    is_sample INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS threat_indicators (
    id TEXT PRIMARY KEY,
    pulse_id TEXT NOT NULL,
    pulse_title TEXT NOT NULL,
    indicator TEXT NOT NULL,
    normalized_indicator TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    source TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence_score INTEGER NOT NULL,
    recurrence_count INTEGER NOT NULL DEFAULT 1,
    z_score REAL NOT NULL DEFAULT 0,
    mitre_tactic TEXT NOT NULL,
    country TEXT NOT NULL,
    asn TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Active',
    raw_sample TEXT NOT NULL,
    cleaning_notes TEXT NOT NULL,
    is_sample INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS sightings (
    id TEXT PRIMARY KEY,
    normalized_indicator TEXT NOT NULL,
    source TEXT NOT NULL,
    pulse_id TEXT NOT NULL,
    seen_at TEXT NOT NULL,
    UNIQUE(normalized_indicator, source, pulse_id)
  );

  CREATE TABLE IF NOT EXISTS pipeline_runs (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source_name TEXT NOT NULL,
    raw_count INTEGER NOT NULL,
    duplicates_removed INTEGER NOT NULL,
    malformed_dropped INTEGER NOT NULL,
    normalized_count INTEGER NOT NULL,
    anomaly_spikes_detected INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    status TEXT NOT NULL,
    error_message TEXT
  );
`);

export function recomputeRobustZScores(): { median: number; mad: number; outliers: number } {
  const syncCountsTx = db.transaction(() => {
    db.prepare(`
      UPDATE threat_indicators
      SET recurrence_count = COALESCE(
        (SELECT COUNT(*) FROM sightings WHERE sightings.normalized_indicator = threat_indicators.normalized_indicator),
        1
      )
    `).run();
  });
  syncCountsTx();

  const rows = db
    .prepare('SELECT id, recurrence_count FROM threat_indicators')
    .all() as Array<{ id: string; recurrence_count: number }>;

  if (rows.length === 0) return { median: 0, mad: 0, outliers: 0 };

  const values = rows.map((r) => r.recurrence_count);
  const { medianVal, madVal, zScores } = computeRobustZScores(values);

  const updateStmt = db.prepare('UPDATE threat_indicators SET z_score = ? WHERE id = ?');
  let outliers = 0;

  const updateTx = db.transaction(() => {
    rows.forEach((row, idx) => {
      const z = zScores[idx];
      if (z >= 1.5) outliers++;
      updateStmt.run(z, row.id);
    });
  });
  updateTx();

  return { median: medianVal, mad: madVal, outliers };
}

export function upsertNormalizedIndicator(params: {
  pulseId: string;
  pulseTitle: string;
  rawToken: string;
  source: FeedSourceType;
  category: string;
  severity: ThreatSeverity;
  confidence: number;
  mitreTactic: string;
  country: string;
  asn: string;
  seenAt?: string;
  isSample?: boolean;
}): { outcome: 'persisted' | 'duplicate_in_same_sighting' | 'new_sighting_merged' | 'dropped'; normalized?: string; type?: IndicatorType; note?: string } {
  const check = classifyAndNormalizeToken(params.rawToken);
  if (!check.valid || !check.normalized || check.type === 'Invalid') {
    return { outcome: 'dropped', note: check.note };
  }

  const normalizedKey = check.normalized;
  const seenAt = params.seenAt || new Date().toISOString();
  const isSampleInt = params.isSample ? 1 : 0;

  const sightingId = `sight-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
  const sightingInsert = db
    .prepare(`
      INSERT OR IGNORE INTO sightings (id, normalized_indicator, source, pulse_id, seen_at)
      VALUES (?, ?, ?, ?, ?)
    `)
    .run(sightingId, normalizedKey, params.source, params.pulseId, seenAt);

  const existing = db
    .prepare('SELECT id, is_sample FROM threat_indicators WHERE normalized_indicator = ?')
    .get(normalizedKey) as { id: string; is_sample: number } | undefined;

  if (existing) {
    // If a live feed confirms a previously seeded sample indicator, promote it to non-sample
    const nextSampleFlag = isSampleInt === 0 ? 0 : existing.is_sample;
    db.prepare(`
      UPDATE threat_indicators
      SET last_seen = CASE WHEN last_seen < ? THEN ? ELSE last_seen END,
          confidence_score = MAX(confidence_score, ?),
          is_sample = ?
      WHERE id = ?
    `).run(seenAt, seenAt, params.confidence, nextSampleFlag, existing.id);

    return {
      outcome: sightingInsert.changes > 0 ? 'new_sighting_merged' : 'duplicate_in_same_sighting',
      normalized: normalizedKey,
      type: check.type,
      note:
        sightingInsert.changes > 0
          ? 'Recorded distinct cross-feed sighting on existing IOC'
          : 'Already recorded for this pulse & source (no recurrence inflation)',
    };
  }

  const id = `ioc-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
  db.prepare(`
    INSERT INTO threat_indicators (
      id, pulse_id, pulse_title, indicator, normalized_indicator, type, source,
      category, severity, confidence_score, recurrence_count, z_score, mitre_tactic,
      country, asn, first_seen, last_seen, status, raw_sample, cleaning_notes, is_sample
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?, ?, ?, ?, 'Active', ?, ?, ?)
  `).run(
    id,
    params.pulseId,
    params.pulseTitle,
    check.normalized,
    normalizedKey,
    check.type,
    params.source,
    params.category,
    params.severity,
    params.confidence,
    params.mitreTactic,
    params.country,
    params.asn,
    seenAt,
    seenAt,
    params.rawToken,
    check.note,
    isSampleInt
  );

  return {
    outcome: 'persisted',
    normalized: normalizedKey,
    type: check.type,
    note: check.note,
  };
}

export function seedSampleIntel() {
  const countRow = db.prepare('SELECT COUNT(*) as count FROM threat_indicators').get() as { count: number };
  if (countRow.count > 0) return;

  const now = Date.now();
  const isoHoursAgo = (h: number) => new Date(now - h * 3600_000).toISOString();

  // Sample pulses clearly marked is_sample = 1 so UI distinguishes fixture samples from live REST syncs
  const samplePulses = [
    {
      id: 'sample-otx-iam',
      title: '[Sample] Cloud IAM Token Abuse & Lookalike SSO Infrastructure',
      source: 'AlienVault OTX' as FeedSourceType,
      author: 'Sample Fixture',
      createdAt: isoHoursAgo(18),
      tlp: 'TLP:WHITE',
      adversary: 'Sample Threat Group A',
      tags: JSON.stringify(['sample', 'cloud-iam', 'phishing', 'sts-token']),
      rawIndicatorCount: 5,
      cleanedIndicatorCount: 4,
    },
    {
      id: 'sample-sel-k8s',
      title: '[Sample] Web Advisory Extract: Container Runtime & Ingress Exploitation',
      source: 'Selenium Web Scraper' as FeedSourceType,
      author: 'Sample Fixture',
      createdAt: isoHoursAgo(36),
      tlp: 'TLP:WHITE',
      adversary: 'Sample Threat Group B',
      tags: JSON.stringify(['sample', 'kubernetes', 'container', 'cryptojacking']),
      rawIndicatorCount: 4,
      cleanedIndicatorCount: 3,
    },
    {
      id: 'sample-kev-edge',
      title: '[Sample] Edge Gateway & VPN Known Exploited Vulnerabilities',
      source: 'CISA KEV' as FeedSourceType,
      author: 'Sample Fixture',
      createdAt: isoHoursAgo(54),
      tlp: 'TLP:CLEAR',
      adversary: 'Sample Exploited CVEs',
      tags: JSON.stringify(['sample', 'kev', 'rce', 'edge-appliance']),
      rawIndicatorCount: 3,
      cleanedIndicatorCount: 3,
    },
    {
      id: 'sample-feodo-c2',
      title: '[Sample] Botnet Command & Control Infrastructure Snapshot',
      source: 'Abuse.ch Feodo' as FeedSourceType,
      author: 'Sample Fixture',
      createdAt: isoHoursAgo(72),
      tlp: 'TLP:WHITE',
      adversary: 'Sample Botnet C2',
      tags: JSON.stringify(['sample', 'c2', 'botnet']),
      rawIndicatorCount: 3,
      cleanedIndicatorCount: 2,
    },
  ];

  const insertPulse = db.prepare(`
    INSERT INTO threat_pulses (id, title, source, author, created_at, tlp, adversary, tags, raw_indicator_count, cleaned_indicator_count, is_live, is_sample)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1)
  `);

  for (const p of samplePulses) {
    insertPulse.run(p.id, p.title, p.source, p.author, p.createdAt, p.tlp, p.adversary, p.tags, p.rawIndicatorCount, p.cleanedIndicatorCount);
  }

  // Note: Zero RFC1918, zero TEST-NET documentation IPs (198.51.100.x), and zero famous empty/test SHA-256 hashes.
  const sampleIndicators: Array<{
    id: string;
    pulseId: string;
    pulseTitle: string;
    rawToken: string;
    source: FeedSourceType;
    category: string;
    severity: ThreatSeverity;
    confidence: number;
    tactic: string;
    country: string;
    asn: string;
    hoursAgo: number;
    status: ThreatStatus;
    extraSightings: Array<{ source: FeedSourceType; pulseId: string; hoursAgo: number }>;
  }> = [
    {
      id: 'sample-ioc-01',
      pulseId: 'sample-otx-iam',
      pulseTitle: '[Sample] Cloud IAM Token Abuse & Lookalike SSO Infrastructure',
      rawToken: '185[.]220[.]101[.]44',
      source: 'AlienVault OTX',
      category: 'Credential Harvesting',
      severity: 'Critical',
      confidence: 94,
      tactic: 'Credential Access',
      country: 'DE',
      asn: 'Sample ASN',
      hoursAgo: 12,
      status: 'Active',
      extraSightings: [
        { source: 'Selenium Web Scraper', pulseId: 'sample-sel-k8s', hoursAgo: 30 },
        { source: 'Abuse.ch Feodo', pulseId: 'sample-feodo-c2', hoursAgo: 48 },
        { source: 'AlienVault OTX', pulseId: 'sample-otx-mirror-1', hoursAgo: 66 },
        { source: 'Selenium Web Scraper', pulseId: 'sample-sel-mirror-2', hoursAgo: 90 },
      ],
    },
    {
      id: 'sample-ioc-02',
      pulseId: 'sample-feodo-c2',
      pulseTitle: '[Sample] Botnet Command & Control Infrastructure Snapshot',
      rawToken: '91.92.240.118:443',
      source: 'Abuse.ch Feodo',
      category: 'C2 Infrastructure',
      severity: 'Critical',
      confidence: 95,
      tactic: 'Command & Control',
      country: 'BG',
      asn: 'Sample ASN',
      hoursAgo: 10,
      status: 'Active',
      extraSightings: [
        { source: 'AlienVault OTX', pulseId: 'sample-otx-iam', hoursAgo: 28 },
        { source: 'Selenium Web Scraper', pulseId: 'sample-sel-k8s', hoursAgo: 52 },
        { source: 'Abuse.ch Feodo', pulseId: 'sample-feodo-mirror-1', hoursAgo: 80 },
      ],
    },
    {
      id: 'sample-ioc-03',
      pulseId: 'sample-kev-edge',
      pulseTitle: '[Sample] Edge Gateway & VPN Known Exploited Vulnerabilities',
      rawToken: 'CVE-2024-3400',
      source: 'CISA KEV',
      category: 'Cloud API Exploit',
      severity: 'Critical',
      confidence: 99,
      tactic: 'Initial Access',
      country: 'GLOBAL',
      asn: 'Vendor Advisory',
      hoursAgo: 16,
      status: 'Active',
      extraSightings: [
        { source: 'AlienVault OTX', pulseId: 'sample-otx-iam', hoursAgo: 40 },
        { source: 'Selenium Web Scraper', pulseId: 'sample-sel-k8s', hoursAgo: 62 },
      ],
    },
    {
      id: 'sample-ioc-04',
      pulseId: 'sample-otx-iam',
      pulseTitle: '[Sample] Cloud IAM Token Abuse & Lookalike SSO Infrastructure',
      rawToken: 'SSO-Okta-CloudVerify[.]com',
      source: 'AlienVault OTX',
      category: 'Credential Harvesting',
      severity: 'High',
      confidence: 89,
      tactic: 'Initial Access',
      country: 'US',
      asn: 'Sample ASN',
      hoursAgo: 20,
      status: 'Investigating',
      extraSightings: [
        { source: 'Selenium Web Scraper', pulseId: 'sample-sel-k8s', hoursAgo: 44 },
      ],
    },
    {
      id: 'sample-ioc-05',
      pulseId: 'sample-sel-k8s',
      pulseTitle: '[Sample] Web Advisory Extract: Container Runtime & Ingress Exploitation',
      rawToken: '45.155.205.91',
      source: 'Selenium Web Scraper',
      category: 'Cloud API Exploit',
      severity: 'High',
      confidence: 86,
      tactic: 'Execution',
      country: 'NL',
      asn: 'Sample ASN',
      hoursAgo: 26,
      status: 'Active',
      extraSightings: [
        { source: 'AlienVault OTX', pulseId: 'sample-otx-iam', hoursAgo: 58 },
      ],
    },
    {
      id: 'sample-ioc-06',
      pulseId: 'sample-otx-iam',
      pulseTitle: '[Sample] Cloud IAM Token Abuse & Lookalike SSO Infrastructure',
      rawToken: 'hxxps://cdn-s3-artifacts[.]top/drop/stage2.bin',
      source: 'AlienVault OTX',
      category: 'Malware Distribution',
      severity: 'High',
      confidence: 88,
      tactic: 'Execution',
      country: 'RU',
      asn: 'Sample ASN',
      hoursAgo: 32,
      status: 'Investigating',
      extraSightings: [],
    },
    {
      id: 'sample-ioc-07',
      pulseId: 'sample-kev-edge',
      pulseTitle: '[Sample] Edge Gateway & VPN Known Exploited Vulnerabilities',
      rawToken: 'CVE-2024-47575',
      source: 'CISA KEV',
      category: 'Ransomware & Extortion',
      severity: 'Critical',
      confidence: 99,
      tactic: 'Impact',
      country: 'GLOBAL',
      asn: 'Vendor Advisory',
      hoursAgo: 42,
      status: 'Investigating',
      extraSightings: [
        { source: 'Selenium Web Scraper', pulseId: 'sample-sel-k8s', hoursAgo: 70 },
      ],
    },
    {
      id: 'sample-ioc-08',
      pulseId: 'sample-sel-k8s',
      pulseTitle: '[Sample] Web Advisory Extract: Container Runtime & Ingress Exploitation',
      rawToken: 'k8s-metrics-collector[.]xyz',
      source: 'Selenium Web Scraper',
      category: 'Cloud API Exploit',
      severity: 'Medium',
      confidence: 81,
      tactic: 'Persistence',
      country: 'SG',
      asn: 'Sample ASN',
      hoursAgo: 50,
      status: 'Active',
      extraSightings: [],
    },
    {
      id: 'sample-ioc-09',
      pulseId: 'sample-feodo-c2',
      pulseTitle: '[Sample] Botnet Command & Control Infrastructure Snapshot',
      rawToken: '193.233.132.18',
      source: 'Abuse.ch Feodo',
      category: 'C2 Infrastructure',
      severity: 'High',
      confidence: 90,
      tactic: 'Command & Control',
      country: 'RO',
      asn: 'Sample ASN',
      hoursAgo: 64,
      status: 'Mitigated',
      extraSightings: [],
    },
    {
      id: 'sample-ioc-10',
      pulseId: 'sample-kev-edge',
      pulseTitle: '[Sample] Edge Gateway & VPN Known Exploited Vulnerabilities',
      rawToken: 'CVE-2024-21887',
      source: 'CISA KEV',
      category: 'Supply Chain / CVE',
      severity: 'High',
      confidence: 94,
      tactic: 'Initial Access',
      country: 'GLOBAL',
      asn: 'Vendor Advisory',
      hoursAgo: 84,
      status: 'Mitigated',
      extraSightings: [],
    },
  ];

  const insertSighting = db.prepare(`
    INSERT OR IGNORE INTO sightings (id, normalized_indicator, source, pulse_id, seen_at)
    VALUES (?, ?, ?, ?, ?)
  `);

  for (const item of sampleIndicators) {
    const res = upsertNormalizedIndicator({
      pulseId: item.pulseId,
      pulseTitle: item.pulseTitle,
      rawToken: item.rawToken,
      source: item.source,
      category: item.category,
      severity: item.severity,
      confidence: item.confidence,
      mitreTactic: item.tactic,
      country: item.country,
      asn: item.asn,
      seenAt: isoHoursAgo(item.hoursAgo),
      isSample: true,
    });

    if (res.normalized) {
      db.prepare('UPDATE threat_indicators SET status = ? WHERE normalized_indicator = ?').run(
        item.status,
        res.normalized
      );
      for (const extra of item.extraSightings) {
        insertSighting.run(
          `sight-${Math.random().toString(36).slice(2, 10)}`,
          res.normalized,
          extra.source,
          extra.pulseId,
          isoHoursAgo(extra.hoursAgo)
        );
      }
    }
  }

  recomputeRobustZScores();
}
