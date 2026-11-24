import { db, recomputeRobustZScores, upsertNormalizedIndicator } from './db.ts';
import {
  classifyAndNormalizeToken,
  deriveFeodoAttributes,
  deriveKevAttributes,
  deriveOtxAttributes,
  extractOtxAttackIds,
} from './normalize.ts';
import type {
  CustomIngestAuditItem,
  CustomIngestResponse,
  FeedSourceType,
  PipelineRun,
  PythonModuleSpec,
} from '../src/types.ts';

export async function syncLiveOsintFeeds(): Promise<{
  ok: boolean;
  run: PipelineRun;
  feedErrors: string[];
  feedCounts: Record<string, number>;
}> {
  const startedAt = Date.now();
  const ingestedAt = new Date().toISOString();
  let rawCount = 0;
  let persisted = 0;
  let mergedNewSightings = 0;
  let duplicateSamePulse = 0;
  let dropped = 0;
  const liveSourcesSucceeded: string[] = [];
  const feedErrors: string[] = [];
  const feedCounts: Record<string, number> = {
    'AlienVault OTX': 0,
    'CISA KEV': 0,
    'Abuse.ch Feodo': 0,
  };

  // 1. AlienVault OTX REST API
  try {
    const otxKey = process.env.OTX_API_KEY?.trim();
    const otxUrl = otxKey
      ? 'https://otx.alienvault.com/api/v1/pulses/subscribed?limit=5'
      : 'https://otx.alienvault.com/api/v1/search/pulses?q=cloud+ransomware&limit=5';

    const headers: Record<string, string> = { Accept: 'application/json' };
    if (otxKey) headers['X-OTX-API-KEY'] = otxKey;

    const resp = await fetch(otxUrl, { headers, signal: AbortSignal.timeout(6000) });
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status} ${resp.statusText}`);
    }

    const data = (await resp.json()) as { results?: Array<Record<string, unknown>> };
    const pulses = Array.isArray(data.results) ? data.results.slice(0, 5) : [];
    if (pulses.length === 0) {
      throw new Error('OTX returned zero pulses');
    }

    // Log sample attack_ids structure once for verification
    if (pulses[0]?.attack_ids !== undefined) {
      console.log('[OSINT Sync] Sample OTX attack_ids payload:', JSON.stringify(pulses[0].attack_ids));
    }

    liveSourcesSucceeded.push('AlienVault OTX');
    for (const p of pulses) {
      const pulseId = `otx-${String(p.id || Date.now()).slice(0, 16)}`;
      const title = String(p.name || 'AlienVault OTX Threat Pulse');
      const author = String(p.author_name || 'OTX_Community');
      const adversary = String(p.adversary || 'Unattributed');
      const tlp = String(p.TLP || 'TLP:WHITE').toUpperCase();
      const tags = Array.isArray(p.tags) ? p.tags.slice(0, 6).map(String) : ['osint'];
      const attackIds = extractOtxAttackIds(p.attack_ids);
      const indicators = Array.isArray(p.indicators)
        ? (p.indicators as Array<Record<string, unknown>>).slice(0, 12)
        : [];

      let pulseCleanCount = 0;
      for (const ind of indicators) {
        rawCount++;
        const val = String(ind.indicator || '');
        const derived = deriveOtxAttributes({
          tags,
          attackIds,
          adversary,
          tlp,
          indicatorCount: indicators.length,
          indicatorRole: String(ind.role || ind.description || ''),
        });

        const res = upsertNormalizedIndicator({
          pulseId,
          pulseTitle: title,
          rawToken: val,
          source: 'AlienVault OTX',
          category: derived.category,
          severity: derived.severity,
          confidence: derived.confidence,
          mitreTactic: derived.mitreTactic,
          country: 'GLOBAL',
          asn: adversary !== 'Unattributed' ? adversary : 'OSINT-OTX',
          firstSeen: String(ind.created || p.created || ingestedAt),
          seenAt: ingestedAt,
          isSample: false,
        });

        if (res.outcome === 'persisted') {
          persisted++;
          pulseCleanCount++;
          feedCounts['AlienVault OTX']++;
        } else if (res.outcome === 'new_sighting_merged') {
          mergedNewSightings++;
          pulseCleanCount++;
          feedCounts['AlienVault OTX']++;
        } else if (res.outcome === 'duplicate_in_same_sighting') {
          duplicateSamePulse++;
          pulseCleanCount++;
        } else {
          dropped++;
        }
      }

      db.prepare(`
        INSERT OR REPLACE INTO threat_pulses (
          id, title, source, author, created_at, tlp, adversary, tags,
          raw_indicator_count, cleaned_indicator_count, is_live, is_sample
        ) VALUES (?, ?, 'AlienVault OTX', ?, ?, ?, ?, ?, ?, ?, 1, 0)
      `).run(
        pulseId,
        title,
        author,
        String(p.created || ingestedAt),
        tlp,
        adversary,
        JSON.stringify(tags),
        indicators.length,
        pulseCleanCount
      );
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('[OSINT Sync] AlienVault OTX failed:', msg);
    feedErrors.push(`AlienVault OTX: ${msg}`);
  }

  // 2. CISA Known Exploited Vulnerabilities (KEV) — constant pulse ID 'kev-live', sorted by dateAdded descending
  try {
    const resp = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', {
      signal: AbortSignal.timeout(6000),
    });
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status} ${resp.statusText}`);
    }

    const json = (await resp.json()) as { vulnerabilities?: Array<Record<string, unknown>> };
    const vulns = Array.isArray(json.vulnerabilities) ? [...json.vulnerabilities] : [];
    if (vulns.length === 0) {
      throw new Error('CISA KEV catalog returned empty list');
    }

    vulns.sort((a, b) => {
      const da = new Date(String(a.dateAdded || 0)).getTime();
      const dbTime = new Date(String(b.dateAdded || 0)).getTime();
      return dbTime - da;
    });

    const latest = vulns.slice(0, 10);
    liveSourcesSucceeded.push('CISA KEV');
    const pulseId = 'kev-live';
    let cleanCount = 0;

    for (const vuln of latest) {
      rawCount++;
      const cve = String(vuln.cveID || '');
      const derived = deriveKevAttributes({
        knownRansomwareCampaignUse: String(vuln.knownRansomwareCampaignUse || ''),
        vulnerabilityName: String(vuln.vulnerabilityName || ''),
        shortDescription: String(vuln.shortDescription || ''),
      });

      const publishedAt = vuln.dateAdded ? new Date(String(vuln.dateAdded)).toISOString() : ingestedAt;
      const res = upsertNormalizedIndicator({
        pulseId,
        pulseTitle: 'CISA KEV Live Catalog Sync',
        rawToken: cve,
        source: 'CISA KEV',
        category: derived.category,
        severity: derived.severity,
        confidence: derived.confidence,
        mitreTactic: derived.mitreTactic,
        country: 'GLOBAL',
        asn: String(vuln.vendorProject || 'Vendor Advisory'),
        firstSeen: publishedAt,
        seenAt: ingestedAt,
        isSample: false,
      });

      if (res.outcome === 'persisted') {
        persisted++;
        cleanCount++;
        feedCounts['CISA KEV']++;
      } else if (res.outcome === 'new_sighting_merged') {
        mergedNewSightings++;
        cleanCount++;
        feedCounts['CISA KEV']++;
      } else if (res.outcome === 'duplicate_in_same_sighting') {
        duplicateSamePulse++;
        cleanCount++;
      } else {
        dropped++;
      }
    }

    db.prepare(`
      INSERT OR REPLACE INTO threat_pulses (
        id, title, source, author, created_at, tlp, adversary, tags,
        raw_indicator_count, cleaned_indicator_count, is_live, is_sample
      ) VALUES (?, 'CISA KEV Live Catalog Sync', 'CISA KEV', 'CISA_Catalog_API', ?, 'TLP:CLEAR', 'Active Exploitation', ?, ?, ?, 1, 0)
    `).run(pulseId, ingestedAt, JSON.stringify(['cisa-kev', 'cve', 'live-rest']), latest.length, cleanCount);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('[OSINT Sync] CISA KEV failed:', msg);
    feedErrors.push(`CISA KEV: ${msg}`);
  }

  // 3. Abuse.ch Feodo Tracker — constant pulse ID 'feodo-live', sorted online-first & most recent
  try {
    const resp = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json', {
      signal: AbortSignal.timeout(6000),
    });
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status} ${resp.statusText}`);
    }

    const rawList = (await resp.json()) as Array<Record<string, unknown>>;
    const list = Array.isArray(rawList) ? [...rawList] : [];
    if (list.length === 0) {
      throw new Error('Feodo Tracker returned empty list');
    }

    list.sort((a, b) => {
      const aOnline = String(a.status || '').toLowerCase() === 'online' ? 1 : 0;
      const bOnline = String(b.status || '').toLowerCase() === 'online' ? 1 : 0;
      if (aOnline !== bOnline) return bOnline - aOnline;
      const aTime = new Date(String(a.last_online || a.first_seen || 0)).getTime();
      const bTime = new Date(String(b.last_online || b.first_seen || 0)).getTime();
      return bTime - aTime;
    });

    const slice = list.slice(0, 10);
    liveSourcesSucceeded.push('Abuse.ch Feodo');
    const pulseId = 'feodo-live';
    let cleanCount = 0;

    for (const item of slice) {
      rawCount++;
      const ip = String(item.ip_address || '');
      const port = item.port ? Number(item.port) : undefined;
      const rawWithPort = port ? `${ip}:${port}` : ip;
      const malware = String(item.malware || 'Botnet C2');
      const derived = deriveFeodoAttributes({
        status: String(item.status || 'online'),
        malware,
        port,
      });

      const publishedAt = item.first_seen ? new Date(String(item.first_seen)).toISOString() : ingestedAt;
      const res = upsertNormalizedIndicator({
        pulseId,
        pulseTitle: 'Abuse.ch Feodo C2 IP Blocklist',
        rawToken: rawWithPort,
        source: 'Abuse.ch Feodo',
        category: derived.category,
        severity: derived.severity,
        confidence: derived.confidence,
        mitreTactic: derived.mitreTactic,
        country: String(item.country || 'GLOBAL'),
        asn: `${malware} · ${String(item.as_name || `AS${item.as_number || 'Unknown'}`)}`,
        firstSeen: publishedAt,
        seenAt: ingestedAt,
        isSample: false,
      });

      if (res.outcome === 'persisted') {
        persisted++;
        cleanCount++;
        feedCounts['Abuse.ch Feodo']++;
      } else if (res.outcome === 'new_sighting_merged') {
        mergedNewSightings++;
        cleanCount++;
        feedCounts['Abuse.ch Feodo']++;
      } else if (res.outcome === 'duplicate_in_same_sighting') {
        duplicateSamePulse++;
        cleanCount++;
      } else {
        dropped++;
      }
    }

    db.prepare(`
      INSERT OR REPLACE INTO threat_pulses (
        id, title, source, author, created_at, tlp, adversary, tags,
        raw_indicator_count, cleaned_indicator_count, is_live, is_sample
      ) VALUES (?, 'Abuse.ch Feodo C2 IP Blocklist', 'Abuse.ch Feodo', 'abuse_ch_feed', ?, 'TLP:WHITE', 'Botnet C2', ?, ?, ?, 1, 0)
    `).run(pulseId, ingestedAt, JSON.stringify(['feodo', 'c2', 'botnet']), slice.length, cleanCount);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('[OSINT Sync] Abuse.ch Feodo failed:', msg);
    feedErrors.push(`Abuse.ch Feodo: ${msg}`);
  }

  const allFailed = liveSourcesSucceeded.length === 0;
  const stats = recomputeRobustZScores();
  const durationMs = Math.max(50, Date.now() - startedAt);
  const runId = `run-${Date.now().toString(36)}`;
  const status: PipelineRun['status'] = allFailed
    ? 'Failed'
    : feedErrors.length > 0
      ? 'Partial'
      : 'Live Sync';

  const runRecord: PipelineRun = {
    id: runId,
    timestamp: ingestedAt,
    sourceName: liveSourcesSucceeded.length > 0 ? liveSourcesSucceeded.join(' + ') : 'All Live Feeds Failed',
    rawCount,
    duplicatesRemoved: mergedNewSightings + duplicateSamePulse,
    malformedDropped: dropped,
    normalizedCount: persisted + mergedNewSightings,
    highRecurrenceOutliers: stats.outliers,
    durationMs,
    status,
    errorMessage: feedErrors.length > 0 ? feedErrors.join(' | ') : null,
  };

  db.prepare(`
    INSERT INTO pipeline_runs (
      id, timestamp, source_name, raw_count, duplicates_removed, malformed_dropped,
      normalized_count, anomaly_spikes_detected, duration_ms, status, error_message
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    runRecord.id,
    runRecord.timestamp,
    runRecord.sourceName,
    runRecord.rawCount,
    runRecord.duplicatesRemoved,
    runRecord.malformedDropped,
    runRecord.normalizedCount,
    runRecord.highRecurrenceOutliers,
    runRecord.durationMs,
    runRecord.status,
    runRecord.errorMessage || null
  );

  return {
    ok: !allFailed,
    run: runRecord,
    feedErrors,
    feedCounts,
  };
}

export function ingestCustomBatch(rawText: string, sourceLabel: FeedSourceType = 'Manual Batch'): CustomIngestResponse {
  const startedAt = Date.now();
  const tokens = rawText
    .split(/[\s,;|\n\r]+/)
    .map((t) => t.trim())
    .filter(Boolean)
    .slice(0, 200);

  const audit: CustomIngestAuditItem[] = [];
  let persistedNew = 0;
  let duplicatesMerged = 0;
  let droppedInvalid = 0;

  const pulseId = `manual-${Date.now().toString(36)}`;
  const pulseTitle = `Manual Batch Ingestion (${sourceLabel})`;

  for (const token of tokens) {
    const check = classifyAndNormalizeToken(token);
    if (!check.valid || !check.normalized || check.type === 'Invalid') {
      droppedInvalid++;
      audit.push({
        rawToken: token,
        normalizedValue: null,
        type: 'Invalid',
        action: 'Dropped (Private/Malformed)',
        reason: check.note,
      });
      continue;
    }

    // Pasted batches are unlabeled user input — mark Unclassified instead of guessing severity/confidence
    const res = upsertNormalizedIndicator({
      pulseId,
      pulseTitle,
      rawToken: token,
      source: sourceLabel,
      category: 'Unclassified',
      severity: 'Unclassified',
      confidence: 0,
      mitreTactic: 'Unclassified',
      country: 'UNKNOWN',
      asn: 'Manual Batch Input',
      isSample: false,
    });

    if (res.outcome === 'persisted') {
      persistedNew++;
      audit.push({
        rawToken: token,
        normalizedValue: check.normalized,
        type: check.type,
        action: 'Persisted',
        reason: check.note,
      });
    } else {
      duplicatesMerged++;
      audit.push({
        rawToken: token,
        normalizedValue: check.normalized,
        type: check.type,
        action: 'Merged Duplicate',
        reason: res.note || 'Merged on existing normalized IOC',
      });
    }
  }

  if (persistedNew + duplicatesMerged > 0) {
    db.prepare(`
      INSERT OR REPLACE INTO threat_pulses (
        id, title, source, author, created_at, tlp, adversary, tags,
        raw_indicator_count, cleaned_indicator_count, is_live, is_sample
      ) VALUES (?, ?, ?, 'Analyst_Manual_Batch', ?, 'TLP:AMBER', 'Unattributed', ?, ?, ?, 0, 0)
    `).run(
      pulseId,
      pulseTitle,
      sourceLabel,
      new Date().toISOString(),
      JSON.stringify(['manual-batch', 'normalized']),
      tokens.length,
      persistedNew + duplicatesMerged
    );
  }

  const stats = recomputeRobustZScores();
  const durationMs = Math.max(15, Date.now() - startedAt);

  db.prepare(`
    INSERT INTO pipeline_runs (
      id, timestamp, source_name, raw_count, duplicates_removed, malformed_dropped,
      normalized_count, anomaly_spikes_detected, duration_ms, status, error_message
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Completed', NULL)
  `).run(
    `run-${Date.now().toString(36)}`,
    new Date().toISOString(),
    `Manual Batch (${sourceLabel})`,
    tokens.length,
    duplicatesMerged,
    droppedInvalid,
    persistedNew + duplicatesMerged,
    stats.outliers,
    durationMs
  );

  return {
    summary: {
      rawTokens: tokens.length,
      persistedNew,
      duplicatesMerged,
      droppedInvalid,
      durationMs,
    },
    audit,
  };
}

export const PYTHON_MODULES: PythonModuleSpec[] = [
  {
    filename: 'otx_collector.py',
    title: 'AlienVault OTX REST Collector (Standalone Template)',
    stage: 'Reference Template · Collection',
    libraries: ['requests', 'os', 'datetime'],
    description:
      'Optional standalone Python script illustrating AlienVault OTX v1 pulse polling outside this Node/TypeScript runtime.',
    code: `import os
import requests
from datetime import datetime, timezone

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
API_KEY = os.getenv("OTX_API_KEY", "")

def fetch_otx_pulses(limit: int = 25, query: str = "cloud ransomware") -> list[dict]:
    headers = {"Accept": "application/json"}
    if API_KEY:
        headers["X-OTX-API-KEY"] = API_KEY
        url = f"{OTX_BASE_URL}/pulses/subscribed?limit={limit}"
    else:
        url = f"{OTX_BASE_URL}/search/pulses?q={query}&limit={limit}"

    response = requests.get(url, headers=headers, timeout=15)
    response.raise_for_status()
    payload = response.json()

    pulses = []
    for pulse in payload.get("results", []):
        pulses.append({
            "pulse_id": pulse.get("id"),
            "title": pulse.get("name"),
            "author": pulse.get("author_name"),
            "adversary": pulse.get("adversary") or "Unattributed",
            "tags": pulse.get("tags", []),
            "attack_ids": [
                a.get("id") if isinstance(a, dict) else a
                for a in pulse.get("attack_ids", [])
            ],
            "ingested_at": datetime.now(timezone.utc).isoformat(),
            "indicators": pulse.get("indicators", []),
        })
    return pulses`,
  },
  {
    filename: 'pandas_numpy_analyzer.py',
    title: 'Pandas & NumPy Cleaning Template (Standalone)',
    stage: 'Reference Template · Analysis',
    libraries: ['pandas', 'numpy', 'ipaddress'],
    description:
      'Optional standalone Python script showing how exported CSV data can be analyzed offline with Pandas and NumPy.',
    code: `import ipaddress
import numpy as np
import pandas as pd

def normalize_indicator(val: str) -> str:
    cleaned = str(val).strip().replace("[.]", ".").replace("hxxp", "http")
    if ":" in cleaned and not cleaned.startswith("http"):
        cleaned = cleaned.split(":", 1)[0]
    return cleaned.upper() if cleaned.upper().startswith("CVE-") else cleaned.lower()

def is_public_ip(val: str) -> bool:
    try:
        return ipaddress.ip_address(val).is_global
    except ValueError:
        return True

def consolidate_and_score(raw_records: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(raw_records).dropna(subset=["raw_indicator"])
    df["normalized_indicator"] = df["raw_indicator"].apply(normalize_indicator)
    df = df[df["normalized_indicator"].apply(is_public_ip)]

    df = df.drop_duplicates(subset=["normalized_indicator", "source", "pulse_id"])
    grouped = (
        df.groupby(["normalized_indicator", "ioc_type"], as_index=False)
        .agg(recurrence_count=("pulse_id", "count"))
    )

    counts = grouped["recurrence_count"].to_numpy(dtype=float)
    median_val = float(np.median(counts))
    mad_val = float(np.median(np.abs(counts - median_val)))
    grouped["robust_z"] = np.round(0.6745 * (counts - median_val) / mad_val, 2) if mad_val > 0 else 0.0
    grouped["is_high_recurrence_outlier"] = grouped["robust_z"] >= 1.5
    return grouped.sort_values(by=["robust_z", "recurrence_count"], ascending=False)`,
  },
];
