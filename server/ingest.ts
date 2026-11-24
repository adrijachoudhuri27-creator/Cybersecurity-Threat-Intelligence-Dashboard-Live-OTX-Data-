import { db, recomputeRobustZScores, upsertNormalizedIndicator } from './db.ts';
import {
  classifyAndNormalizeToken,
  deriveFeodoAttributes,
  deriveKevAttributes,
  deriveOtxAttributes,
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
}> {
  const startedAt = Date.now();
  let rawCount = 0;
  let persisted = 0;
  let mergedNewSightings = 0;
  let duplicateSamePulse = 0;
  let dropped = 0;
  const liveSourcesSucceeded: string[] = [];
  const feedErrors: string[] = [];

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

    liveSourcesSucceeded.push('AlienVault OTX');
    for (const p of pulses) {
      const pulseId = `otx-${String(p.id || Date.now()).slice(0, 16)}`;
      const title = String(p.name || 'AlienVault OTX Threat Pulse');
      const author = String(p.author_name || 'OTX_Community');
      const adversary = String(p.adversary || 'Unattributed');
      const tlp = String(p.TLP || 'TLP:WHITE').toUpperCase();
      const tags = Array.isArray(p.tags) ? p.tags.slice(0, 6).map(String) : ['osint'];
      const attackIds = Array.isArray(p.attack_ids) ? p.attack_ids.map(String) : [];
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
          seenAt: String(ind.created || p.created || new Date().toISOString()),
          isSample: false,
        });

        if (res.outcome === 'persisted') {
          persisted++;
          pulseCleanCount++;
        } else if (res.outcome === 'new_sighting_merged') {
          mergedNewSightings++;
          pulseCleanCount++;
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
        String(p.created || new Date().toISOString()),
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

  // 2. CISA Known Exploited Vulnerabilities (KEV) — explicitly sorted by dateAdded descending
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
    const pulseId = `kev-live-${new Date().toISOString().slice(0, 10)}`;
    let cleanCount = 0;

    for (const vuln of latest) {
      rawCount++;
      const cve = String(vuln.cveID || '');
      const derived = deriveKevAttributes({
        knownRansomwareCampaignUse: String(vuln.knownRansomwareCampaignUse || ''),
        vulnerabilityName: String(vuln.vulnerabilityName || ''),
        shortDescription: String(vuln.shortDescription || ''),
      });

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
        seenAt: vuln.dateAdded ? new Date(String(vuln.dateAdded)).toISOString() : new Date().toISOString(),
        isSample: false,
      });

      if (res.outcome === 'persisted') {
        persisted++;
        cleanCount++;
      } else if (res.outcome === 'new_sighting_merged') {
        mergedNewSightings++;
        cleanCount++;
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
    `).run(pulseId, new Date().toISOString(), JSON.stringify(['cisa-kev', 'cve', 'live-rest']), latest.length, cleanCount);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('[OSINT Sync] CISA KEV failed:', msg);
    feedErrors.push(`CISA KEV: ${msg}`);
  }

  // 3. Abuse.ch Feodo Tracker Live C2 Blocklist — derive severity/confidence from status & malware family
  try {
    const resp = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json', {
      signal: AbortSignal.timeout(6000),
    });
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status} ${resp.statusText}`);
    }

    const list = (await resp.json()) as Array<Record<string, unknown>>;
    const slice = Array.isArray(list) ? list.slice(0, 10) : [];
    if (slice.length === 0) {
      throw new Error('Feodo Tracker returned empty list');
    }

    liveSourcesSucceeded.push('Abuse.ch Feodo');
    const pulseId = `feodo-live-${new Date().toISOString().slice(0, 10)}`;
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
        seenAt: item.first_seen ? new Date(String(item.first_seen)).toISOString() : new Date().toISOString(),
        isSample: false,
      });

      if (res.outcome === 'persisted') {
        persisted++;
        cleanCount++;
      } else if (res.outcome === 'new_sighting_merged') {
        mergedNewSightings++;
        cleanCount++;
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
    `).run(pulseId, new Date().toISOString(), JSON.stringify(['feodo', 'c2', 'botnet']), slice.length, cleanCount);
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
    timestamp: new Date().toISOString(),
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
  };
}

export function ingestCustomBatch(rawText: string, sourceLabel: FeedSourceType): CustomIngestResponse {
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

  const pulseId = `custom-${Date.now().toString(36)}`;
  const pulseTitle = `Consolidated Ingestion Batch (${sourceLabel})`;

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

    const category =
      check.type === 'CVE'
        ? 'Supply Chain / CVE'
        : check.type === 'SHA256'
          ? 'Malware Distribution'
          : check.type === 'URL'
            ? 'Credential Harvesting'
            : 'C2 Infrastructure';

    const res = upsertNormalizedIndicator({
      pulseId,
      pulseTitle,
      rawToken: token,
      source: sourceLabel,
      category,
      severity: check.type === 'CVE' ? 'Critical' : 'High',
      confidence: 85,
      mitreTactic: check.type === 'CVE' ? 'Initial Access' : 'Command & Control',
      country: 'GLOBAL',
      asn: 'Manual / Scraped Batch',
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
      ) VALUES (?, ?, ?, 'Analyst_Batch_Pipeline', ?, 'TLP:AMBER', 'Manual / Scraped Batch', ?, ?, ?, 0, 0)
    `).run(
      pulseId,
      pulseTitle,
      sourceLabel,
      new Date().toISOString(),
      JSON.stringify(['cleaned-batch', 'pandas-pipeline']),
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
    `Custom Batch (${sourceLabel})`,
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
    title: 'AlienVault OTX REST API Collector',
    stage: '01. Data Collection',
    libraries: ['requests', 'os', 'datetime'],
    description:
      'Polls AlienVault OTX v1 pulse endpoints via authenticated REST requests with timeout protection and ATT&CK metadata extraction.',
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
            "attack_ids": pulse.get("attack_ids", []),
            "ingested_at": datetime.now(timezone.utc).isoformat(),
            "indicators": pulse.get("indicators", []),
        })
    return pulses`,
  },
  {
    filename: 'selenium_scraper.py',
    title: 'Automated Web Threat Scraper',
    stage: '01. Web Ingestion',
    libraries: ['selenium', 'webdriver.Chrome', 're'],
    description:
      'Executes headless Chrome sessions to extract newly published IOCs and CVE bulletins from JavaScript-rendered vendor advisories.',
    code: `import re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

IOC_PATTERNS = {
    "IPv4": re.compile(r"\\b(?:\\d{1,3}(?:\\.|\\[\\.\\])){3}\\d{1,3}(?::\\d{1,5})?\\b"),
    "CVE": re.compile(r"\\bCVE-\\d{4}-\\d{4,7}\\b", re.IGNORECASE),
    "SHA256": re.compile(r"\\b[a-fA-F0-9]{64}\\b"),
}

def scrape_advisory_feed(target_url: str) -> list[dict]:
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    driver = webdriver.Chrome(options=options)
    extracted = []
    try:
        driver.get(target_url)
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "article"))
        )
        for article in driver.find_elements(By.TAG_NAME, "article"):
            body_text = article.text
            for ioc_type, pattern in IOC_PATTERNS.items():
                for match in pattern.findall(body_text):
                    extracted.append({
                        "raw_indicator": match,
                        "ioc_type": ioc_type,
                        "source": "Selenium Web Scraper",
                    })
    finally:
        driver.quit()
    return extracted`,
  },
  {
    filename: 'pandas_numpy_analyzer.py',
    title: 'Pandas & NumPy Cleaning and Robust Z-Score Engine',
    stage: '02. Consolidation & Analysis',
    libraries: ['pandas', 'numpy', 'ipaddress'],
    description:
      'Normalizes defanged indicators, strips ports, filters private/documentation/CGNAT IPs, deduplicates distinct sightings, and computes Median/MAD robust Z-scores.',
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
        ip_obj = ipaddress.ip_address(val)
        return ip_obj.is_global
    except ValueError:
        return True

def consolidate_and_score(raw_records: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(raw_records).dropna(subset=["raw_indicator"])
    df["normalized_indicator"] = df["raw_indicator"].apply(normalize_indicator)
    df = df[df["normalized_indicator"].apply(is_public_ip)]

    # Distinct sightings by (indicator, source, pulse_id) prevent sync-click inflation
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
  {
    filename: 'streamlit_dashboard.py',
    title: 'Streamlit Interactive Threat Visibility App',
    stage: '03. BI & Visualization',
    libraries: ['streamlit', 'pandas', 'plotly.express'],
    description:
      'Provides analyst parameter controls for robust Z-score outlier sensitivity, distinct sighting thresholds, and Power BI CSV export.',
    code: `import streamlit as st
import pandas as pd
import plotly.express as px

st.set_page_config(page_title="Cloud Threat Intelligence", layout="wide")
st.title("Cloud-Based Cybersecurity Threat Intelligence Framework")

df = pd.read_csv("threat_intel_consolidated.csv")

with st.sidebar:
    st.header("Analysis Parameters")
    min_recurrence = st.slider("Minimum Distinct Sightings", 1, 20, 2)
    z_cutoff = st.slider("Robust Z-Score Cutoff (MAD)", -1.0, 3.5, 1.0, 0.1)
    selected_types = st.multiselect("IOC Types", df["type"].unique(), default=list(df["type"].unique()))

filtered = df[
    (df["recurrence_count"] >= min_recurrence)
    & (df["z_score"] >= z_cutoff)
    & (df["type"].isin(selected_types))
]

fig = px.scatter(
    filtered, x="recurrence_count", y="z_score",
    color="severity", hover_data=["normalized_indicator", "category"]
)
st.plotly_chart(fig, use_container_width=True)
st.dataframe(filtered, use_container_width=True)`,
  },
];
