import crypto from 'node:crypto';
import express from 'express';
import type { NextFunction, Request, Response } from 'express';
import { db } from './db.ts';
import { ingestCustomBatch, PYTHON_MODULES, syncLiveOsintFeeds } from './ingest.ts';
import { computeRobustZScores } from './normalize.ts';
import type {
  FeedSourceType,
  IndicatorType,
  PipelineRun,
  ThreatIndicator,
  ThreatPulse,
  ThreatSeverity,
  ThreatStatus,
} from '../src/types.ts';

function createRateLimiter(maxRequests: number, windowMs: number) {
  const hits = new Map<string, number[]>();
  return (req: Request, res: Response, next: NextFunction) => {
    const key = req.ip || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const recent = (hits.get(key) || []).filter((t) => now - t < windowMs);
    if (recent.length >= maxRequests) {
      const retryAfterSec = Math.ceil((windowMs - (now - recent[0])) / 1000);
      res.setHeader('Retry-After', String(Math.max(1, retryAfterSec)));
      res.status(429).json({
        error: `Rate limit exceeded. Try again in ${Math.max(1, retryAfterSec)}s.`,
      });
      return;
    }
    recent.push(now);
    hits.set(key, recent);
    next();
  };
}

function timingSafeMatch(expected: string, provided: string): boolean {
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(provided, 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function requireWriteAccess(req: Request, res: Response, next: NextFunction) {
  if (process.env.READ_ONLY_DEMO === 'true') {
    res.status(403).json({
      error: 'Read-only demo mode is enabled. Outbound sync and triage mutations are disabled.',
    });
    return;
  }

  const adminToken = process.env.ADMIN_TOKEN?.trim();
  if (adminToken) {
    const authHeader = String(req.headers.authorization || '');
    const bearer = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    if (!bearer || !timingSafeMatch(adminToken, bearer)) {
      res.status(401).json({
        error: 'Authentication required. Provide a valid Bearer token.',
      });
      return;
    }
  }

  next();
}

export function createApiRouter() {
  const router = express.Router();
  const mutateRateLimit = createRateLimiter(20, 60_000);
  const syncRateLimit = createRateLimiter(4, 60_000);

  router.get('/health', (_req: Request, res: Response) => {
    res.json({ ok: true });
  });

  router.get('/config', (_req: Request, res: Response) => {
    res.json({
      readOnlyDemo: process.env.READ_ONLY_DEMO === 'true',
      authRequired: Boolean(process.env.ADMIN_TOKEN?.trim()),
    });
  });

  router.get('/dashboard', (req: Request, res: Response) => {
    const category = String(req.query.category || '').trim();
    const source = String(req.query.source || '').trim();
    const iocType = String(req.query.iocType || '').trim();
    const severity = String(req.query.severity || '').trim();
    const status = String(req.query.status || '').trim();
    const search = String(req.query.search || '').trim().toLowerCase();
    const minRecurrence = Number(req.query.minRecurrence || 1);
    const zThreshold = Number(req.query.zThreshold ?? -10);
    const days = Number(req.query.days || 30);

    const allRows = db
      .prepare('SELECT * FROM threat_indicators ORDER BY z_score DESC, recurrence_count DESC, last_seen DESC')
      .all() as Array<Record<string, unknown>>;

    const mapIndicator = (r: Record<string, unknown>): ThreatIndicator => ({
      id: String(r.id),
      pulseId: String(r.pulse_id),
      pulseTitle: String(r.pulse_title),
      indicator: String(r.indicator),
      normalizedIndicator: String(r.normalized_indicator),
      type: r.type as IndicatorType,
      source: r.source as FeedSourceType,
      category: String(r.category),
      severity: r.severity as ThreatSeverity,
      confidenceScore: Number(r.confidence_score),
      recurrenceCount: Number(r.recurrence_count),
      daysObserved: Number(r.days_observed || 1),
      zScore: Number(r.z_score),
      mitreTactic: String(r.mitre_tactic),
      country: String(r.country),
      asn: String(r.asn),
      firstSeen: String(r.first_seen),
      lastSeen: String(r.last_seen),
      status: r.status as ThreatStatus,
      rawSample: String(r.raw_sample),
      cleaningNotes: String(r.cleaning_notes),
      isSample: Boolean(r.is_sample),
    });

    const mappedAll = allRows.map(mapIndicator);
    const cutoffMs = Date.now() - days * 86_400_000;

    const filteredIndicators = mappedAll.filter((item) => {
      if (category && item.category !== category) return false;
      if (source && item.source !== source) return false;
      if (iocType && item.type !== iocType) return false;
      if (severity && item.severity !== severity) return false;
      if (status && item.status !== status) return false;
      if (item.recurrenceCount < minRecurrence) return false;
      if (item.zScore < zThreshold) return false;
      if (days < 365 && new Date(item.lastSeen).getTime() < cutoffMs) return false;
      if (search) {
        const hay = `${item.indicator} ${item.pulseTitle} ${item.category} ${item.mitreTactic} ${item.asn} ${item.source}`.toLowerCase();
        if (!hay.includes(search)) return false;
      }
      return true;
    });

    const runsRaw = db
      .prepare('SELECT * FROM pipeline_runs ORDER BY timestamp DESC LIMIT 20')
      .all() as Array<Record<string, unknown>>;
    const pipelineRuns: PipelineRun[] = runsRaw.map((r) => ({
      id: String(r.id),
      timestamp: String(r.timestamp),
      sourceName: String(r.source_name),
      rawCount: Number(r.raw_count),
      duplicatesRemoved: Number(r.duplicates_removed),
      malformedDropped: Number(r.malformed_dropped),
      normalizedCount: Number(r.normalized_count),
      highRecurrenceOutliers: Number(r.anomaly_spikes_detected),
      durationMs: Number(r.duration_ms),
      status: r.status as PipelineRun['status'],
      errorMessage: r.error_message ? String(r.error_message) : null,
    }));

    const pulsesRaw = db
      .prepare('SELECT * FROM threat_pulses ORDER BY created_at DESC LIMIT 12')
      .all() as Array<Record<string, unknown>>;
    const pulses: ThreatPulse[] = pulsesRaw.map((p) => ({
      id: String(p.id),
      title: String(p.title),
      source: p.source as FeedSourceType,
      author: String(p.author),
      createdAt: String(p.created_at),
      tlp: String(p.tlp),
      adversary: String(p.adversary),
      tags: JSON.parse(String(p.tags || '[]')) as string[],
      rawIndicatorCount: Number(p.raw_indicator_count),
      cleanedIndicatorCount: Number(p.cleaned_indicator_count),
      isLive: Boolean(p.is_live),
      isSample: Boolean(p.is_sample),
    }));

    const recValues = filteredIndicators.map((i) => i.recurrenceCount);
    const { medianVal, madVal } = computeRobustZScores(recValues);
    const maxRobustZ = filteredIndicators.length
      ? Math.max(...filteredIndicators.map((i) => i.zScore))
      : 0;

    const totalRaw = pipelineRuns.reduce((acc, r) => acc + r.rawCount, 0);
    const duplicatesRemovedTotal = pipelineRuns.reduce((acc, r) => acc + r.duplicatesRemoved, 0);
    const deduplicationRate = totalRaw > 0 ? Number(((duplicatesRemovedTotal / totalRaw) * 100).toFixed(1)) : 0;

    const groupBy = (keyFn: (item: ThreatIndicator) => string) => {
      const map = new Map<string, { count: number; zSum: number; criticalCount: number }>();
      for (const item of filteredIndicators) {
        const k = keyFn(item);
        const cur = map.get(k) || { count: 0, zSum: 0, criticalCount: 0 };
        cur.count += 1;
        cur.zSum += item.zScore;
        if (item.severity === 'Critical') cur.criticalCount += 1;
        map.set(k, cur);
      }
      return Array.from(map.entries())
        .map(([name, val]) => ({
          name,
          count: val.count,
          avgZScore: Number((val.zSum / val.count).toFixed(2)),
          criticalCount: val.criticalCount,
        }))
        .sort((a, b) => b.count - a.count);
    };

    const timelineMap = new Map<
      string,
      { distinctSightings: number; syncRawCount: number; syncCleanCount: number }
    >();
    for (let d = 6; d >= 0; d--) {
      const dateStr = new Date(Date.now() - d * 86_400_000).toISOString().slice(5, 10);
      timelineMap.set(dateStr, { distinctSightings: 0, syncRawCount: 0, syncCleanCount: 0 });
    }

    const filteredKeys = new Set(filteredIndicators.map((i) => i.normalizedIndicator));
    const sightingsRows = db
      .prepare('SELECT normalized_indicator, seen_at FROM sightings')
      .all() as Array<{ normalized_indicator: string; seen_at: string }>;

    for (const s of sightingsRows) {
      if (!filteredKeys.has(s.normalized_indicator)) continue;
      const dateKey = s.seen_at.slice(5, 10);
      const bucket = timelineMap.get(dateKey);
      if (bucket) {
        bucket.distinctSightings += 1;
      }
    }

    for (const run of pipelineRuns) {
      const dateKey = run.timestamp.slice(5, 10);
      const bucket = timelineMap.get(dateKey);
      if (bucket) {
        bucket.syncRawCount += run.rawCount;
        bucket.syncCleanCount += run.normalizedCount;
      }
    }

    const timeline = Array.from(timelineMap.entries()).map(([date, vals]) => ({
      date,
      ...vals,
    }));

    res.json({
      kpis: {
        totalIndicators: filteredIndicators.length,
        sampleCount: filteredIndicators.filter((i) => i.isSample).length,
        liveCount: filteredIndicators.filter((i) => !i.isSample).length,
        activeCritical: filteredIndicators.filter((i) => i.severity === 'Critical' && i.status !== 'Mitigated').length,
        recurringPatterns: filteredIndicators.filter((i) => i.recurrenceCount >= 2).length,
        highRecurrenceOutliers: filteredIndicators.filter((i) => i.zScore >= 1.5).length,
        duplicatesRemovedTotal,
        deduplicationRate,
        medianRecurrence: medianVal,
        madRecurrence: madVal,
        maxRobustZ,
        lastSyncAt: pipelineRuns[0]?.timestamp || null,
        pulseCount: pulses.length,
      },
      timeline,
      byCategory: groupBy((i) => i.category),
      byType: groupBy((i) => i.type),
      bySeverity: groupBy((i) => i.severity),
      byTactic: groupBy((i) => i.mitreTactic),
      byCountry: groupBy((i) => i.country).slice(0, 6),
      topPatterns: [...filteredIndicators].slice(0, 8),
      scatterPoints: filteredIndicators.map((i) => ({
        id: i.id,
        indicator: i.indicator,
        type: i.type,
        category: i.category,
        severity: i.severity,
        recurrence: i.recurrenceCount,
        daysObserved: i.daysObserved,
        zScore: i.zScore,
        confidence: i.confidenceScore,
        source: i.source,
        isSample: i.isSample,
      })),
      filteredIndicators,
      pulses,
      pipelineRuns,
    });
  });

  router.post('/pipeline/sync', syncRateLimit, requireWriteAccess, async (_req: Request, res: Response) => {
    try {
      const result = await syncLiveOsintFeeds();
      if (!result.ok) {
        res.status(502).json({
          ok: false,
          error: `All live feeds failed: ${result.feedErrors.join(' | ')}`,
          run: result.run,
          feedErrors: result.feedErrors,
          feedCounts: result.feedCounts,
        });
        return;
      }
      res.json(result);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Sync failed';
      console.error('[API /pipeline/sync] Unexpected error:', message);
      res.status(500).json({ ok: false, error: message });
    }
  });

  router.post('/pipeline/ingest-custom', mutateRateLimit, requireWriteAccess, (req: Request, res: Response) => {
    const rawText = String(req.body?.rawText || '');
    if (!rawText.trim()) {
      res.status(400).json({ error: 'rawText is required' });
      return;
    }
    const sourceInput = String(req.body?.sourceLabel || 'Manual Batch').trim() as FeedSourceType;
    const validSource: FeedSourceType =
      sourceInput === 'AlienVault OTX' ||
      sourceInput === 'CISA KEV' ||
      sourceInput === 'Abuse.ch Feodo'
        ? sourceInput
        : 'Manual Batch';

    const result = ingestCustomBatch(rawText, validSource);
    res.json(result);
  });

  router.patch('/indicators/:id/status', mutateRateLimit, requireWriteAccess, (req: Request, res: Response) => {
    const { id } = req.params;
    const status = String(req.body?.status || '') as ThreatStatus;
    if (!['Active', 'Investigating', 'Mitigated'].includes(status)) {
      res.status(400).json({ error: 'Invalid status' });
      return;
    }
    const info = db.prepare('UPDATE threat_indicators SET status = ? WHERE id = ?').run(status, id);
    if (info.changes === 0) {
      res.status(404).json({ error: 'Indicator not found' });
      return;
    }
    res.json({ ok: true, id, status });
  });

  router.get('/export/csv', (_req: Request, res: Response) => {
    const rows = db
      .prepare('SELECT * FROM threat_indicators ORDER BY z_score DESC, recurrence_count DESC')
      .all() as Array<Record<string, unknown>>;

    const headers = [
      'id',
      'normalized_indicator',
      'type',
      'source',
      'category',
      'severity',
      'confidence_score',
      'recurrence_count',
      'days_observed',
      'z_score',
      'mitre_tactic',
      'country',
      'asn',
      'status',
      'is_sample',
      'first_seen',
      'last_seen',
      'pulse_title',
    ];

    const escapeCsv = (val: unknown, isNumeric = false) => {
      let s = String(val ?? '');
      if (!isNumeric && /^[=+\-@\t\r]/.test(s)) {
        s = `'${s}`;
      }
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };

    const numericCols = new Set(['confidence_score', 'recurrence_count', 'days_observed', 'z_score', 'is_sample']);
    const lines = [headers.join(',')];
    for (const row of rows) {
      lines.push(headers.map((h) => escapeCsv(row[h], numericCols.has(h))).join(','));
    }

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="threat_intel_consolidated.csv"');
    res.send(lines.join('\n'));
  });

  router.get('/python-modules', (_req: Request, res: Response) => {
    res.json({ modules: PYTHON_MODULES });
  });

  return router;
}
