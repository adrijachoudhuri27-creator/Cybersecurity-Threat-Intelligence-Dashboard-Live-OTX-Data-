import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createDatabase } from '../server/db.ts';

describe('SQLite sightings deduplication & recurrence stability', () => {
  it('never inflates recurrence_count or z_score when inserting the same sighting twice', () => {
    const store = createDatabase(':memory:');

    const first = store.upsertNormalizedIndicator({
      pulseId: 'kev-live',
      pulseTitle: 'CISA KEV Live Catalog Sync',
      rawToken: 'CVE-2024-3400',
      source: 'CISA KEV',
      category: 'Cloud API Exploit',
      severity: 'Critical',
      confidence: 99,
      mitreTactic: 'Initial Access',
      country: 'GLOBAL',
      asn: 'Palo Alto Networks',
      seenAt: '2026-11-23T10:00:00.000Z',
      isSample: false,
    });
    assert.equal(first.outcome, 'persisted');
    store.recomputeRobustZScores();

    const rowAfterFirst = store.db
      .prepare('SELECT recurrence_count, days_observed, z_score FROM threat_indicators WHERE normalized_indicator = ?')
      .get('CVE-2024-3400') as { recurrence_count: number; days_observed: number; z_score: number };
    assert.equal(rowAfterFirst.recurrence_count, 1);
    assert.equal(rowAfterFirst.days_observed, 1);

    // Repeat the exact same feed + pulse on a subsequent day
    const second = store.upsertNormalizedIndicator({
      pulseId: 'kev-live',
      pulseTitle: 'CISA KEV Live Catalog Sync',
      rawToken: 'CVE-2024-3400',
      source: 'CISA KEV',
      category: 'Cloud API Exploit',
      severity: 'Critical',
      confidence: 99,
      mitreTactic: 'Initial Access',
      country: 'GLOBAL',
      asn: 'Palo Alto Networks',
      seenAt: '2026-11-24T10:00:00.000Z',
      isSample: false,
    });
    assert.equal(second.outcome, 'duplicate_in_same_sighting');
    store.recomputeRobustZScores();

    const rowAfterSecond = store.db
      .prepare('SELECT recurrence_count, days_observed, z_score FROM threat_indicators WHERE normalized_indicator = ?')
      .get('CVE-2024-3400') as { recurrence_count: number; days_observed: number; z_score: number };

    assert.equal(rowAfterSecond.recurrence_count, 1);
    assert.equal(rowAfterSecond.days_observed, 2);
    assert.equal(rowAfterSecond.z_score, rowAfterFirst.z_score);
  });

  it('increments recurrence_count only when an indicator appears in a distinct feed or pulse', () => {
    const store = createDatabase(':memory:');

    store.upsertNormalizedIndicator({
      pulseId: 'kev-live',
      pulseTitle: 'CISA KEV Live Catalog Sync',
      rawToken: 'CVE-2024-47575',
      source: 'CISA KEV',
      category: 'Ransomware & Extortion',
      severity: 'Critical',
      confidence: 99,
      mitreTactic: 'Impact',
      country: 'GLOBAL',
      asn: 'Fortinet',
      seenAt: '2026-11-23T10:00:00.000Z',
      isSample: false,
    });

    const crossFeed = store.upsertNormalizedIndicator({
      pulseId: 'otx-pulse-991',
      pulseTitle: 'OTX FortiManager Exploit Campaign',
      rawToken: 'cve-2024-47575',
      source: 'AlienVault OTX',
      category: 'Cloud API Exploit',
      severity: 'Critical',
      confidence: 94,
      mitreTactic: 'Initial Access',
      country: 'GLOBAL',
      asn: 'OTX',
      seenAt: '2026-11-23T12:00:00.000Z',
      isSample: false,
    });
    assert.equal(crossFeed.outcome, 'new_sighting_merged');
    store.recomputeRobustZScores();

    const row = store.db
      .prepare('SELECT recurrence_count, days_observed FROM threat_indicators WHERE normalized_indicator = ?')
      .get('CVE-2024-47575') as { recurrence_count: number; days_observed: number };

    assert.equal(row.recurrence_count, 2);
    assert.equal(row.days_observed, 1);
  });

  it('computes liveOutliers strictly across is_sample = 0 rows without sample fixture bleed', () => {
    const store = createDatabase(':memory:');
    store.seedSampleIntel();

    // Insert uniform live indicators (each with 1 sighting)
    for (const cve of ['CVE-2025-1001', 'CVE-2025-1002', 'CVE-2025-1003']) {
      store.upsertNormalizedIndicator({
        pulseId: 'kev-live',
        pulseTitle: 'CISA KEV Live Catalog Sync',
        rawToken: cve,
        source: 'CISA KEV',
        category: 'Supply Chain / CVE',
        severity: 'High',
        confidence: 94,
        mitreTactic: 'Execution',
        country: 'GLOBAL',
        asn: 'Vendor',
        seenAt: '2026-11-24T07:00:00.000Z',
        isSample: false,
      });
    }

    const stats = store.recomputeRobustZScores();
    assert.equal(stats.liveOutliers, 0);
  });
});
