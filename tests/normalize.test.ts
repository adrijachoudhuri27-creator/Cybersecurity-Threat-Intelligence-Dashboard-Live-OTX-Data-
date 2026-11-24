import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyAndNormalizeToken,
  computeRobustZScores,
  deriveFeodoAttributes,
  deriveKevAttributes,
  deriveOtxAttributes,
  extractOtxAttackIds,
} from '../server/normalize.ts';

describe('classifyAndNormalizeToken', () => {
  it('refangs bracketed IPv4 and strips port suffix', () => {
    const bracketed = classifyAndNormalizeToken('185[.]220[.]101[.]44');
    assert.equal(bracketed.valid, true);
    assert.equal(bracketed.type, 'IPv4');
    assert.equal(bracketed.normalized, '185.220.101.44');

    const withPort = classifyAndNormalizeToken('91.92.240.118:443');
    assert.equal(withPort.valid, true);
    assert.equal(withPort.type, 'IPv4');
    assert.equal(withPort.normalized, '91.92.240.118');
  });

  it('rejects RFC1918, loopback, CGNAT, documentation, and multicast IPv4 addresses', () => {
    const blockedIps = [
      '10.0.0.1',
      '172.16.4.20',
      '192.168.1.50',
      '127.0.0.1',
      '169.254.169.254',
      '100.64.0.1',
      '192.0.2.1',
      '198.51.100.77',
      '203.0.113.5',
      '224.0.0.1',
      '0.0.0.0',
    ];

    for (const ip of blockedIps) {
      const res = classifyAndNormalizeToken(ip);
      assert.equal(res.valid, false, `Expected ${ip} to be rejected`);
      assert.equal(res.type, 'Invalid');
      assert.equal(res.normalized, null);
    }
  });

  it('canonicalizes CVEs, SHA-256 hashes, defanged domains, and hxxp URLs', () => {
    const cve = classifyAndNormalizeToken('cve-2024-3400');
    assert.equal(cve.valid, true);
    assert.equal(cve.type, 'CVE');
    assert.equal(cve.normalized, 'CVE-2024-3400');

    const sha = classifyAndNormalizeToken('A'.repeat(64));
    assert.equal(sha.valid, true);
    assert.equal(sha.type, 'SHA256');
    assert.equal(sha.normalized, 'a'.repeat(64));

    const domain = classifyAndNormalizeToken('SSO-Okta-CloudVerify[.]com');
    assert.equal(domain.valid, true);
    assert.equal(domain.type, 'Domain');
    assert.equal(domain.normalized, 'sso-okta-cloudverify.com');

    const url = classifyAndNormalizeToken('hxxps://Login-Example[.]com/auth');
    assert.equal(url.valid, true);
    assert.equal(url.type, 'URL');
    assert.equal(url.normalized, 'https://login-example.com/auth');
  });

  it('rejects internal domains, invalid ports, and malformed tokens', () => {
    assert.equal(classifyAndNormalizeToken('db.internal').valid, false);
    assert.equal(classifyAndNormalizeToken('printer.local').valid, false);
    assert.equal(classifyAndNormalizeToken('91.92.240.118:99999').valid, false);
    assert.equal(classifyAndNormalizeToken('hxxp://192.168.1.10/admin').valid, false);
    assert.equal(classifyAndNormalizeToken('not_a_valid_ioc_$$').valid, false);
  });
});

describe('computeRobustZScores', () => {
  it('computes Median and MAD robust Z-scores without mean distortion', () => {
    const { medianVal, madVal, zScores } = computeRobustZScores([1, 1, 2, 2, 3, 14]);
    assert.equal(medianVal, 2);
    assert.equal(madVal, 1);
    assert.ok(zScores[5] > 5, 'Expected high-recurrence outlier to exceed +5 MAD Z-score');
    assert.equal(zScores[2], 0);
  });

  it('handles zero-MAD distributions gracefully without NaN', () => {
    const { medianVal, zScores } = computeRobustZScores([1, 1, 1, 1, 5]);
    assert.equal(medianVal, 1);
    assert.ok(zScores.every((z) => Number.isFinite(z)));
    assert.ok(zScores[4] > 0);
  });
});

describe('OTX attack_ids & word-boundary attribute derivation', () => {
  it('extracts OTX attack_ids from both objects and strings and maps T1566 to Credential Harvesting', () => {
    const ids = extractOtxAttackIds([
      { id: 'T1566', name: 'Phishing', display_name: 'T1566 - Phishing' },
      'T1078',
    ]);
    assert.deepEqual(ids, ['T1566', 'T1078']);

    const derived = deriveOtxAttributes({
      tags: ['phishing'],
      attackIds: ids,
      adversary: 'Unattributed',
    });
    assert.equal(derived.mitreTactic, 'Initial Access');
    assert.equal(derived.category, 'Credential Harvesting');
  });

  it('does not trigger false Critical severity or false categories on substring collisions', () => {
    const benignWords = deriveOtxAttributes({
      tags: ['adapt', 'source code', 'inactive', 'diamond', 'tests'],
      attackIds: [],
      adversary: 'Unattributed',
      indicatorCount: 2,
    });
    assert.notEqual(benignWords.severity, 'Critical');
    assert.equal(benignWords.category, 'C2 Infrastructure');
  });

  it('triggers Critical severity on whole-word exploit/ransomware/apt terms', () => {
    const critical = deriveOtxAttributes({
      tags: ['ransomware', 'apt'],
      attackIds: [{ id: 'T1486', name: 'Data Encrypted for Impact' }].map((a) => a.id),
      adversary: 'Scattered Spider',
      tlp: 'AMBER',
      indicatorCount: 12,
    });
    assert.equal(critical.mitreTactic, 'Impact');
    assert.equal(critical.category, 'Ransomware & Extortion');
    assert.equal(critical.severity, 'Critical');
    assert.ok(critical.confidence >= 90);
  });

  it('derives CISA KEV severity from knownRansomwareCampaignUse', () => {
    const rw = deriveKevAttributes({
      knownRansomwareCampaignUse: 'Known',
      vulnerabilityName: 'Edge Gateway RCE',
    });
    assert.equal(rw.severity, 'Critical');
    assert.equal(rw.category, 'Ransomware & Extortion');

    const nonRw = deriveKevAttributes({
      knownRansomwareCampaignUse: 'Unknown',
      vulnerabilityName: 'Source code inspection note (inactive)',
    });
    assert.equal(nonRw.severity, 'High');
  });

  it('derives Abuse.ch Feodo severity and confidence from online/offline status', () => {
    const online = deriveFeodoAttributes({ status: 'online', malware: 'Pikabot' });
    const offline = deriveFeodoAttributes({ status: 'offline', malware: 'QakBot' });
    assert.equal(online.severity, 'Critical');
    assert.ok(online.confidence > offline.confidence);
    assert.equal(offline.severity, 'Medium');
  });
});
