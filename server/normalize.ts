import net from 'node:net';
import type { IndicatorType, ThreatSeverity } from '../src/types.ts';

// Comprehensive IPv4 non-routable / reserved / documentation blocklist via Node net.BlockList
const RESERVED_IPV4_BLOCKLIST = new net.BlockList();
RESERVED_IPV4_BLOCKLIST.addSubnet('0.0.0.0', 8, 'ipv4');       // Current network
RESERVED_IPV4_BLOCKLIST.addSubnet('10.0.0.0', 8, 'ipv4');      // RFC1918 Private
RESERVED_IPV4_BLOCKLIST.addSubnet('100.64.0.0', 10, 'ipv4');   // RFC6598 CGNAT
RESERVED_IPV4_BLOCKLIST.addSubnet('127.0.0.0', 8, 'ipv4');     // Loopback
RESERVED_IPV4_BLOCKLIST.addSubnet('169.254.0.0', 16, 'ipv4');  // Link-local
RESERVED_IPV4_BLOCKLIST.addSubnet('172.16.0.0', 12, 'ipv4');   // RFC1918 Private
RESERVED_IPV4_BLOCKLIST.addSubnet('192.0.0.0', 24, 'ipv4');    // IETF Protocol Assignments
RESERVED_IPV4_BLOCKLIST.addSubnet('192.0.2.0', 24, 'ipv4');    // TEST-NET-1 Documentation
RESERVED_IPV4_BLOCKLIST.addSubnet('192.168.0.0', 16, 'ipv4');  // RFC1918 Private
RESERVED_IPV4_BLOCKLIST.addSubnet('198.18.0.0', 15, 'ipv4');   // Benchmarking
RESERVED_IPV4_BLOCKLIST.addSubnet('198.51.100.0', 24, 'ipv4'); // TEST-NET-2 Documentation
RESERVED_IPV4_BLOCKLIST.addSubnet('203.0.113.0', 24, 'ipv4');  // TEST-NET-3 Documentation
RESERVED_IPV4_BLOCKLIST.addSubnet('224.0.0.0', 4, 'ipv4');     // Multicast
RESERVED_IPV4_BLOCKLIST.addSubnet('240.0.0.0', 4, 'ipv4');     // Reserved / Broadcast

export function isNonRoutableOrReservedIPv4(ip: string): boolean {
  if (net.isIPv4(ip) === false) return true;
  return RESERVED_IPV4_BLOCKLIST.check(ip, 'ipv4');
}

export interface NormalizedTokenResult {
  valid: boolean;
  type: IndicatorType | 'Invalid';
  normalized: string | null;
  note: string;
}

export function classifyAndNormalizeToken(raw: string): NormalizedTokenResult {
  const trimmed = raw.trim().replace(/^["'`(<[]+|["'`>)\],;]+$/g, '');
  if (!trimmed) {
    return { valid: false, type: 'Invalid', normalized: null, note: 'Empty token removed' };
  }

  // Refang common OSINT notation for canonicalization
  const canonical = trimmed
    .replace(/^hxxps?:\/\//i, (m) => (m.toLowerCase().startsWith('hxxps') ? 'https://' : 'http://'))
    .replace(/\[\.\]/g, '.')
    .replace(/\(dot\)/gi, '.');

  if (/^CVE-\d{4}-\d{4,7}$/i.test(canonical)) {
    return {
      valid: true,
      type: 'CVE',
      normalized: canonical.toUpperCase(),
      note: 'Canonicalized uppercase CVE identifier',
    };
  }

  if (/^[a-fA-F0-9]{64}$/.test(canonical)) {
    return {
      valid: true,
      type: 'SHA256',
      normalized: canonical.toLowerCase(),
      note: 'Normalized lowercase SHA-256 digest',
    };
  }

  // Strip optional :port suffix on IPv4 indicators (e.g. 91.92.240.118:443 -> 91.92.240.118)
  const ipPortMatch = canonical.match(/^((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?$/);
  if (ipPortMatch) {
    const ipOnly = ipPortMatch[1];
    const portStr = ipPortMatch[2];
    if (portStr !== undefined) {
      const portNum = Number(portStr);
      if (portNum < 1 || portNum > 65535) {
        return {
          valid: false,
          type: 'Invalid',
          normalized: null,
          note: 'Malformed IPv4 port range excluded',
        };
      }
    }

    if (!net.isIPv4(ipOnly)) {
      return {
        valid: false,
        type: 'Invalid',
        normalized: null,
        note: 'Malformed IPv4 octet range excluded',
      };
    }

    if (isNonRoutableOrReservedIPv4(ipOnly)) {
      return {
        valid: false,
        type: 'Invalid',
        normalized: null,
        note: 'Dropped private, loopback, CGNAT, documentation, or multicast IPv4',
      };
    }

    const hadRefang = canonical !== trimmed;
    const hadPort = portStr !== undefined;
    let note = 'Validated public IPv4';
    if (hadPort && hadRefang) note = 'Refanged IPv4 & stripped port suffix';
    else if (hadPort) note = 'Stripped port suffix & validated public IPv4';
    else if (hadRefang) note = 'Refanged bracketed IPv4 & validated public range';

    return {
      valid: true,
      type: 'IPv4',
      normalized: ipOnly,
      note,
    };
  }

  if (/^https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(canonical)) {
    try {
      const parsed = new URL(canonical);
      const host = parsed.hostname.toLowerCase();
      if (host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal')) {
        return {
          valid: false,
          type: 'Invalid',
          normalized: null,
          note: 'Dropped non-routable local URL host',
        };
      }
      if (net.isIPv4(host) && isNonRoutableOrReservedIPv4(host)) {
        return {
          valid: false,
          type: 'Invalid',
          normalized: null,
          note: 'Dropped URL targeting reserved/private IPv4',
        };
      }
      const cleanedUrl = parsed.toString();
      return {
        valid: true,
        type: 'URL',
        normalized: cleanedUrl,
        note: canonical !== trimmed ? 'Refanged hxxp/[.] URL & normalized host' : 'Validated HTTP/HTTPS IOC URL',
      };
    } catch {
      return {
        valid: false,
        type: 'Invalid',
        normalized: null,
        note: 'Malformed URL excluded',
      };
    }
  }

  if (/^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}$/.test(canonical) && !canonical.includes('..')) {
    const domain = canonical.toLowerCase();
    if (domain.endsWith('.local') || domain.endsWith('.internal') || domain === 'localhost') {
      return {
        valid: false,
        type: 'Invalid',
        normalized: null,
        note: 'Dropped non-routable internal domain',
      };
    }
    return {
      valid: true,
      type: 'Domain',
      normalized: domain,
      note: domain !== trimmed ? 'Refanged [.] domain & lowercased FQDN' : 'Normalized lowercase FQDN',
    };
  }

  return {
    valid: false,
    type: 'Invalid',
    normalized: null,
    note: 'Malformed or non-IOC token excluded',
  };
}

export function median(nums: number[]): number {
  if (nums.length === 0) return 0;
  const sorted = [...nums].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 0) {
    return (sorted[mid - 1] + sorted[mid]) / 2;
  }
  return sorted[mid];
}

// Robust Modified Z-Score via Median & MAD: M_i = 0.6745 * (x_i - median) / MAD
export function computeRobustZScores(values: number[]): {
  medianVal: number;
  madVal: number;
  zScores: number[];
} {
  if (values.length === 0) {
    return { medianVal: 0, madVal: 0, zScores: [] };
  }
  const med = median(values);
  const absDevs = values.map((v) => Math.abs(v - med));
  const mad = median(absDevs);

  if (mad > 0) {
    const zScores = values.map((v) => Number(((0.6745 * (v - med)) / mad).toFixed(2)));
    return {
      medianVal: Number(med.toFixed(2)),
      madVal: Number(mad.toFixed(2)),
      zScores,
    };
  }

  // Fallback when >50% of observations equal the median (MAD == 0): use Mean Absolute Deviation
  const meanAbsDev = absDevs.reduce((a, b) => a + b, 0) / values.length;
  if (meanAbsDev === 0) {
    return {
      medianVal: Number(med.toFixed(2)),
      madVal: 0,
      zScores: values.map(() => 0),
    };
  }
  const zScores = values.map((v) => Number(((v - med) / (1.253314 * meanAbsDev)).toFixed(2)));
  return {
    medianVal: Number(med.toFixed(2)),
    madVal: Number(meanAbsDev.toFixed(2)),
    zScores,
  };
}

const MITRE_PREFIX_MAP: Array<[RegExp, string, string]> = [
  [/T1566|T1190|T1133|T1195/i, 'Initial Access', 'Cloud API Exploit'],
  [/T1078|T1110|T1552|T1528/i, 'Credential Access', 'Credential Harvesting'],
  [/T1059|T1204|T1203/i, 'Execution', 'Malware Distribution'],
  [/T1071|T1095|T1105|T1572/i, 'Command & Control', 'C2 Infrastructure'],
  [/T1486|T1490|T1485/i, 'Impact', 'Ransomware & Extortion'],
  [/T1041|T1567|T1048/i, 'Exfiltration', 'Ransomware & Extortion'],
  [/T1053|T1543|T1136/i, 'Persistence', 'Cloud API Exploit'],
];

export function deriveOtxAttributes(pulse: {
  tags?: string[];
  attackIds?: string[];
  adversary?: string;
  tlp?: string;
  indicatorCount?: number;
  indicatorRole?: string;
}): {
  category: string;
  severity: ThreatSeverity;
  confidence: number;
  mitreTactic: string;
} {
  const tags = (pulse.tags || []).map((t) => t.toLowerCase());
  const attackStr = (pulse.attackIds || []).join(' ');
  const combined = `${tags.join(' ')} ${attackStr} ${pulse.indicatorRole || ''}`.toLowerCase();

  let mitreTactic = 'Command & Control';
  let category = 'C2 Infrastructure';

  for (const [pattern, tactic, cat] of MITRE_PREFIX_MAP) {
    if (pattern.test(attackStr)) {
      mitreTactic = tactic;
      category = cat;
      break;
    }
  }

  if (mitreTactic === 'Command & Control') {
    if (/ransom|lockbit|blackcat|extort/.test(combined)) {
      category = 'Ransomware & Extortion';
      mitreTactic = 'Impact';
    } else if (/phish|cred|oauth|iam|sts|okta|stealer/.test(combined)) {
      category = 'Credential Harvesting';
      mitreTactic = 'Credential Access';
    } else if (/cve|exploit|rce|k8s|kubernetes|cloud|ingress|api/.test(combined)) {
      category = 'Cloud API Exploit';
      mitreTactic = 'Initial Access';
    } else if (/loader|dropper|trojan|malware|payload|botnet/.test(combined)) {
      category = 'Malware Distribution';
      mitreTactic = 'Execution';
    }
  }

  const hasAdversary = Boolean(pulse.adversary && pulse.adversary !== 'Unattributed');
  const isCriticalKeyword = /ransom|zero-day|0day|apt|rce|exploit|active/.test(combined);
  const severity: ThreatSeverity =
    isCriticalKeyword || (hasAdversary && (pulse.indicatorCount || 0) >= 8)
      ? 'Critical'
      : tags.length >= 3 || hasAdversary
        ? 'High'
        : 'Medium';

  let confidence = 72;
  if (hasAdversary) confidence += 10;
  if ((pulse.attackIds || []).length > 0) confidence += 8;
  if ((pulse.indicatorCount || 0) >= 5) confidence += 5;
  if ((pulse.tlp || '').toUpperCase().includes('AMBER') || (pulse.tlp || '').toUpperCase().includes('RED')) {
    confidence += 3;
  }

  return {
    category,
    severity,
    confidence: Math.min(98, confidence),
    mitreTactic,
  };
}

export function deriveKevAttributes(vuln: {
  knownRansomwareCampaignUse?: string;
  vulnerabilityName?: string;
  shortDescription?: string;
}): {
  category: string;
  severity: ThreatSeverity;
  confidence: number;
  mitreTactic: string;
} {
  const isRansomware = String(vuln.knownRansomwareCampaignUse || '').toLowerCase() === 'known';
  const text = `${vuln.vulnerabilityName || ''} ${vuln.shortDescription || ''}`.toLowerCase();

  const isAuthOrPriv = /authentication|credential|privilege|bypass|iam/.test(text);
  const isExecution = /remote code execution|command injection|arbitrary code|rce/.test(text);

  const mitreTactic = isRansomware
    ? 'Impact'
    : isAuthOrPriv
      ? 'Credential Access'
      : isExecution
        ? 'Initial Access'
        : 'Execution';

  const category = isRansomware
    ? 'Ransomware & Extortion'
    : /vpn|firewall|cloud|api|gateway|citrix|ivanti|palo alto/.test(text)
      ? 'Cloud API Exploit'
      : 'Supply Chain / CVE';

  const severity: ThreatSeverity = isRansomware || isExecution ? 'Critical' : 'High';
  const confidence = isRansomware ? 99 : 94;

  return { category, severity, confidence, mitreTactic };
}

export function deriveFeodoAttributes(entry: {
  status?: string;
  malware?: string;
  port?: number;
}): {
  category: string;
  severity: ThreatSeverity;
  confidence: number;
  mitreTactic: string;
} {
  const isOnline = String(entry.status || '').toLowerCase() === 'online';
  const malware = String(entry.malware || '').toLowerCase();

  const category = /emotet|qakbot|pikabot|bumblebee/.test(malware)
    ? 'C2 Infrastructure'
    : 'Malware Distribution';

  const severity: ThreatSeverity = isOnline ? 'Critical' : 'Medium';
  const confidence = isOnline ? 95 : 74;

  return {
    category,
    severity,
    confidence,
    mitreTactic: 'Command & Control',
  };
}
