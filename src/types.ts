export type IndicatorType = 'IPv4' | 'Domain' | 'URL' | 'SHA256' | 'CVE';
export type ThreatSeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Unclassified';
export type ThreatStatus = 'Active' | 'Investigating' | 'Mitigated';
export type FeedSourceType = 'AlienVault OTX' | 'CISA KEV' | 'Abuse.ch Feodo' | 'Manual Batch';

export interface ThreatIndicator {
  id: string;
  pulseId: string;
  pulseTitle: string;
  indicator: string;
  normalizedIndicator: string;
  type: IndicatorType;
  source: FeedSourceType;
  category: string;
  severity: ThreatSeverity;
  confidenceScore: number;
  recurrenceCount: number;
  daysObserved: number;
  zScore: number;
  mitreTactic: string;
  country: string;
  asn: string;
  firstSeen: string;
  lastSeen: string;
  status: ThreatStatus;
  rawSample: string;
  cleaningNotes: string;
  isSample: boolean;
}

export interface ThreatPulse {
  id: string;
  title: string;
  source: FeedSourceType;
  author: string;
  createdAt: string;
  tlp: string;
  adversary: string;
  tags: string[];
  rawIndicatorCount: number;
  cleanedIndicatorCount: number;
  isLive: boolean;
  isSample: boolean;
}

export interface PipelineRun {
  id: string;
  timestamp: string;
  sourceName: string;
  rawCount: number;
  duplicatesRemoved: number;
  malformedDropped: number;
  normalizedCount: number;
  highRecurrenceOutliers: number;
  durationMs: number;
  status: 'Completed' | 'Live Sync' | 'Partial' | 'Failed';
  errorMessage?: string | null;
}

export interface DashboardKPIs {
  totalIndicators: number;
  sampleCount: number;
  liveCount: number;
  activeCritical: number;
  recurringPatterns: number;
  highRecurrenceOutliers: number;
  duplicatesRemovedTotal: number;
  deduplicationRate: number;
  medianRecurrence: number;
  madRecurrence: number;
  maxRobustZ: number;
  lastSyncAt: string | null;
  pulseCount: number;
}

export interface TimelineBucket {
  date: string;
  distinctSightings: number;
  syncRawCount: number;
  syncCleanCount: number;
}

export interface BreakdownItem {
  name: string;
  count: number;
  avgZScore?: number;
  criticalCount?: number;
}

export interface ScatterPoint {
  id: string;
  indicator: string;
  type: IndicatorType;
  category: string;
  severity: ThreatSeverity;
  recurrence: number;
  daysObserved: number;
  zScore: number;
  confidence: number;
  source: FeedSourceType;
  isSample: boolean;
}

export interface DashboardResponse {
  kpis: DashboardKPIs;
  timeline: TimelineBucket[];
  byCategory: BreakdownItem[];
  byType: BreakdownItem[];
  bySeverity: BreakdownItem[];
  byTactic: BreakdownItem[];
  byCountry: BreakdownItem[];
  topPatterns: ThreatIndicator[];
  scatterPoints: ScatterPoint[];
  filteredIndicators: ThreatIndicator[];
  pulses: ThreatPulse[];
  pipelineRuns: PipelineRun[];
}

export interface CustomIngestAuditItem {
  rawToken: string;
  normalizedValue: string | null;
  type: IndicatorType | 'Invalid';
  action: 'Persisted' | 'Merged Duplicate' | 'Dropped (Private/Malformed)';
  reason: string;
}

export interface CustomIngestResponse {
  summary: {
    rawTokens: number;
    persistedNew: number;
    duplicatesMerged: number;
    droppedInvalid: number;
    durationMs: number;
  };
  audit: CustomIngestAuditItem[];
}

export interface PythonModuleSpec {
  filename: string;
  title: string;
  stage: string;
  libraries: string[];
  description: string;
  code: string;
}

export interface AppConfig {
  readOnlyDemo: boolean;
  authRequired: boolean;
}
