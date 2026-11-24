import React from 'react';
import { Copy, Check, Play, RefreshCw } from 'lucide-react';
import type {
  CustomIngestResponse,
  FeedSourceType,
  PipelineRun,
  PythonModuleSpec,
  ThreatPulse,
} from '../types';

interface PipelineWorkspaceProps {
  pipelineRuns: PipelineRun[];
  pulses: ThreatPulse[];
  pythonModules: PythonModuleSpec[];
  syncing: boolean;
  readOnlyDemo: boolean;
  onSyncLiveFeeds: () => Promise<void>;
  onAfterIngest: () => Promise<void>;
}

const SAMPLE_DIRTY_BATCH = `185[.]220[.]101[.]44
91.92.240.118:443
192.168.1.45
10.0.4.12
100.64.0.15
198.51.100.77
hxxps://login-okta-support[.]com/auth
SSO-Okta-CloudVerify[.]com
CVE-2024-3400
cve-2024-50623
bad_malformed_token_$$
45.142.212.19`;

export default function PipelineWorkspace({
  pipelineRuns,
  pulses,
  pythonModules,
  syncing,
  readOnlyDemo,
  onSyncLiveFeeds,
  onAfterIngest,
}: PipelineWorkspaceProps) {
  const [rawText, setRawText] = React.useState('');
  const [sourceLabel, setSourceLabel] = React.useState<FeedSourceType>('Manual Batch');
  const [ingesting, setIngesting] = React.useState(false);
  const [ingestResult, setIngestResult] = React.useState<CustomIngestResponse | null>(null);
  const [ingestError, setIngestError] = React.useState<string | null>(null);
  const [activeModuleIndex, setActiveModuleIndex] = React.useState(0);
  const [copiedFile, setCopiedFile] = React.useState<string | null>(null);

  const handleRunCleaning = async () => {
    if (!rawText.trim() || readOnlyDemo) return;
    setIngesting(true);
    setIngestError(null);
    try {
      const resp = await fetch('/api/pipeline/ingest-custom', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rawText, sourceLabel }),
      });
      const json = (await resp.json()) as CustomIngestResponse & { error?: string };
      if (!resp.ok) throw new Error(json.error || 'Failed to process raw batch');
      setIngestResult(json);
      await onAfterIngest();
    } catch (err) {
      setIngestError(err instanceof Error ? err.message : 'Cleaning failed');
    } finally {
      setIngesting(false);
    }
  };

  const handleCopyCode = async (mod: PythonModuleSpec) => {
    try {
      await navigator.clipboard.writeText(mod.code);
      setCopiedFile(mod.filename);
      setTimeout(() => setCopiedFile(null), 1800);
    } catch {
      // Clipboard restricted
    }
  };

  const activeModule = pythonModules[activeModuleIndex] || null;

  return (
    <div className="space-y-6">
      <section className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 bg-[#111827] border border-slate-800 rounded-lg divide-y sm:divide-y-0 sm:divide-x divide-slate-800">
        <div className="p-5">
          <p className="text-xs font-medium text-blue-400">01. Live Collection</p>
          <h3 className="mt-1 text-sm font-semibold text-slate-100">
            REST API Threat Feeds
          </h3>
          <p className="mt-1.5 text-xs text-slate-400 leading-relaxed">
            Polls AlienVault OTX, date-sorted CISA KEV vulnerabilities, and online-sorted Abuse.ch Feodo C2 IPs.
          </p>
        </div>

        <div className="p-5">
          <p className="text-xs font-medium text-blue-400">02. Normalization & Filtering</p>
          <h3 className="mt-1 text-sm font-semibold text-slate-100">
            net.BlockList & Sightings
          </h3>
          <p className="mt-1.5 text-xs text-slate-400 leading-relaxed">
            Strips ports, refangs bracketed IOCs, drops private/CGNAT/documentation IPs, and tracks distinct sightings.
          </p>
        </div>

        <div className="p-5">
          <p className="text-xs font-medium text-blue-400">03. Statistical Scoring</p>
          <h3 className="mt-1 text-sm font-semibold text-slate-100">
            Median & MAD Robust Z
          </h3>
          <p className="mt-1.5 text-xs text-slate-400 leading-relaxed">
            Computes robust Modified Z-scores resistant to skewed recurrence distributions and tracks days observed.
          </p>
        </div>

        <div className="p-5">
          <p className="text-xs font-medium text-blue-400">04. Analyst Visibility</p>
          <h3 className="mt-1 text-sm font-semibold text-slate-100">
            Triage & CSV Export
          </h3>
          <p className="mt-1.5 text-xs text-slate-400 leading-relaxed">
            Persists triage status updates in SQLite and exports normalized CSV datasets for external BI tools.
          </p>
        </div>
      </section>

      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-5 bg-[#111827] border border-slate-800 rounded-lg p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-base font-semibold text-slate-100">
                Manual Batch Normalization Sandbox
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Pasted indicators are normalized and stored as Unclassified until triaged
              </p>
            </div>
            <button
              type="button"
              onClick={() => setRawText(SAMPLE_DIRTY_BATCH)}
              className="px-2.5 py-1 text-xs font-medium text-blue-400 hover:text-blue-300 border border-slate-700 rounded-md whitespace-nowrap"
            >
              Load Sample Batch
            </button>
          </div>

          <div className="space-y-1.5">
            <label htmlFor="ingest-source" className="block text-xs font-medium text-slate-300">
              Batch Source Label
            </label>
            <select
              id="ingest-source"
              value={sourceLabel}
              onChange={(e) => setSourceLabel(e.target.value as FeedSourceType)}
              className="w-full bg-[#0B1120] border border-slate-700 rounded-md px-3 py-2 text-xs text-slate-100 outline-none focus:border-blue-500"
            >
              <option value="Manual Batch">Manual Batch</option>
              <option value="AlienVault OTX">AlienVault OTX</option>
              <option value="CISA KEV">CISA KEV</option>
              <option value="Abuse.ch Feodo">Abuse.ch Feodo</option>
            </select>
          </div>

          <div className="space-y-1.5">
            <label htmlFor="raw-batch-input" className="block text-xs font-medium text-slate-300">
              Raw Indicators
            </label>
            <textarea
              id="raw-batch-input"
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              placeholder="Paste raw IPs (with or without :port), defanged domains, hxxps:// URLs, CVEs, or SHA-256 hashes..."
              className="w-full h-48 bg-[#0B1120] border border-slate-700 rounded-md p-3 text-xs font-mono text-slate-100 placeholder:text-slate-500 outline-none focus:border-blue-500 resize-none thin-scrollbar"
            />
          </div>

          {ingestError && <p className="text-xs text-red-400">{ingestError}</p>}

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={handleRunCleaning}
              disabled={readOnlyDemo || ingesting || !rawText.trim()}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-40 rounded-lg transition-colors whitespace-nowrap"
            >
              <Play className="w-3.5 h-3.5" />
              {readOnlyDemo ? 'Read-Only Demo' : ingesting ? 'Normalizing...' : 'Normalize Batch'}
            </button>

            <button
              type="button"
              onClick={onSyncLiveFeeds}
              disabled={readOnlyDemo || syncing}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-slate-200 bg-[#0B1120] hover:bg-slate-800 disabled:opacity-40 border border-slate-700 rounded-lg transition-colors whitespace-nowrap"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${syncing ? 'animate-spin' : ''}`} />
              {syncing ? 'Polling REST Feeds...' : 'Poll Live OSINT APIs'}
            </button>
          </div>
        </div>

        <div className="lg:col-span-7 bg-[#111827] border border-slate-800 rounded-lg overflow-hidden flex flex-col">
          <div className="px-5 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-semibold text-slate-100">
                Data Quality & Normalization Audit
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Token-by-token transformation log from raw ingestion to canonical schema
              </p>
            </div>
            {ingestResult && (
              <div className="flex items-center gap-3 text-xs font-mono tabular-nums text-slate-300">
                <span>Raw: {ingestResult.summary.rawTokens}</span>
                <span aria-hidden="true">·</span>
                <span className="text-emerald-400">New: {ingestResult.summary.persistedNew}</span>
                <span aria-hidden="true">·</span>
                <span className="text-blue-400">Merged: {ingestResult.summary.duplicatesMerged}</span>
                <span aria-hidden="true">·</span>
                <span className="text-amber-400">Dropped: {ingestResult.summary.droppedInvalid}</span>
              </div>
            )}
          </div>

          {!ingestResult ? (
            <div className="flex-1 flex flex-col items-center justify-center p-10 text-center">
              <p className="text-sm text-slate-300">No manual batch executed yet.</p>
              <p className="text-xs text-slate-500 mt-1 max-w-md">
                Click Load Sample Batch and Normalize Batch to verify port stripping, CGNAT/documentation IP filtering, and sighting deduplication.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto max-h-[340px] thin-scrollbar">
              <table className="w-full text-left border-collapse">
                <thead className="sticky top-0 bg-[#111827] border-b border-slate-800 text-xs font-medium text-slate-400">
                  <tr>
                    <th className="py-2.5 px-4">Raw Token</th>
                    <th className="py-2.5 px-3">Normalized Value</th>
                    <th className="py-2.5 px-3">Action</th>
                    <th className="py-2.5 px-4">Rule Applied</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80 text-xs">
                  {ingestResult.audit.map((row, idx) => (
                    <tr key={`${row.rawToken}-${idx}`} className="hover:bg-slate-800/30">
                      <td className="py-2 px-4 font-mono text-slate-300 max-w-[160px] truncate">
                        {row.rawToken}
                      </td>
                      <td className="py-2 px-3 font-mono text-slate-100 max-w-[180px] truncate">
                        {row.normalizedValue || '—'}
                      </td>
                      <td
                        className={`py-2 px-3 font-medium whitespace-nowrap ${
                          row.action === 'Persisted'
                            ? 'text-emerald-400'
                            : row.action === 'Merged Duplicate'
                              ? 'text-blue-400'
                              : 'text-amber-400'
                        }`}
                      >
                        {row.action}
                      </td>
                      <td className="py-2 px-4 text-slate-400">{row.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>

      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 bg-[#111827] border border-slate-800 rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-800">
            <h3 className="text-sm font-semibold text-slate-100">Pipeline Execution History</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Genuine OSINT REST syncs and batch runs (zero synthetic history)
            </p>
          </div>
          {pipelineRuns.length === 0 ? (
            <div className="p-10 text-center">
              <p className="text-sm text-slate-300">No live pipeline runs recorded yet.</p>
              <p className="text-xs text-slate-500 mt-1">
                Trigger Sync Live Feeds or Normalize Batch to record real execution metrics.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-xs font-medium text-slate-400">
                    <th className="py-2.5 px-4">Source Pipeline</th>
                    <th className="py-2.5 px-3 text-right">Raw</th>
                    <th className="py-2.5 px-3 text-right">Deduped</th>
                    <th className="py-2.5 px-3 text-right">Dropped</th>
                    <th className="py-2.5 px-3 text-right">Clean</th>
                    <th className="py-2.5 px-4 text-right">Outcome</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80 text-xs">
                  {pipelineRuns.slice(0, 8).map((run) => (
                    <tr key={run.id} className="hover:bg-slate-800/30">
                      <td className="py-2.5 px-4">
                        <div className="text-slate-200 font-medium">{run.sourceName}</div>
                        <div className="text-[11px] font-mono text-slate-500 tabular-nums">
                          {new Date(run.timestamp).toLocaleString([], {
                            month: 'short',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                          })}{' '}
                          · {run.durationMs}ms
                        </div>
                        {run.errorMessage && (
                          <div className="text-[11px] text-amber-400 mt-0.5">
                            {run.errorMessage}
                          </div>
                        )}
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono tabular-nums text-slate-300">
                        {run.rawCount}
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono tabular-nums text-blue-400">
                        {run.duplicatesRemoved}
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono tabular-nums text-amber-400">
                        {run.malformedDropped}
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono tabular-nums text-emerald-400">
                        {run.normalizedCount}
                      </td>
                      <td
                        className={`py-2.5 px-4 text-right whitespace-nowrap font-medium ${
                          run.status === 'Failed'
                            ? 'text-red-400'
                            : run.status === 'Partial'
                              ? 'text-amber-400'
                              : 'text-emerald-400'
                        }`}
                      >
                        {run.status}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="lg:col-span-5 bg-[#111827] border border-slate-800 rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-800">
            <h3 className="text-sm font-semibold text-slate-100">Collected Pulses & Feeds</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Provenance tagged explicitly as Live Feed or Sample Fixture
            </p>
          </div>
          <div className="divide-y divide-slate-800/80 max-h-[360px] overflow-y-auto thin-scrollbar">
            {pulses.map((pulse) => (
              <div key={pulse.id} className="p-4 space-y-1.5">
                <div className="flex items-start justify-between gap-3">
                  <h4 className="text-xs font-semibold text-slate-100 leading-snug">
                    {pulse.title}
                  </h4>
                  <span className="text-[11px] font-mono text-slate-400 whitespace-nowrap shrink-0">
                    {pulse.tlp}
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-400">
                  <span className={pulse.isSample ? 'text-slate-400' : 'text-blue-400'}>
                    {pulse.isSample ? 'Sample Fixture' : 'Live Feed'}
                  </span>
                  <span aria-hidden="true">·</span>
                  <span>{pulse.source}</span>
                  <span aria-hidden="true">·</span>
                  <span className="font-mono tabular-nums">
                    {pulse.cleanedIndicatorCount}/{pulse.rawIndicatorCount} clean IOCs
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {pythonModules.length > 0 && (
        <section className="bg-[#111827] border border-slate-800 rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-100">
                Optional Standalone Python Templates
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Read-only reference templates for offline Python workflows (this live web app executes in Node/TypeScript)
              </p>
            </div>
            <div className="inline-flex flex-wrap items-center gap-1 p-1 bg-[#0B1120] border border-slate-800 rounded-lg">
              {pythonModules.map((mod, idx) => (
                <button
                  key={mod.filename}
                  type="button"
                  onClick={() => setActiveModuleIndex(idx)}
                  className={`px-3 py-1.5 text-xs font-mono rounded-md transition-colors whitespace-nowrap ${
                    activeModuleIndex === idx
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-400 hover:text-slate-100'
                  }`}
                >
                  {mod.filename}
                </button>
              ))}
            </div>
          </div>

          {activeModule && (
            <div className="p-5 space-y-4">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div>
                  <p className="text-xs text-blue-400 font-medium">{activeModule.stage}</p>
                  <h4 className="text-sm font-semibold text-slate-100 mt-0.5">
                    {activeModule.title}
                  </h4>
                  <p className="text-xs text-slate-400 mt-1 max-w-3xl">
                    {activeModule.description}
                  </p>
                  <p className="text-xs text-slate-500 mt-1.5 font-mono">
                    Libraries: {activeModule.libraries.join(' · ')}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => handleCopyCode(activeModule)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-[#0B1120] hover:bg-slate-800 border border-slate-700 rounded-md transition-colors whitespace-nowrap"
                >
                  {copiedFile === activeModule.filename ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      Copied
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      Copy Script
                    </>
                  )}
                </button>
              </div>

              <pre className="bg-[#0B1120] border border-slate-800 rounded-lg p-4 overflow-x-auto text-xs font-mono text-slate-200 leading-relaxed thin-scrollbar">
                <code>{activeModule.code}</code>
              </pre>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
