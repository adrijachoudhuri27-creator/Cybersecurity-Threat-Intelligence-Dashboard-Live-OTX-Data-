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
  onSyncLiveFeeds: () => Promise<void>;
  onAfterIngest: () => Promise<void>;
}

const SAMPLE_DIRTY_BATCH = `185[.]220[.]101[.]44
192.168.1.45
10.0.4.12
hxxps://login-okta-support[.]com/auth
SSO-Okta-CloudVerify[.]com
CVE-2024-3400
cve-2024-50623
91.92.240.118
127.0.0.1
bad_malformed_token_$$
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
45.142.212.19`;

export default function PipelineWorkspace({
  pipelineRuns,
  pulses,
  pythonModules,
  syncing,
  onSyncLiveFeeds,
  onAfterIngest,
}: PipelineWorkspaceProps) {
  const [rawText, setRawText] = React.useState('');
  const [sourceLabel, setSourceLabel] = React.useState<FeedSourceType>('Selenium Web Scraper');
  const [ingesting, setIngesting] = React.useState(false);
  const [ingestResult, setIngestResult] = React.useState<CustomIngestResponse | null>(null);
  const [ingestError, setIngestError] = React.useState<string | null>(null);
  const [activeModuleIndex, setActiveModuleIndex] = React.useState(0);
  const [copiedFile, setCopiedFile] = React.useState<string | null>(null);

  const handleRunCleaning = async () => {
    if (!rawText.trim()) return;
    setIngesting(true);
    setIngestError(null);
    try {
      const resp = await fetch('/api/pipeline/ingest-custom', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rawText, sourceLabel }),
      });
      if (!resp.ok) throw new Error('Failed to process raw batch');
      const data = (await resp.json()) as CustomIngestResponse;
      setIngestResult(data);
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
      {/* Architecture Stages Strip */}
      <section className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 bg-[#111827] border border-slate-800 rounded-lg divide-y sm:divide-y-0 sm:divide-x divide-slate-800">
        <div className="p-5">
          <p className="text-xs font-medium text-blue-400">01. Data Collection</p>
          <h3 className="mt-1 text-sm font-semibold text-slate-100">
            AlienVault OTX & Selenium
          </h3>
          <p className="mt-1.5 text-xs text-slate-400 leading-relaxed">
            REST API pulse polling paired with headless Selenium extraction from web security advisories.
          </p>
        </div>

        <div className="p-5">
          <p className="text-xs font-medium text-blue-400">02. Consolidation & Cleaning</p>
          <h3 className="mt-1 text-sm font-semibold text-slate-100">
            Pandas Deduplication
          </h3>
          <p className="mt-1.5 text-xs text-slate-400 leading-relaxed">
            Refangs bracketed indicators, removes RFC1918 private ranges, and merges cross-feed duplicates.
          </p>
        </div>

        <div className="p-5">
          <p className="text-xs font-medium text-blue-400">03. Statistical Analysis</p>
          <h3 className="mt-1 text-sm font-semibold text-slate-100">
            NumPy Z-Score Engine
          </h3>
          <p className="mt-1.5 text-xs text-slate-400 leading-relaxed">
            Computes recurrence mean and standard deviation to surface statistically anomalous campaigns.
          </p>
        </div>

        <div className="p-5">
          <p className="text-xs font-medium text-blue-400">04. Threat Visibility</p>
          <h3 className="mt-1 text-sm font-semibold text-slate-100">
            Power BI & Streamlit
          </h3>
          <p className="mt-1.5 text-xs text-slate-400 leading-relaxed">
            Publishes normalized datasets for executive cross-filtering and interactive parameter exploration.
          </p>
        </div>
      </section>

      {/* Interactive Raw Ingestion & Cleaning Workbench */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-5 bg-[#111827] border border-slate-800 rounded-lg p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-base font-semibold text-slate-100">
                Raw Feed Consolidation Sandbox
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Test normalization, RFC1918 filtering, and deduplication against SQLite
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
              Attribution Source
            </label>
            <select
              id="ingest-source"
              value={sourceLabel}
              onChange={(e) => setSourceLabel(e.target.value as FeedSourceType)}
              className="w-full bg-[#0B1120] border border-slate-700 rounded-md px-3 py-2 text-xs text-slate-100 outline-none focus:border-blue-500"
            >
              <option value="Selenium Web Scraper">Selenium Web Scraper</option>
              <option value="AlienVault OTX">AlienVault OTX</option>
              <option value="CISA KEV">CISA KEV</option>
              <option value="Abuse.ch Feodo">Abuse.ch Feodo</option>
            </select>
          </div>

          <div className="space-y-1.5">
            <label htmlFor="raw-batch-input" className="block text-xs font-medium text-slate-300">
              Uncleaned OSINT / Scraped Indicators
            </label>
            <textarea
              id="raw-batch-input"
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              placeholder="Paste raw IPs, defanged domains (example[.]com), hxxps:// URLs, CVEs, or SHA-256 hashes..."
              className="w-full h-48 bg-[#0B1120] border border-slate-700 rounded-md p-3 text-xs font-mono text-slate-100 placeholder:text-slate-500 outline-none focus:border-blue-500 resize-none thin-scrollbar"
            />
          </div>

          {ingestError && <p className="text-xs text-red-400">{ingestError}</p>}

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={handleRunCleaning}
              disabled={ingesting || !rawText.trim()}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-40 rounded-lg transition-colors whitespace-nowrap"
            >
              <Play className="w-3.5 h-3.5" />
              {ingesting ? 'Consolidating...' : 'Run Cleaning Pipeline'}
            </button>

            <button
              type="button"
              onClick={onSyncLiveFeeds}
              disabled={syncing}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-slate-200 bg-[#0B1120] hover:bg-slate-800 disabled:opacity-40 border border-slate-700 rounded-lg transition-colors whitespace-nowrap"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${syncing ? 'animate-spin' : ''}`} />
              {syncing ? 'Polling REST Feeds...' : 'Poll Live OSINT APIs'}
            </button>
          </div>
        </div>

        {/* Cleaning Audit Output */}
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
              <p className="text-sm text-slate-300">No custom cleaning batch executed yet.</p>
              <p className="text-xs text-slate-500 mt-1 max-w-md">
                Click Load Sample Batch and Run Cleaning Pipeline to inspect how bracketed domains, private IPs, and duplicates are normalized.
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

      {/* Pipeline Run Execution History + Active OSINT Pulses */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 bg-[#111827] border border-slate-800 rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-800">
            <h3 className="text-sm font-semibold text-slate-100">Pipeline Execution History</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Recorded OSINT REST API syncs and Pandas consolidation runs
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-xs font-medium text-slate-400">
                  <th className="py-2.5 px-4">Source Pipeline</th>
                  <th className="py-2.5 px-3 text-right">Raw</th>
                  <th className="py-2.5 px-3 text-right">Deduped</th>
                  <th className="py-2.5 px-3 text-right">Dropped</th>
                  <th className="py-2.5 px-3 text-right">Clean</th>
                  <th className="py-2.5 px-4 text-right">Mode</th>
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
                    <td className="py-2.5 px-4 text-right whitespace-nowrap text-slate-300">
                      {run.status}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Collected Pulses & Web Advisories */}
        <div className="lg:col-span-5 bg-[#111827] border border-slate-800 rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-800">
            <h3 className="text-sm font-semibold text-slate-100">Collected Pulses & Advisories</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Recent AlienVault OTX, CISA KEV, and scraped threat bulletins
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
                  <span>{pulse.source}</span>
                  <span aria-hidden="true">·</span>
                  <span>{pulse.adversary}</span>
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

      {/* Python Reference Architecture Inspector */}
      {pythonModules.length > 0 && (
        <section className="bg-[#111827] border border-slate-800 rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-100">
                Python ETL & Streamlit Reference Modules
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Production Python scripts covering OTX REST collection, Selenium scraping, Pandas/NumPy cleaning, and Streamlit
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
