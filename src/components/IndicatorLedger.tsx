import React from 'react';
import { Search, Download, X } from 'lucide-react';
import type { ThreatIndicator, ThreatSeverity, ThreatStatus } from '../types';

interface IndicatorLedgerProps {
  indicators: ThreatIndicator[];
  loading: boolean;
  readOnlyDemo: boolean;
  searchQuery: string;
  selectedSeverity: string;
  selectedStatus: string;
  onSearchChange: (q: string) => void;
  onSeverityChange: (s: string) => void;
  onStatusChange: (s: string) => void;
  onResetFilters: () => void;
  onExportCsv: () => void;
  selectedIndicator: ThreatIndicator | null;
  onSelectIndicator: (ind: ThreatIndicator | null) => void;
  onUpdateStatus: (id: string, status: ThreatStatus) => Promise<void>;
}

const SEVERITIES: Array<'' | ThreatSeverity> = ['', 'Critical', 'High', 'Medium', 'Low', 'Unclassified'];
const STATUSES: Array<'' | ThreatStatus> = ['', 'Active', 'Investigating', 'Mitigated'];

const SEVERITY_COLOR: Record<ThreatSeverity, string> = {
  Critical: 'text-red-400',
  High: 'text-amber-400',
  Medium: 'text-sky-400',
  Low: 'text-slate-400',
  Unclassified: 'text-slate-400',
};

const STATUS_COLOR: Record<ThreatStatus, string> = {
  Active: 'text-red-400',
  Investigating: 'text-amber-400',
  Mitigated: 'text-emerald-400',
};

export default function IndicatorLedger({
  indicators,
  loading,
  readOnlyDemo,
  searchQuery,
  selectedSeverity,
  selectedStatus,
  onSearchChange,
  onSeverityChange,
  onStatusChange,
  onResetFilters,
  onExportCsv,
  selectedIndicator,
  onSelectIndicator,
  onUpdateStatus,
}: IndicatorLedgerProps) {
  const [updatingId, setUpdatingId] = React.useState<string | null>(null);
  const [triageError, setTriageError] = React.useState<string | null>(null);

  const handleStatusClick = async (id: string, nextStatus: ThreatStatus) => {
    if (readOnlyDemo) return;
    setUpdatingId(id);
    setTriageError(null);
    try {
      await onUpdateStatus(id, nextStatus);
    } catch (err) {
      setTriageError(err instanceof Error ? err.message : 'Status update failed');
    } finally {
      setUpdatingId(null);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div className="flex flex-wrap items-center gap-3 flex-1 min-w-[260px]">
          <div className="relative flex-1 max-w-sm">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder="Filter by IP, domain, CVE, hash, ASN, or pulse..."
              className="w-full bg-[#111827] border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 outline-none focus:border-blue-500"
            />
          </div>

          <div className="inline-flex flex-wrap items-center gap-1 p-1 bg-[#111827] border border-slate-800 rounded-lg">
            {SEVERITIES.map((sev) => (
              <button
                key={sev || 'all'}
                type="button"
                onClick={() => onSeverityChange(sev)}
                className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                  selectedSeverity === sev
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-400 hover:text-slate-100'
                }`}
              >
                {sev || 'All Severities'}
              </button>
            ))}
          </div>

          <select
            aria-label="Filter by triage status"
            value={selectedStatus}
            onChange={(e) => onStatusChange(e.target.value)}
            className="bg-[#111827] border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 outline-none focus:border-blue-500"
          >
            {STATUSES.map((st) => (
              <option key={st || 'all'} value={st}>
                {st ? `Status: ${st}` : 'All Statuses'}
              </option>
            ))}
          </select>
        </div>

        <button
          type="button"
          onClick={onExportCsv}
          className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-slate-200 bg-[#111827] hover:bg-slate-800 border border-slate-700 rounded-lg transition-colors whitespace-nowrap shrink-0"
        >
          <Download className="w-3.5 h-3.5" />
          Export Ledger CSV
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <div
          className={`${
            selectedIndicator ? 'lg:col-span-8' : 'lg:col-span-12'
          } bg-[#111827] border border-slate-800 rounded-lg overflow-hidden`}
        >
          {loading && indicators.length === 0 ? (
            <div className="p-6 space-y-3 animate-pulse">
              {[0, 1, 2, 3, 4].map((idx) => (
                <div key={idx} className="h-9 bg-slate-800/70 rounded" />
              ))}
            </div>
          ) : indicators.length === 0 ? (
            <div className="p-12 text-center">
              <p className="text-sm font-medium text-slate-200">
                No consolidated indicators match your filters.
              </p>
              <p className="text-xs text-slate-400 mt-1">
                Adjust your search query or clear severity and status filters.
              </p>
              <button
                type="button"
                onClick={onResetFilters}
                className="mt-4 px-4 py-2 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 rounded-lg transition-colors"
              >
                Reset Filters
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-xs font-medium text-slate-400">
                    <th className="py-3 px-4">Normalized Indicator</th>
                    <th className="py-3 px-3">Origin</th>
                    <th className="py-3 px-3">Source Feed</th>
                    <th className="py-3 px-3">Category</th>
                    <th className="py-3 px-3">Severity</th>
                    <th className="py-3 px-3 text-right">Sightings</th>
                    <th className="py-3 px-3 text-right">Days</th>
                    <th className="py-3 px-3 text-right">Robust Z</th>
                    <th className="py-3 px-4 text-right">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80 text-xs">
                  {indicators.map((item) => {
                    const isSelected = selectedIndicator?.id === item.id;
                    return (
                      <tr
                        key={item.id}
                        onClick={() => onSelectIndicator(item)}
                        className={`cursor-pointer transition-colors ${
                          isSelected ? 'bg-blue-600/10' : 'hover:bg-slate-800/40'
                        }`}
                      >
                        <td className="py-2.5 px-4 font-mono text-slate-100 max-w-[210px] truncate">
                          {item.normalizedIndicator}
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                          <span className="font-mono">{item.type}</span>{' '}
                          <span className="text-slate-600">·</span>{' '}
                          <span className={item.isSample ? 'text-slate-400' : 'text-blue-400'}>
                            {item.isSample ? 'Sample' : 'Live'}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">
                          {item.source}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">
                          {item.category}
                        </td>
                        <td className={`py-2.5 px-3 font-medium whitespace-nowrap ${SEVERITY_COLOR[item.severity]}`}>
                          {item.severity}
                        </td>
                        <td className="py-2.5 px-3 text-right font-mono tabular-nums text-slate-200">
                          {item.recurrenceCount}
                        </td>
                        <td className="py-2.5 px-3 text-right font-mono tabular-nums text-slate-400">
                          {item.daysObserved}d
                        </td>
                        <td
                          className={`py-2.5 px-3 text-right font-mono tabular-nums ${
                            item.zScore >= 1.5 ? 'text-amber-400 font-medium' : 'text-slate-300'
                          }`}
                        >
                          {item.zScore >= 0 ? `+${item.zScore.toFixed(2)}` : item.zScore.toFixed(2)}σ
                        </td>
                        <td className={`py-2.5 px-4 text-right font-medium whitespace-nowrap ${STATUS_COLOR[item.status]}`}>
                          {item.status}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {selectedIndicator && (
          <aside className="lg:col-span-4 bg-[#111827] border border-slate-800 rounded-lg divide-y divide-slate-800">
            <div className="p-5 flex items-start justify-between gap-3">
              <div className="min-w-0">
                <p className="text-xs text-slate-400">
                  {selectedIndicator.type} · {selectedIndicator.source} ·{' '}
                  {selectedIndicator.isSample ? 'Sample Fixture' : 'Live OSINT'}
                </p>
                <h3 className="mt-1 text-sm font-mono font-semibold text-slate-100 break-all">
                  {selectedIndicator.normalizedIndicator}
                </h3>
              </div>
              <button
                type="button"
                aria-label="Close inspector"
                onClick={() => onSelectIndicator(null)}
                className="p-1.5 text-slate-400 hover:text-slate-100 rounded-md hover:bg-slate-800 shrink-0"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 space-y-3 text-xs">
              <div className="flex justify-between gap-2">
                <span className="text-slate-400">Attack Pattern</span>
                <span className="text-slate-200 font-medium text-right">{selectedIndicator.category}</span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-slate-400">MITRE ATT&CK</span>
                <span className="text-slate-200 text-right">{selectedIndicator.mitreTactic}</span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-slate-400">Distinct Sightings</span>
                <span className="font-mono tabular-nums text-slate-100">
                  {selectedIndicator.recurrenceCount} sightings
                </span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-slate-400">Days Observed</span>
                <span className="font-mono tabular-nums text-slate-100">
                  {selectedIndicator.daysObserved} days
                </span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-slate-400">Robust Z-Score (MAD)</span>
                <span className="font-mono tabular-nums text-amber-400">
                  {selectedIndicator.zScore >= 0
                    ? `+${selectedIndicator.zScore.toFixed(2)}`
                    : selectedIndicator.zScore.toFixed(2)}σ
                </span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-slate-400">Confidence</span>
                <span className="font-mono tabular-nums text-slate-200">
                  {selectedIndicator.confidenceScore > 0 ? `${selectedIndicator.confidenceScore}%` : 'Unclassified'}
                </span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-slate-400">Origin / ASN</span>
                <span className="font-mono text-slate-300 text-right">
                  {selectedIndicator.country} · {selectedIndicator.asn}
                </span>
              </div>
            </div>

            <div className="p-5 space-y-2 text-xs">
              <p className="font-medium text-slate-300">Consolidation & Cleaning Trace</p>
              <p className="font-mono text-[11px] text-slate-400 break-all">
                Raw sample: {selectedIndicator.rawSample}
              </p>
              <p className="text-slate-400 leading-relaxed">{selectedIndicator.cleaningNotes}</p>
              <p className="text-slate-500 pt-1">Pulse: {selectedIndicator.pulseTitle}</p>
            </div>

            <div className="p-5 space-y-2.5">
              <p className="text-xs font-medium text-slate-300">
                Analyst Triage Status {readOnlyDemo ? '(Read-Only Demo)' : ''}
              </p>
              {triageError && <p className="text-xs text-red-400">{triageError}</p>}
              <div className="grid grid-cols-3 gap-2">
                {(['Active', 'Investigating', 'Mitigated'] as ThreatStatus[]).map((st) => {
                  const active = selectedIndicator.status === st;
                  return (
                    <button
                      key={st}
                      type="button"
                      disabled={readOnlyDemo || updatingId === selectedIndicator.id}
                      onClick={() => handleStatusClick(selectedIndicator.id, st)}
                      className={`px-2 py-2 text-xs font-medium rounded-md border transition-colors whitespace-nowrap disabled:opacity-40 ${
                        active
                          ? 'bg-blue-600 border-blue-500 text-white'
                          : 'bg-[#0B1120] border-slate-700 text-slate-300 hover:bg-slate-800'
                      }`}
                    >
                      {st}
                    </button>
                  );
                })}
              </div>
            </div>
          </aside>
        )}
      </div>
    </div>
  );
}
