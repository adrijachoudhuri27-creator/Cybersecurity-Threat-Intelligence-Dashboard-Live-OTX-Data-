import React from 'react';
import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  ZAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
  BarChart,
  Bar,
} from 'recharts';
import { Download, RotateCcw } from 'lucide-react';
import type { DashboardResponse, FeedSourceType, IndicatorType, ThreatIndicator } from '../types';

interface ParameterExplorerProps {
  data: DashboardResponse | null;
  loading: boolean;
  minRecurrence: number;
  zThreshold: number;
  days: number;
  selectedSource: string;
  selectedType: string;
  onChangeMinRecurrence: (v: number) => void;
  onChangeZThreshold: (v: number) => void;
  onChangeDays: (v: number) => void;
  onChangeSource: (v: string) => void;
  onChangeType: (v: string) => void;
  onResetParams: () => void;
  onInspectIndicator: (indicator: ThreatIndicator) => void;
}

const IOC_TYPES: Array<'' | IndicatorType> = ['', 'IPv4', 'Domain', 'URL', 'SHA256', 'CVE'];
const SOURCES: Array<'' | FeedSourceType> = [
  '',
  'AlienVault OTX',
  'CISA KEV',
  'Abuse.ch Feodo',
  'Manual Batch',
];

export default function ParameterExplorer({
  data,
  loading,
  minRecurrence,
  zThreshold,
  days,
  selectedSource,
  selectedType,
  onChangeMinRecurrence,
  onChangeZThreshold,
  onChangeDays,
  onChangeSource,
  onChangeType,
  onResetParams,
  onInspectIndicator,
}: ParameterExplorerProps) {
  const handleDownloadFilteredCsv = () => {
    if (!data?.filteredIndicators.length) return;
    const headers = [
      'indicator',
      'type',
      'source',
      'category',
      'severity',
      'recurrenceCount',
      'daysObserved',
      'zScore',
      'confidenceScore',
      'mitreTactic',
      'status',
      'isSample',
    ];
    const rows = data.filteredIndicators.map((row) =>
      [
        row.indicator,
        row.type,
        row.source,
        row.category,
        row.severity,
        row.recurrenceCount,
        row.daysObserved,
        row.zScore,
        row.confidenceScore,
        row.mitreTactic,
        row.status,
        row.isSample,
      ]
        .map((v) => `"${String(v).replace(/"/g, '""')}"`)
        .join(',')
    );
    const blob = new Blob([[headers.join(','), ...rows].join('\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'filtered_indicators.csv';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
      <aside className="lg:col-span-3 bg-[#111827] border border-slate-800 rounded-lg p-5 space-y-5">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">Analysis Parameters</h2>
            <p className="text-xs text-slate-400 mt-0.5">Robust Median & MAD slice</p>
          </div>
          <button
            type="button"
            onClick={onResetParams}
            className="text-xs text-slate-400 hover:text-slate-100 inline-flex items-center gap-1 whitespace-nowrap"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Reset
          </button>
        </div>

        <div className="space-y-2">
          <label className="block text-xs font-medium text-slate-300">Collection Window</label>
          <div className="grid grid-cols-2 gap-1.5">
            {[
              { label: '24 Hours', value: 1 },
              { label: '7 Days', value: 7 },
              { label: '30 Days', value: 30 },
              { label: 'All Time', value: 3650 },
            ].map((opt) => (
              <button
                key={opt.value}
                type="button"
                onClick={() => onChangeDays(opt.value)}
                className={`px-2.5 py-1.5 text-xs font-medium rounded-md border transition-colors whitespace-nowrap ${
                  days === opt.value
                    ? 'bg-blue-600 border-blue-500 text-white'
                    : 'bg-[#0B1120] border-slate-800 text-slate-400 hover:text-slate-100'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <label htmlFor="min-recurrence" className="font-medium text-slate-300">
              Minimum Distinct Sightings
            </label>
            <span className="font-mono tabular-nums text-blue-400">{minRecurrence}+</span>
          </div>
          <input
            id="min-recurrence"
            type="range"
            min={1}
            max={10}
            step={1}
            value={minRecurrence}
            onChange={(e) => onChangeMinRecurrence(Number(e.target.value))}
            className="w-full accent-blue-500 cursor-pointer"
          />
          <div className="flex justify-between text-[11px] font-mono text-slate-500 tabular-nums">
            <span>1</span>
            <span>5</span>
            <span>10</span>
          </div>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <label htmlFor="z-cutoff" className="font-medium text-slate-300">
              Robust Z-Score Cutoff
            </label>
            <span className="font-mono tabular-nums text-amber-400">
              {zThreshold <= -5 ? 'All' : `≥ ${zThreshold.toFixed(1)}σ`}
            </span>
          </div>
          <input
            id="z-cutoff"
            type="range"
            min={-2}
            max={2.5}
            step={0.5}
            value={zThreshold <= -5 ? -2 : zThreshold}
            onChange={(e) => {
              const val = Number(e.target.value);
              onChangeZThreshold(val <= -2 ? -10 : val);
            }}
            className="w-full accent-blue-500 cursor-pointer"
          />
          <div className="flex justify-between text-[11px] font-mono text-slate-500 tabular-nums">
            <span>All</span>
            <span>0.0σ</span>
            <span>+2.5σ</span>
          </div>
        </div>

        <div className="space-y-2">
          <label htmlFor="source-select" className="block text-xs font-medium text-slate-300">
            OSINT / Batch Source
          </label>
          <select
            id="source-select"
            value={selectedSource}
            onChange={(e) => onChangeSource(e.target.value)}
            className="w-full bg-[#0B1120] border border-slate-700 rounded-md px-3 py-2 text-xs text-slate-100 outline-none focus:border-blue-500"
          >
            {SOURCES.map((s) => (
              <option key={s || 'all'} value={s}>
                {s || 'All Consolidated Sources'}
              </option>
            ))}
          </select>
        </div>

        <div className="space-y-2">
          <label className="block text-xs font-medium text-slate-300">Indicator Type</label>
          <div className="flex flex-wrap gap-1.5">
            {IOC_TYPES.map((t) => (
              <button
                key={t || 'all'}
                type="button"
                onClick={() => onChangeType(t)}
                className={`px-2.5 py-1 text-xs font-mono rounded border transition-colors whitespace-nowrap ${
                  selectedType === t
                    ? 'bg-blue-600 border-blue-500 text-white'
                    : 'bg-[#0B1120] border-slate-800 text-slate-400 hover:text-slate-100'
                }`}
              >
                {t || 'All'}
              </button>
            ))}
          </div>
        </div>
      </aside>

      <div className="lg:col-span-9 space-y-6">
        <div className="grid grid-cols-2 sm:grid-cols-4 bg-[#111827] border border-slate-800 rounded-lg divide-y sm:divide-y-0 sm:divide-x divide-slate-800">
          <div className="p-4">
            <p className="text-xs text-slate-400">Filtered Rows</p>
            <p className="mt-1 text-2xl font-semibold font-mono tabular-nums text-slate-50">
              {data?.filteredIndicators.length ?? 0}
            </p>
          </div>
          <div className="p-4">
            <p className="text-xs text-slate-400">Median Sightings</p>
            <p className="mt-1 text-2xl font-semibold font-mono tabular-nums text-slate-50">
              {data?.kpis.medianRecurrence.toFixed(2) ?? '0.00'}
            </p>
          </div>
          <div className="p-4">
            <p className="text-xs text-slate-400">MAD Spread</p>
            <p className="mt-1 text-2xl font-semibold font-mono tabular-nums text-slate-50">
              {data?.kpis.madRecurrence.toFixed(2) ?? '0.00'}
            </p>
          </div>
          <div className="p-4">
            <p className="text-xs text-slate-400">Max Robust Z</p>
            <p className="mt-1 text-2xl font-semibold font-mono tabular-nums text-amber-400">
              {data ? `+${data.kpis.maxRobustZ.toFixed(2)}σ` : '0.00σ'}
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
          <div className="xl:col-span-7 bg-[#111827] border border-slate-800 rounded-lg p-5">
            <div className="mb-4">
              <h3 className="text-base font-semibold text-slate-100">
                High-Recurrence Outlier Matrix
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Median/MAD robust Z-score plotted against distinct sightings (threshold line at 1.5σ)
              </p>
            </div>

            {loading && !data ? (
              <div className="h-[260px] bg-slate-900/50 rounded animate-pulse" />
            ) : !data?.scatterPoints.length ? (
              <div className="h-[260px] flex flex-col items-center justify-center text-center">
                <p className="text-sm text-slate-300">No indicators satisfy the active thresholds.</p>
                <button
                  type="button"
                  onClick={onResetParams}
                  className="mt-3 px-3 py-1.5 text-xs font-medium text-blue-400 border border-slate-700 rounded-md hover:bg-slate-800"
                >
                  Reset Parameters
                </button>
              </div>
            ) : (
              <div className="h-[260px] w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <ScatterChart margin={{ top: 12, right: 16, bottom: 8, left: -12 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" />
                    <XAxis
                      type="number"
                      dataKey="recurrence"
                      name="Distinct Sightings"
                      stroke="#94A3B8"
                      fontSize={11}
                      tickLine={false}
                      allowDecimals={false}
                    />
                    <YAxis
                      type="number"
                      dataKey="zScore"
                      name="Robust Z-Score"
                      stroke="#94A3B8"
                      fontSize={11}
                      tickLine={false}
                    />
                    <ZAxis type="number" dataKey="confidence" range={[50, 220]} name="Confidence" />
                    <ReferenceLine y={1.5} stroke="#F59E0B" strokeDasharray="4 4" />
                    <Tooltip
                      cursor={{ strokeDasharray: '3 3', stroke: '#475569' }}
                      content={({ active, payload }) => {
                        if (!active || !payload?.length) return null;
                        const pt = payload[0].payload as DashboardResponse['scatterPoints'][0];
                        return (
                          <div className="bg-[#0F172A] border border-slate-700 rounded-lg p-3 text-xs space-y-1 shadow-lg">
                            <p className="font-mono font-semibold text-slate-100">{pt.indicator}</p>
                            <p className="text-slate-400">
                              {pt.type} · {pt.category} · {pt.isSample ? 'Sample' : 'Live'}
                            </p>
                            <p className="font-mono tabular-nums text-blue-400">
                              Sightings: {pt.recurrence} · Days: {pt.daysObserved} · Robust Z: {pt.zScore}σ
                            </p>
                          </div>
                        );
                      }}
                    />
                    <Scatter data={data.scatterPoints} fill="#3B82F6" fillOpacity={0.85} />
                  </ScatterChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>

          <div className="xl:col-span-5 bg-[#111827] border border-slate-800 rounded-lg p-5">
            <div className="mb-4">
              <h3 className="text-base font-semibold text-slate-100">
                Origin & Hosting Geographies
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Consolidated indicator count by ISO country code
              </p>
            </div>
            <div className="h-[260px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data?.byCountry || []} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
                  <XAxis dataKey="name" stroke="#94A3B8" fontSize={11} tickLine={false} axisLine={false} />
                  <YAxis stroke="#94A3B8" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0F172A',
                      border: '1px solid #334155',
                      borderRadius: '8px',
                      fontSize: '12px',
                      color: '#F8FAFC',
                    }}
                  />
                  <Bar dataKey="count" name="Indicators" fill="#3B82F6" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-lg overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-slate-100">
                Consolidated Indicator Table
              </h3>
              <p className="text-xs text-slate-400">
                Normalized SQLite schema with sample vs. live provenance
              </p>
            </div>
            <button
              type="button"
              onClick={handleDownloadFilteredCsv}
              disabled={!data?.filteredIndicators.length}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-[#0B1120] hover:bg-slate-800 disabled:opacity-40 border border-slate-700 rounded-md transition-colors whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5" />
              Export Filtered CSV
            </button>
          </div>

          <div className="overflow-x-auto max-h-[340px] thin-scrollbar">
            <table className="w-full text-left border-collapse">
              <thead className="sticky top-0 bg-[#111827] border-b border-slate-800 text-xs font-mono text-slate-400">
                <tr>
                  <th className="py-2.5 px-4">normalized_indicator</th>
                  <th className="py-2.5 px-3">type</th>
                  <th className="py-2.5 px-3">origin</th>
                  <th className="py-2.5 px-3">source</th>
                  <th className="py-2.5 px-3 text-right">sightings</th>
                  <th className="py-2.5 px-3 text-right">days</th>
                  <th className="py-2.5 px-3 text-right">robust_z</th>
                  <th className="py-2.5 px-4 text-right">confidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 text-xs">
                {(data?.filteredIndicators || []).map((row) => (
                  <tr
                    key={row.id}
                    onClick={() => onInspectIndicator(row)}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                  >
                    <td className="py-2 px-4 font-mono text-slate-100 max-w-[240px] truncate">
                      {row.normalizedIndicator}
                    </td>
                    <td className="py-2 px-3 font-mono text-slate-400">{row.type}</td>
                    <td className={`py-2 px-3 whitespace-nowrap ${row.isSample ? 'text-slate-400' : 'text-blue-400'}`}>
                      {row.isSample ? 'Sample' : 'Live'}
                    </td>
                    <td className="py-2 px-3 text-slate-300 whitespace-nowrap">{row.source}</td>
                    <td className="py-2 px-3 text-right font-mono tabular-nums text-slate-200">
                      {row.recurrenceCount}
                    </td>
                    <td className="py-2 px-3 text-right font-mono tabular-nums text-slate-400">
                      {row.daysObserved}d
                    </td>
                    <td
                      className={`py-2 px-3 text-right font-mono tabular-nums ${
                        row.zScore >= 1.5 ? 'text-amber-400 font-medium' : 'text-slate-300'
                      }`}
                    >
                      {row.zScore.toFixed(2)}
                    </td>
                    <td className="py-2 px-4 text-right font-mono tabular-nums text-slate-300">
                      {row.confidenceScore > 0 ? `${row.confidenceScore}%` : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
