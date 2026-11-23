import React from 'react';
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import { Download, RotateCcw, ArrowUpRight } from 'lucide-react';
import type { DashboardResponse, FeedSourceType, ThreatIndicator } from '../types';

interface PowerBIOverviewProps {
  data: DashboardResponse | null;
  loading: boolean;
  selectedCategory: string;
  selectedType: string;
  selectedSource: string;
  onSelectCategory: (category: string) => void;
  onSelectType: (type: string) => void;
  onSelectSource: (source: string) => void;
  onResetCrossFilters: () => void;
  onInspectIndicator: (indicator: ThreatIndicator) => void;
  onExportCsv: () => void;
}

const SOURCE_OPTIONS: Array<'' | FeedSourceType> = [
  '',
  'AlienVault OTX',
  'Selenium Web Scraper',
  'CISA KEV',
  'Abuse.ch Feodo',
];

const SEVERITY_TEXT_CLASS: Record<string, string> = {
  Critical: 'text-red-400',
  High: 'text-amber-400',
  Medium: 'text-sky-400',
  Low: 'text-slate-400',
};

const STATUS_TEXT_CLASS: Record<string, string> = {
  Active: 'text-red-400',
  Investigating: 'text-amber-400',
  Mitigated: 'text-emerald-400',
};

export default function PowerBIOverview({
  data,
  loading,
  selectedCategory,
  selectedType,
  selectedSource,
  onSelectCategory,
  onSelectType,
  onSelectSource,
  onResetCrossFilters,
  onInspectIndicator,
  onExportCsv,
}: PowerBIOverviewProps) {
  const hasActiveFilter = Boolean(selectedCategory || selectedType || selectedSource);

  if (loading && !data) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 border border-slate-800 rounded-lg bg-[#111827] divide-y sm:divide-y-0 sm:divide-x divide-slate-800">
          {[0, 1, 2, 3].map((idx) => (
            <div key={idx} className="p-5 space-y-2 animate-pulse">
              <div className="h-3 w-28 bg-slate-800 rounded" />
              <div className="h-7 w-20 bg-slate-800 rounded" />
              <div className="h-3 w-36 bg-slate-800 rounded" />
            </div>
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-7 h-80 bg-[#111827] border border-slate-800 rounded-lg animate-pulse" />
          <div className="lg:col-span-5 h-80 bg-[#111827] border border-slate-800 rounded-lg animate-pulse" />
        </div>
      </div>
    );
  }

  if (!data) return null;

  const { kpis, timeline, byCategory, byType, byTactic, topPatterns } = data;

  return (
    <div className="space-y-6">
      {/* Power BI Interactive Slicer Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium text-slate-400 mr-1">Feed Slice:</span>
          <div className="inline-flex flex-wrap items-center gap-1 p-1 bg-[#111827] border border-slate-800 rounded-lg">
            {SOURCE_OPTIONS.map((src) => {
              const active = selectedSource === src;
              return (
                <button
                  key={src || 'all'}
                  type="button"
                  onClick={() => onSelectSource(src)}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                    active
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/60'
                  }`}
                >
                  {src || 'All Sources'}
                </button>
              );
            })}
          </div>
        </div>

        <div className="flex items-center gap-3">
          {hasActiveFilter && (
            <button
              type="button"
              onClick={onResetCrossFilters}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-[#111827] hover:bg-slate-800 border border-slate-700 rounded-lg transition-colors whitespace-nowrap shrink-0"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Clear Cross-Filters
            </button>
          )}
          <button
            type="button"
            onClick={onExportCsv}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-[#111827] hover:bg-slate-800 border border-slate-700 rounded-lg transition-colors whitespace-nowrap shrink-0"
          >
            <Download className="w-3.5 h-3.5" />
            Export Power BI CSV
          </button>
        </div>
      </div>

      {/* Active Cross-Filter Summary Line */}
      {hasActiveFilter && (
        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
          <span className="text-slate-300 font-medium">Active cross-filter:</span>
          {selectedSource && <span>Source: {selectedSource}</span>}
          {selectedSource && (selectedCategory || selectedType) && <span aria-hidden="true">·</span>}
          {selectedCategory && <span>Attack Pattern: {selectedCategory}</span>}
          {selectedCategory && selectedType && <span aria-hidden="true">·</span>}
          {selectedType && <span>IOC Type: {selectedType}</span>}
        </div>
      )}

      {/* 4-Column Executive KPI Strip (Single surface, hairline dividers, zero nested cards) */}
      <section className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 bg-[#111827] border border-slate-800 rounded-lg divide-y sm:divide-y-0 sm:divide-x divide-slate-800">
        <div className="p-5">
          <p className="text-xs text-slate-400 font-medium">Consolidated Indicators</p>
          <p className="mt-2 text-3xl font-semibold tracking-tight text-slate-50 font-mono tabular-nums">
            {kpis.totalIndicators}
          </p>
          <p className="mt-1.5 text-xs text-slate-400 tabular-nums">
            {kpis.deduplicationRate}% duplicate noise removed across {kpis.pulseCount} pulses
          </p>
        </div>

        <div className="p-5">
          <p className="text-xs text-slate-400 font-medium">Recurring Attack Patterns</p>
          <p className="mt-2 text-3xl font-semibold tracking-tight text-slate-50 font-mono tabular-nums">
            {kpis.recurringPatterns}
          </p>
          <p className="mt-1.5 text-xs text-slate-400 tabular-nums">
            Mean {kpis.meanRecurrence} sightings · Std Dev {kpis.stdRecurrence}
          </p>
        </div>

        <div className="p-5">
          <p className="text-xs text-slate-400 font-medium">Statistical Anomaly Spikes</p>
          <p className="mt-2 text-3xl font-semibold tracking-tight text-amber-400 font-mono tabular-nums">
            {kpis.anomalySpikes}
          </p>
          <p className="mt-1.5 text-xs text-slate-400 tabular-nums">
            Threshold Z ≥ 1.5σ · Peak Z = {kpis.maxZScore.toFixed(2)}σ
          </p>
        </div>

        <div className="p-5">
          <p className="text-xs text-slate-400 font-medium">Unmitigated Critical Threats</p>
          <p className="mt-2 text-3xl font-semibold tracking-tight text-red-400 font-mono tabular-nums">
            {kpis.activeCritical}
          </p>
          <p className="mt-1.5 text-xs text-slate-400 tabular-nums">
            Last sync {new Date(kpis.lastSyncAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
          </p>
        </div>
      </section>

      {/* Primary Visualization Row */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Ingestion & Consolidation Volume Timeline */}
        <div className="lg:col-span-7 bg-[#111827] border border-slate-800 rounded-lg p-5">
          <div className="flex flex-wrap items-baseline justify-between gap-2 mb-5">
            <div>
              <h2 className="text-base font-semibold text-slate-100">
                Ingestion vs. Consolidated Sightings
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                7-day raw OSINT collection compared with Pandas deduplicated volume
              </p>
            </div>
            <div className="flex items-center gap-4 text-xs text-slate-400">
              <span className="inline-flex items-center gap-1.5">
                <span className="w-2.5 h-0.5 bg-slate-500 inline-block" /> Raw Ingested
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="w-2.5 h-0.5 bg-blue-500 inline-block" /> Cleaned Sightings
              </span>
            </div>
          </div>

          <div className="h-[290px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeline} margin={{ top: 8, right: 12, left: -16, bottom: 0 }}>
                <defs>
                  <linearGradient id="cleanedGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.28} />
                    <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
                <XAxis
                  dataKey="date"
                  stroke="#94A3B8"
                  fontSize={11}
                  tickLine={false}
                  axisLine={false}
                />
                <YAxis
                  stroke="#94A3B8"
                  fontSize={11}
                  tickLine={false}
                  axisLine={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0F172A',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    fontSize: '12px',
                    color: '#F8FAFC',
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="rawIngested"
                  name="Raw Ingested"
                  stroke="#64748B"
                  strokeWidth={1.5}
                  strokeDasharray="4 4"
                  fill="none"
                />
                <Area
                  type="monotone"
                  dataKey="cleanedStored"
                  name="Cleaned Sightings"
                  stroke="#3B82F6"
                  strokeWidth={2}
                  fill="url(#cleanedGrad)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Interactive Cross-Filter Chart: Recurring Attack Patterns */}
        <div className="lg:col-span-5 bg-[#111827] border border-slate-800 rounded-lg p-5 flex flex-col">
          <div className="mb-5">
            <h2 className="text-base font-semibold text-slate-100">
              Attack Pattern Clusters
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Click any category bar to cross-filter the dashboard
            </p>
          </div>

          {byCategory.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center text-center py-12">
              <p className="text-sm text-slate-300">No attack categories match the current slice.</p>
              <button
                type="button"
                onClick={onResetCrossFilters}
                className="mt-3 px-3 py-1.5 text-xs font-medium text-blue-400 hover:text-blue-300 border border-slate-700 rounded-md"
              >
                Reset Filters
              </button>
            </div>
          ) : (
            <div className="h-[290px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={byCategory}
                  layout="vertical"
                  margin={{ top: 4, right: 20, left: 8, bottom: 0 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" horizontal={false} />
                  <XAxis type="number" stroke="#94A3B8" fontSize={11} tickLine={false} axisLine={false} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    width={142}
                    stroke="#CBD5E1"
                    fontSize={11}
                    tickLine={false}
                    axisLine={false}
                  />
                  <Tooltip
                    cursor={{ fill: 'rgba(59, 130, 246, 0.08)' }}
                    contentStyle={{
                      backgroundColor: '#0F172A',
                      border: '1px solid #334155',
                      borderRadius: '8px',
                      fontSize: '12px',
                      color: '#F8FAFC',
                    }}
                  />
                  <Bar
                    dataKey="count"
                    name="Indicators"
                    radius={[0, 4, 4, 0]}
                    cursor="pointer"
                    onClick={(entry) => {
                      if (entry?.name) {
                        onSelectCategory(selectedCategory === entry.name ? '' : String(entry.name));
                      }
                    }}
                  >
                    {byCategory.map((entry) => {
                      const isSelected = !selectedCategory || selectedCategory === entry.name;
                      return (
                        <Cell
                          key={entry.name}
                          fill={isSelected ? '#3B82F6' : '#1E293B'}
                        />
                      );
                    })}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </section>

      {/* Secondary Row: IOC Type Slice + MITRE ATT&CK Tactics + Top Recurring Patterns */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* IOC Type & MITRE ATT&CK Breakdown */}
        <div className="lg:col-span-4 bg-[#111827] border border-slate-800 rounded-lg divide-y divide-slate-800">
          <div className="p-5">
            <h3 className="text-sm font-semibold text-slate-100">Indicator Type Breakdown</h3>
            <p className="text-xs text-slate-400 mt-0.5">Select a type to slice all visuals</p>
            <div className="mt-4 space-y-2">
              {byType.map((item) => {
                const active = selectedType === item.name;
                return (
                  <button
                    key={item.name}
                    type="button"
                    onClick={() => onSelectType(active ? '' : item.name)}
                    className={`w-full flex items-center justify-between px-3 py-2 rounded-md text-xs transition-colors border ${
                      active
                        ? 'bg-blue-600/15 border-blue-500/60 text-slate-50'
                        : 'bg-transparent border-slate-800/80 text-slate-300 hover:bg-slate-800/50'
                    }`}
                  >
                    <span className="font-mono font-medium">{item.name}</span>
                    <span className="font-mono tabular-nums text-slate-400">
                      {item.count} IOCs · avg {item.avgZScore ?? 0}σ
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="p-5">
            <h3 className="text-sm font-semibold text-slate-100">MITRE ATT&CK Tactics</h3>
            <div className="mt-3 space-y-2.5">
              {byTactic.slice(0, 5).map((tactic) => {
                const maxCount = byTactic[0]?.count || 1;
                const pct = Math.round((tactic.count / maxCount) * 100);
                return (
                  <div key={tactic.name} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-slate-300">{tactic.name}</span>
                      <span className="font-mono tabular-nums text-slate-400">{tactic.count}</span>
                    </div>
                    <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                      <div className="h-full bg-blue-500" style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* High-Density Recurring Attack Patterns Table */}
        <div className="lg:col-span-8 bg-[#111827] border border-slate-800 rounded-lg overflow-hidden flex flex-col">
          <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between gap-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-100">
                Top Recurring Threat Indicators
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Ranked by NumPy recurrence Z-score across consolidated OSINT and web sources
              </p>
            </div>
            <span className="text-xs font-mono tabular-nums text-slate-400 whitespace-nowrap">
              Showing {topPatterns.length} of {kpis.totalIndicators}
            </span>
          </div>

          {topPatterns.length === 0 ? (
            <div className="p-10 text-center">
              <p className="text-sm text-slate-300">No recurring indicators match the active cross-filters.</p>
              <button
                type="button"
                onClick={onResetCrossFilters}
                className="mt-3 px-4 py-2 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 rounded-lg transition-colors"
              >
                Reset Cross-Filters
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-xs font-medium text-slate-400">
                    <th className="py-3 px-4">Indicator</th>
                    <th className="py-3 px-3">Type</th>
                    <th className="py-3 px-3">Pattern / Tactic</th>
                    <th className="py-3 px-3">Severity</th>
                    <th className="py-3 px-3 text-right">Sightings</th>
                    <th className="py-3 px-3 text-right">Z-Score</th>
                    <th className="py-3 px-4 text-right">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80 text-xs">
                  {topPatterns.map((row) => (
                    <tr
                      key={row.id}
                      onClick={() => onInspectIndicator(row)}
                      className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                    >
                      <td className="py-2.5 px-4 font-mono text-slate-100 max-w-[230px] truncate">
                        <span className="inline-flex items-center gap-1.5">
                          <span className="truncate">{row.indicator}</span>
                          <ArrowUpRight className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                        </span>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-slate-400 whitespace-nowrap">
                        {row.type}
                      </td>
                      <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">
                        {row.category} <span className="text-slate-600">·</span>{' '}
                        <span className="text-slate-400">{row.mitreTactic}</span>
                      </td>
                      <td className={`py-2.5 px-3 font-medium whitespace-nowrap ${SEVERITY_TEXT_CLASS[row.severity]}`}>
                        {row.severity}
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono tabular-nums text-slate-200">
                        {row.recurrenceCount}
                      </td>
                      <td
                        className={`py-2.5 px-3 text-right font-mono tabular-nums font-medium ${
                          row.zScore >= 1.5 ? 'text-amber-400' : 'text-slate-300'
                        }`}
                      >
                        {row.zScore >= 0 ? `+${row.zScore.toFixed(2)}` : row.zScore.toFixed(2)}σ
                      </td>
                      <td className={`py-2.5 px-4 text-right font-medium whitespace-nowrap ${STATUS_TEXT_CLASS[row.status]}`}>
                        {row.status}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
