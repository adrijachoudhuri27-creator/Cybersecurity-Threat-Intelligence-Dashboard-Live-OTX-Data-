import React from 'react';
import {
  BarChart3,
  SlidersHorizontal,
  Database,
  Table2,
  RefreshCw,
  Shield,
  Menu,
  X,
} from 'lucide-react';
import type {
  AppConfig,
  DashboardResponse,
  PythonModuleSpec,
  ThreatIndicator,
  ThreatStatus,
} from '../types';
import ExecutiveOverview from './ExecutiveOverview';
import ParameterExplorer from './ParameterExplorer';
import PipelineWorkspace from './PipelineWorkspace';
import IndicatorLedger from './IndicatorLedger';

type WorkspaceTab = 'overview' | 'explorer' | 'pipeline' | 'ledger';

const NAV_ITEMS: Array<{ id: WorkspaceTab; label: string; icon: React.ReactNode }> = [
  { id: 'overview', label: 'Executive Overview', icon: <BarChart3 className="w-4 h-4" /> },
  { id: 'explorer', label: 'Parameter Explorer', icon: <SlidersHorizontal className="w-4 h-4" /> },
  { id: 'pipeline', label: 'OSINT & Normalization', icon: <Database className="w-4 h-4" /> },
  { id: 'ledger', label: 'IOC Ledger', icon: <Table2 className="w-4 h-4" /> },
];

export default function Dashboard() {
  const [activeTab, setActiveTab] = React.useState<WorkspaceTab>('overview');
  const [mobileMenuOpen, setMobileMenuOpen] = React.useState(false);

  const [selectedCategory, setSelectedCategory] = React.useState('');
  const [selectedType, setSelectedType] = React.useState('');
  const [selectedSource, setSelectedSource] = React.useState('');
  const [selectedSeverity, setSelectedSeverity] = React.useState('');
  const [selectedStatus, setSelectedStatus] = React.useState('');
  const [searchQuery, setSearchQuery] = React.useState('');
  const [minRecurrence, setMinRecurrence] = React.useState(1);
  const [zThreshold, setZThreshold] = React.useState(-10);
  const [days, setDays] = React.useState(30);

  const [appConfig, setAppConfig] = React.useState<AppConfig>({
    readOnlyDemo: false,
    authRequired: false,
  });
  const [dashboardData, setDashboardData] = React.useState<DashboardResponse | null>(null);
  const [pythonModules, setPythonModules] = React.useState<PythonModuleSpec[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [syncing, setSyncing] = React.useState(false);
  const [syncNotice, setSyncNotice] = React.useState<string | null>(null);
  const [errorMsg, setErrorMsg] = React.useState<string | null>(null);
  const [inspectedIndicator, setInspectedIndicator] = React.useState<ThreatIndicator | null>(null);

  const fetchDashboard = React.useCallback(async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const params = new URLSearchParams();
      if (selectedCategory) params.set('category', selectedCategory);
      if (selectedType) params.set('iocType', selectedType);
      if (selectedSource) params.set('source', selectedSource);
      if (selectedSeverity) params.set('severity', selectedSeverity);
      if (selectedStatus) params.set('status', selectedStatus);
      if (searchQuery) params.set('search', searchQuery);
      if (minRecurrence > 1) params.set('minRecurrence', String(minRecurrence));
      if (zThreshold > -5) params.set('zThreshold', String(zThreshold));
      params.set('days', String(days));

      const resp = await fetch(`/api/dashboard?${params.toString()}`);
      if (!resp.ok) throw new Error('Failed to load threat intelligence dataset');
      const data = (await resp.json()) as DashboardResponse;
      setDashboardData(data);

      setInspectedIndicator((prev) => {
        if (!prev) return null;
        return data.filteredIndicators.find((i) => i.id === prev.id) || prev;
      });
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Unable to reach backend API');
    } finally {
      setLoading(false);
    }
  }, [
    selectedCategory,
    selectedType,
    selectedSource,
    selectedSeverity,
    selectedStatus,
    searchQuery,
    minRecurrence,
    zThreshold,
    days,
  ]);

  React.useEffect(() => {
    fetchDashboard();
  }, [fetchDashboard]);

  React.useEffect(() => {
    fetch('/api/config')
      .then((r) => (r.ok ? r.json() : null))
      .then((cfg: AppConfig | null) => {
        if (cfg) setAppConfig(cfg);
      })
      .catch((err) => console.error('Failed to load app config:', err));

    fetch('/api/python-modules')
      .then((r) => (r.ok ? r.json() : { modules: [] }))
      .then((res: { modules?: PythonModuleSpec[] }) => {
        if (Array.isArray(res.modules)) setPythonModules(res.modules);
      })
      .catch((err) => console.error('Failed to load python modules:', err));
  }, []);

  const handleSyncLiveFeeds = async () => {
    if (appConfig.readOnlyDemo) return;
    setSyncing(true);
    setErrorMsg(null);
    setSyncNotice(null);
    try {
      const resp = await fetch('/api/pipeline/sync', { method: 'POST' });
      const json = (await resp.json()) as {
        ok?: boolean;
        error?: string;
        feedErrors?: string[];
        run?: {
          sourceName: string;
          normalizedCount: number;
          highRecurrenceOutliers: number;
          status: string;
        };
      };

      if (!resp.ok) {
        throw new Error(json.error || 'OSINT feed sync failed');
      }

      if (json.run) {
        const partialNote =
          json.feedErrors && json.feedErrors.length > 0
            ? ` Partial warnings: ${json.feedErrors.join('; ')}`
            : '';
        setSyncNotice(
          `${json.run.status}: ${json.run.sourceName} — ${json.run.normalizedCount} normalized IOCs · ${json.run.highRecurrenceOutliers} high-recurrence outliers.${partialNote}`
        );
      }
      await fetchDashboard();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Live OSINT sync error');
      await fetchDashboard();
    } finally {
      setSyncing(false);
    }
  };

  const handleUpdateIndicatorStatus = async (id: string, status: ThreatStatus) => {
    const resp = await fetch(`/api/indicators/${encodeURIComponent(id)}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    });
    const body = (await resp.json()) as { error?: string };
    if (!resp.ok) throw new Error(body.error || 'Failed to update status');
    setInspectedIndicator((prev) => (prev && prev.id === id ? { ...prev, status } : prev));
    await fetchDashboard();
  };

  const handleExportCsv = () => {
    window.location.href = '/api/export/csv';
  };

  const resetAllFilters = () => {
    setSelectedCategory('');
    setSelectedType('');
    setSelectedSource('');
    setSelectedSeverity('');
    setSelectedStatus('');
    setSearchQuery('');
    setMinRecurrence(1);
    setZThreshold(-10);
    setDays(30);
  };

  const handleInspectFromChart = (indicator: ThreatIndicator) => {
    setInspectedIndicator(indicator);
    setActiveTab('ledger');
  };

  const activeNavLabel = NAV_ITEMS.find((n) => n.id === activeTab)?.label || 'Executive Overview';

  return (
    <div className="min-h-screen bg-[#0B1120] text-[#F8FAFC] flex">
      <aside className="hidden lg:flex lg:w-[248px] lg:shrink-0 lg:flex-col bg-[#111827] border-r border-slate-800">
        <div className="h-14 px-5 flex items-center gap-2.5 border-b border-slate-800">
          <div className="w-7 h-7 rounded-md bg-blue-600 flex items-center justify-center shrink-0">
            <Shield className="w-4 h-4 text-white" />
          </div>
          <span className="font-semibold text-base tracking-tight text-slate-50 whitespace-nowrap">
            Sentinel Intel
          </span>
        </div>

        <nav aria-label="Workspace navigation" className="flex-1 p-3 space-y-1">
          {NAV_ITEMS.map((item) => {
            const active = activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                  active
                    ? 'bg-blue-600/15 text-blue-400'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50'
                }`}
              >
                {item.icon}
                <span className="truncate">{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-slate-800 space-y-1.5 text-xs text-slate-400">
          <p className="font-medium text-slate-300">OSINT Workbench</p>
          <p className="leading-relaxed">
            AlienVault OTX · CISA KEV · Abuse.ch Feodo · SQLite · CSV Export
          </p>
        </div>
      </aside>

      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div className="fixed inset-0 bg-black/60" onClick={() => setMobileMenuOpen(false)} />
          <aside className="relative w-64 max-w-[80vw] bg-[#111827] border-r border-slate-800 flex flex-col z-10">
            <div className="h-14 px-4 flex items-center justify-between border-b border-slate-800">
              <span className="font-semibold text-base text-slate-50">Sentinel Intel</span>
              <button
                type="button"
                aria-label="Close navigation menu"
                onClick={() => setMobileMenuOpen(false)}
                className="p-2 text-slate-400 hover:text-slate-100"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <nav className="p-3 space-y-1">
              {NAV_ITEMS.map((item) => {
                const active = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => {
                      setActiveTab(item.id);
                      setMobileMenuOpen(false);
                    }}
                    className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors whitespace-nowrap ${
                      active
                        ? 'bg-blue-600/15 text-blue-400'
                        : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50'
                    }`}
                  >
                    {item.icon}
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </nav>
          </aside>
        </div>
      )}

      <div className="flex-1 min-w-0 flex flex-col">
        <header className="h-14 bg-[#0B1120]/95 border-b border-slate-800 px-4 lg:px-8 flex items-center justify-between gap-4 sticky top-0 z-30">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              aria-label="Open navigation menu"
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden p-2 -ml-2 text-slate-400 hover:text-slate-100"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-2 text-sm truncate">
              <span className="text-slate-400 hidden sm:inline">Threat Framework</span>
              <span className="text-slate-600 hidden sm:inline" aria-hidden="true">/</span>
              <h1 className="font-semibold text-slate-100 truncate">{activeNavLabel}</h1>
            </div>
          </div>

          <button
            type="button"
            onClick={handleSyncLiveFeeds}
            disabled={appConfig.readOnlyDemo || syncing}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-lg transition-colors whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${syncing ? 'animate-spin' : ''}`} />
            {appConfig.readOnlyDemo
              ? 'Read-Only Demo'
              : syncing
                ? 'Syncing OSINT Feeds...'
                : 'Sync Live Feeds'}
          </button>
        </header>

        <main className="flex-1 max-w-[1440px] w-full mx-auto p-4 lg:p-8 space-y-6">
          {dashboardData && dashboardData.kpis.liveCount === 0 && (
            <div className="px-4 py-3 bg-[#111827] border border-slate-800 rounded-lg text-xs text-slate-300">
              Showing labeled <span className="font-medium text-slate-100">Sample</span> fixtures only. Click{' '}
              <span className="font-medium text-slate-100">Sync Live Feeds</span> to ingest live AlienVault OTX, CISA KEV, and Abuse.ch Feodo threat data.
            </div>
          )}

          {syncNotice && (
            <div className="flex items-center justify-between gap-4 px-4 py-3 bg-[#111827] border border-slate-700 rounded-lg text-xs text-slate-200">
              <span>{syncNotice}</span>
              <button
                type="button"
                aria-label="Dismiss sync notice"
                onClick={() => setSyncNotice(null)}
                className="text-slate-400 hover:text-slate-100 p-1 shrink-0"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          )}

          {errorMsg && (
            <div className="flex items-center justify-between gap-4 px-4 py-3 bg-red-950/30 border border-red-900/60 rounded-lg text-xs text-red-300">
              <span>{errorMsg}</span>
              <button
                type="button"
                onClick={fetchDashboard}
                className="underline hover:text-red-200 whitespace-nowrap"
              >
                Retry
              </button>
            </div>
          )}

          {activeTab === 'overview' && (
            <ExecutiveOverview
              data={dashboardData}
              loading={loading}
              selectedCategory={selectedCategory}
              selectedType={selectedType}
              selectedSource={selectedSource}
              onSelectCategory={setSelectedCategory}
              onSelectType={setSelectedType}
              onSelectSource={setSelectedSource}
              onResetCrossFilters={resetAllFilters}
              onInspectIndicator={handleInspectFromChart}
              onExportCsv={handleExportCsv}
            />
          )}

          {activeTab === 'explorer' && (
            <ParameterExplorer
              data={dashboardData}
              loading={loading}
              minRecurrence={minRecurrence}
              zThreshold={zThreshold}
              days={days}
              selectedSource={selectedSource}
              selectedType={selectedType}
              onChangeMinRecurrence={setMinRecurrence}
              onChangeZThreshold={setZThreshold}
              onChangeDays={setDays}
              onChangeSource={setSelectedSource}
              onChangeType={setSelectedType}
              onResetParams={resetAllFilters}
              onInspectIndicator={handleInspectFromChart}
            />
          )}

          {activeTab === 'pipeline' && (
            <PipelineWorkspace
              pipelineRuns={dashboardData?.pipelineRuns || []}
              pulses={dashboardData?.pulses || []}
              pythonModules={pythonModules}
              syncing={syncing}
              readOnlyDemo={appConfig.readOnlyDemo}
              onSyncLiveFeeds={handleSyncLiveFeeds}
              onAfterIngest={fetchDashboard}
            />
          )}

          {activeTab === 'ledger' && (
            <IndicatorLedger
              indicators={dashboardData?.filteredIndicators || []}
              loading={loading}
              readOnlyDemo={appConfig.readOnlyDemo}
              searchQuery={searchQuery}
              selectedSeverity={selectedSeverity}
              selectedStatus={selectedStatus}
              onSearchChange={setSearchQuery}
              onSeverityChange={setSelectedSeverity}
              onStatusChange={setSelectedStatus}
              onResetFilters={resetAllFilters}
              onExportCsv={handleExportCsv}
              selectedIndicator={inspectedIndicator}
              onSelectIndicator={setInspectedIndicator}
              onUpdateStatus={handleUpdateIndicatorStatus}
            />
          )}
        </main>
      </div>
    </div>
  );
}
