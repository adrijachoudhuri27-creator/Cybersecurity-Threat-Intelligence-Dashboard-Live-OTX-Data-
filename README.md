# Cloud-Based Cybersecurity Threat Intelligence Framework

An aggregated threat intelligence workbench built with React, TypeScript, Express, and SQLite (`better-sqlite3`) for collecting live OSINT feeds, normalizing and deduplicating indicators of compromise (IOCs), computing Median/MAD robust recurrence Z-scores, and triaging recurring attack patterns.

> **Architecture Note:** All live feed ingestion, normalization, deduplication, and analytics run in TypeScript/Node.js + React. Inspectable Python scripts in the **OSINT & Normalization** tab (`otx_collector.py`, `selenium_scraper.py`, `pandas_numpy_analyzer.py`, `streamlit_dashboard.py`) are optional standalone reference templates only and are not executed by this web application.

## Key Capabilities

- **Live OSINT Feed Collectors (`server/ingest.ts`)**
  - **AlienVault OTX REST API**: Fetches subscribed pulses when `OTX_API_KEY` is configured (`https://otx.alienvault.com/api/v1/pulses/subscribed`). Falls back to `/api/v1/search/pulses` when unset (note: public unauthenticated search currently returns `HTTP 403 Forbidden`). Parses `attack_ids` objects and strings cleanly via `extractOtxAttackIds()` and derives severity, confidence, and MITRE ATT&CK tactics from pulse metadata with word-boundary matching.
  - **CISA Known Exploited Vulnerabilities (KEV)**: Sorts explicitly by `dateAdded` descending to ingest the latest 10 exploited CVEs using constant pulse ID `kev-live`, deriving ransomware impact and tactics from catalog fields.
  - **Abuse.ch Feodo Tracker**: Sorts entries `online`-first and by recency (`last_online`/`first_seen` descending) to ingest the top 10 recommended botnet C2 IPv4 indicators using constant pulse ID `feodo-live`.
  - **Manual Batch Consolidation**: Parses analyst-pasted IOC batches (`Manual Batch` source) with token-by-token audit logs and labels unassigned fields explicitly as `Unclassified` (`confidence: 0`).
- **Normalization & Blocklist Filtering (`server/normalize.ts`)**
  - Strips optional `:port` suffixes on IPv4 tokens and refangs obfuscated indicators (`[.]`, `(dot)`, `hxxp://`, `hxxps://`).
  - Uses Node's `net.BlockList` to reject RFC1918 private ranges, loopback, link-local, CGNAT (`100.64.0.0/10`), documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), and multicast/reserved addresses.
  - Canonicalizes CVEs (uppercase), SHA-256 digests (lowercase), FQDNs, and URLs.
- **Distinct Sighting Deduplication & Robust Z-Scores (`server/db.ts`)**
  - Persists normalized IOCs, distinct sightings (`UNIQUE(normalized_indicator, source, pulse_id)`), and daily observation records (`indicator_days`) in SQLite.
  - Recurrence is defined strictly as distinct sightings so repeated syncs (including across days for `kev-live` and `feodo-live`) never inflate `recurrence_count` or `z_score`, while `days_observed` tracks multi-day persistence separately.
  - Computes **Median & MAD (Median Absolute Deviation) Robust Z-Scores** (`0.6745 * (x - median) / MAD`) to surface **High-Recurrence Outliers** (`|z| >= 1.5`).
- **Interactive Analytical Views (`src/components/`)**
  - **Executive Overview**: Interactive cross-filtering across feed sources, attack pattern clusters, IOC types, and MITRE ATT&CK tactics, plus 7-day sighting timelines (`seen_at`) and CSV export.
  - **Parameter Explorer**: Parameter controls (collection window, minimum distinct sightings, robust Z-score cutoff, source/type filters) with a recurrence outlier scatter plot and indicator preview table.
  - **OSINT & Normalization**: `Manual Batch` consolidation workbench with token-by-token audit logs, real pipeline execution history, and optional standalone Python reference templates.
  - **IOC Ledger**: High-density searchable indicator ledger with analyst triage status workflow (`Active`, `Investigating`, `Mitigated`).

## Results

Measured from a single live execution of `syncLiveOsintFeeds()` against a seeded SQLite database (`10` sample fixtures) with `OTX_API_KEY` unset:

| Metric / Feed | Observed Result | Notes |
| --- | --- | --- |
| **CISA KEV** | `10` indicators ingested | Succeeded (latest 10 CVEs sorted by `dateAdded` descending) |
| **Abuse.ch Feodo Tracker** | `1` indicator ingested | Succeeded (1 active entry in `ipblocklist_recommended.json`) |
| **AlienVault OTX** | `0` indicators ingested | Returned `HTTP 403 Forbidden` without `OTX_API_KEY` |
| **Pipeline Run Status** | `Partial` | Completed in `1,044 ms` |
| **Raw Tokens Evaluated** | `11` | `10` CISA KEV + `1` Abuse.ch Feodo |
| **Normalized IOCs Persisted** | `11` | `0` malformed dropped · `0` duplicates removed |
| **Total Indicators After Sync** | `21` | `10` Sample fixtures + `11` Live OSINT indicators |
| **High-Recurrence Outliers (`z >= 1.5`)** | `3` | Computed across the combined `21`-indicator distribution |

## Sample vs. Live Data Provenance

On an empty database, `seedSampleIntel()` loads clearly labeled **Sample** fixtures (`is_sample = 1`) so the UI is inspectable without inventing fake pipeline execution history or fabricated timelines. Triggering **Sync Live Feeds** pulls real OSINT indicators (`is_sample = 0`) and records genuine `pipeline_runs` metrics.

## Project Structure

```text
├── server.ts                  # Express (with trust proxy) + Vite / static production entry point
├── server/
│   ├── db.ts                  # Injectable createDatabase(path), sightings, indicator_days, sample fixtures
│   ├── ingest.ts              # Live OTX, CISA KEV, Feodo collectors & Manual Batch ingest
│   ├── normalize.ts           # Pure IOC parser, net.BlockList, Median/MAD Z-scores, ATT&CK mapping
│   └── routes.ts              # REST API, sliding-window rate limiter, READ_ONLY_DEMO & ADMIN_TOKEN guards
├── src/
│   ├── types.ts               # Shared TypeScript interfaces
│   └── components/
│       ├── Dashboard.tsx
│       ├── PowerBIOverview.tsx
│       ├── StreamlitExplorer.tsx
│       ├── PipelineWorkspace.tsx
│       └── IndicatorLedger.tsx
└── tests/
    ├── db.test.ts             # In-memory SQLite tests for sighting idempotency & days_observed
    └── normalize.test.ts      # Unit tests for normalization, net.BlockList, OTX attack_ids & Z-scores
```

## Setup & Environment Variables

Install dependencies and start the development server:

```bash
npm install
npm run dev
```

Configure optional variables in `.env` (see `.env.example`):

| Variable | Purpose | Default |
| --- | --- | --- |
| `OTX_API_KEY` | AlienVault OTX REST API key (`HTTP 403` on public search without key) | Unset |
| `READ_ONLY_DEMO` | Set `"true"` on public demos to disable mutating `POST`/`PATCH` routes | `"false"` |
| `ADMIN_TOKEN` | Optional Bearer token required for sync, ingest, and triage routes | Unset |

## Testing & Verification

```bash
# Run unit tests (Node native test runner)
npm test

# Type-check and build production bundle
npm run lint
npm run build
```
