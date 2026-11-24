# Cloud-Based Cybersecurity Threat Intelligence Framework

An aggregated threat intelligence workbench for collecting live OSINT feeds, normalizing and deduplicating indicators of compromise (IOCs), computing robust statistical recurrence scores, and exploring recurring attack patterns across Power BI-style and Streamlit-style analytical views.

## Key Capabilities

- **Live OSINT Feed Collectors (`server/ingest.ts`)**
  - **AlienVault OTX REST API**: Fetches subscribed pulses (with `OTX_API_KEY`) or public pulse search results, deriving severity, confidence, and MITRE ATT&CK tactics from pulse `tags`, `attack_ids`, `TLP`, and `adversary` metadata.
  - **CISA Known Exploited Vulnerabilities (KEV)**: Sorts explicitly by `dateAdded` descending to ingest the most recent actively exploited CVEs, deriving ransomware impact and tactics from catalog fields.
  - **Abuse.ch Feodo Tracker**: Pulls active botnet C2 IPv4 indicators (`ip_address` + `port`), deriving severity and confidence from `status` (`online`/`offline`) and `malware` family.
- **Normalization & Blocklist Filtering (`server/normalize.ts`)**
  - Strips optional `:port` suffixes on IPv4 tokens and refangs bracketed/obfuscated indicators (`[.]`, `(dot)`, `hxxp://`, `hxxps://`).
  - Uses Node's `net.BlockList` to reject RFC1918 private ranges, loopback, link-local, CGNAT (`100.64.0.0/10`), documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), and multicast/reserved addresses.
  - Canonicalizes CVEs (uppercase), SHA-256 digests (lowercase), FQDNs, and URLs.
- **Distinct Sighting Deduplication & Robust Z-Scores (`server/db.ts`)**
  - Persists normalized IOCs and individual `(normalized_indicator, source, pulse_id)` sightings in SQLite (`better-sqlite3`).
  - Recurrence is defined strictly as the count of distinct sightings so repeated syncs of the same pulse never inflate scores.
  - Computes **Median & MAD (Median Absolute Deviation) Robust Z-Scores** (`0.6745 * (x - median) / MAD`) to surface **High-Recurrence Outliers** without mean distortion.
- **Power BI & Streamlit Analytical Views (`src/components/`)**
  - **Power BI Overview**: Interactive cross-filtering across feed sources, attack pattern clusters, IOC types, and MITRE ATT&CK tactics, plus 7-day real sighting timelines and CSV export.
  - **Streamlit Explorer**: Interactive parameter controls (collection window, minimum distinct sightings, robust Z-score cutoff, source/type filters) with a recurrence outlier scatter plot and DataFrame preview.
  - **OSINT & Cleaning**: Raw batch consolidation sandbox with token-by-token audit logs, pipeline execution history, and inspectable Python reference scripts (`otx_collector.py`, `selenium_scraper.py`, `pandas_numpy_analyzer.py`, `streamlit_dashboard.py`).
  - **IOC Ledger**: High-density searchable indicator table with analyst triage status workflow (`Active`, `Investigating`, `Mitigated`).

## Sample vs. Live Data Provenance

On an empty database, `seedSampleIntel()` loads clearly labeled **Sample** fixtures (`is_sample = 1`) so the UI is immediately inspectable without inventing fake pipeline execution history or fabricated timelines. Triggering **Sync Live Feeds** pulls real OSINT indicators (`is_sample = 0`) and records genuine `pipeline_runs` metrics.

## Project Structure

```text
├── server.ts                  # Express + Vite / static production entry point
├── server/
│   ├── db.ts                  # SQLite schema, sightings table, sample fixtures
│   ├── ingest.ts              # Live OTX, CISA KEV, Feodo collectors & batch ingest
│   ├── normalize.ts           # Pure IOC parser, net.BlockList, Median/MAD Z-scores
│   └── routes.ts              # REST API, rate limiter, auth/read-only middleware
├── src/
│   ├── types.ts               # Shared TypeScript interfaces
│   └── components/
│       ├── Dashboard.tsx
│       ├── PowerBIOverview.tsx
│       ├── StreamlitExplorer.tsx
│       ├── PipelineWorkspace.tsx
│       └── IndicatorLedger.tsx
└── tests/
    └── normalize.test.ts      # Unit tests for normalization, blocklist & Z-scores
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
| `OTX_API_KEY` | Optional AlienVault OTX API key for subscribed pulses | Public search fallback |
| `READ_ONLY_DEMO` | Set `"true"` to disable mutating `POST`/`PATCH` routes | `"false"` |
| `ADMIN_TOKEN` | Optional Bearer token required for sync, ingest, and triage routes | Unset |

## Testing & Verification

```bash
# Run unit tests (Node native test runner)
npm test

# Type-check and build production bundle
npm run lint
npm run build
```
