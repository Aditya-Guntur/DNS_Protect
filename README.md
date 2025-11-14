# DNS Covert Communication Detection System

A powerful tool designed to detect covert communications hidden within DNS traffic by analyzing packet captures for abnormal patterns, suspicious domain structures, and potential data exfiltration attempts.

## Overview

DNS covert channels abuse the Domain Name System protocol to secretly transmit data or establish command-and-control communications. This tool identifies such malicious activities by analyzing DNS query patterns in PCAP files through a multi-stage detection pipeline.

## Key Features

- **Multi-stage Filtering Pipeline**: Progressively narrows down suspicious traffic
- **Statistical Anomaly Detection**: Identifies unusual patterns in query frequency and volume
- **Set-based Analysis**: Detects unusual domain generation patterns
- **String Pattern Recognition**: Uncovers encoded data in domain names
- **High-performance Processing**: Capable of analyzing millions of DNS queries efficiently
- **Low False-positive Rate**: Utilizes intelligent filtering and whitelisting mechanisms

## How It Works

The detection system employs a sophisticated 4-stage funnel approach:

1. **Statistical Filtering**
   - Rapidly eliminates normal traffic
   - Analyzes entropy, frequency, and length patterns
   - Identifies outliers in DNS query behavior

2. **Set Analysis**
   - Examines domain uniqueness ratios
   - Detects abnormal cardinality patterns
   - Identifies potential domain generation algorithms (DGAs)

3. **String Operations**
   - Detects sequential patterns in domain names
   - Identifies potential encoding schemes
   - Recognizes template-based domain generation

4. **Deep Investigation (Optional)**
   - Performs semantic analysis of suspicious domains
   - Verifies destinations and network behaviors
   - Provides detailed threat assessment for high-risk findings

## Project Structure

```
DNS_Protect/
├── advanced_analysis/    # Advanced analysis modules
├── filters/              # Traffic filtering components
├── models/               # Data models and schemas
├── parsers/              # PCAP and DNS parsing utilities
└── utils/                # Helper functions and utilities
```

This runs the `intelligence.py` scoring on three mocked domains and prints a report.


## Installation

- Ensure Python 3.9+.
- Install dependencies:

```
pip install -r requirements.txt
```

Optional: set environment variable to enable web checks by default

```
set DNSP_ENABLE_WEB_CHECKS=true
```

You can also provide a `config.json` at the repository root to override defaults.


## CLI Usage

Run the full pipeline on a PCAP and print a JSON report:

```
python cli.py path/to/traffic.pcap --log-level INFO
```

Options:

- `--config path/to/config.json` to load configuration.
- `--out report.json` to write the full JSON report to a file.
- `--enable-web-checks` to perform WHOIS/SSL/accessibility checks.

Example:

```
python cli.py sample.pcap --enable-web-checks --out report.json
```


## Implemented Status

- **Statistical Filtering**: `filters/statistical_filter.py` implemented with frequency, entropy, single-use, TXT-heavy, rapid generation, and cardinality checks.
- **Set Analysis**: `filters/set_analyzer.py` implemented for high cardinality, single-use ratio, long labels, consonant-heavy heuristics.
- **String Operations**: `utils/string_operations.py` implemented; `filters/string_analyzer.py` integrates for sequential and encoding-like patterns.
- **Advanced Analysis**:
  - `advanced_analysis/semantic_analyzer.py`: keyword, homoglyph-like, brand impersonation heuristics.
  - `advanced_analysis/stealth_crawler.py`: wraps `utils/web_utils.WebAnalyzer` to collect accessibility, SSL, WHOIS, DNS, and page metadata into `models/website_profile.py`.
- **Models**: `models/dns_query.py`, `models/suspicious_domain.py`, `models/website_profile.py` and exports in `models/__init__.py`.
- **Intelligence Scoring**: `intelligence.py` now computes a weighted score, classifies (`LEGITIMATE`, `SUSPICIOUS`, `LIKELY_FAKE`, `CONFIRMED_FAKE`, `UNKNOWN`), and generates recommendations with confidence.

Remaining items are enhancements only (ML, threat feeds, real blacklist integrations, full PCAP ingest pipeline orchestration).


## Usage Notes

- To integrate with real traffic:
  - Parse packets to `DNSQuery` using `parsers/dns_extractor.py` or your PCAP pipeline.
  - Feed batched `DNSQuery` into `StatisticalFilter.process_dns_queries()`.
  - For flagged `SuspiciousDomain` items, run `StringAnalyzer` and `SetAnalyzer`.
  - Optionally run `StealthCrawler` and `SemanticAnalyzer`.
  - Collate analyzer outputs and call `Intelligence.analyze_domain()` per domain, or `bulk_analyze()`.
