# Models Module

## File Interactions Within Folder
```
┌─────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│  dns_query.py   │───▶│ suspicious_domain.py│───▶│ website_profile.py  │
└─────────────────┘    └─────────────────────┘    └─────────────────────┘
```

## Individual File External Interactions

### dns_query.py
```
┌─────────────────┐
│  dns_query.py   │
└─────────────────┘
         │
         ▼
┌─────────────────────┐
│   ┌─parsers────┐    │
│   │pcap_parser │    │
│   │.py         │    │
│   └────────────┘    │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│   ┌─parsers────┐    │
│   │dns_        │    │
│   │extractor.py│    │
│   └────────────┘    │
└─────────────────────┘
```

### suspicious_domain.py
```
┌─────────────────────┐
│ suspicious_domain.py│
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│   ┌─filters────┐    │
│   │statistical_│    │
│   │filter.py   │    │
│   └────────────┘    │
└─────────────────────┘
```

### website_profile.py
```
┌─────────────────────┐
│ website_profile.py  │
└─────────────────────┘
         │
         ▼
┌─────────────────────────┐
│   ┌─advanced_analysis─┐ │
│   │semantic_analyzer.py│ │
│   └────────────────────┘ │
└─────────────────────────┘
         │
         ▼
┌─────────────────────────┐
│   ┌─advanced_analysis─┐ │
│   │stealth_crawler.py  │ │
│   └────────────────────┘ │
└─────────────────────────┘
         │
         ▼
┌─────────────────────┐
│   intelligence.py   │
│  (main classifier)  │
└─────────────────────┘
```

## Purpose
- **dns_query.py**: Core DNS query data structure with timestamp, domain, source IP
- **suspicious_domain.py**: Enhanced domain object with statistical analysis results
- **website_profile.py**: Complete website analysis profile for intelligence system