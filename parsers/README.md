# Parsers Module

## File Interactions Within Folder
```
┌─────────────────┐    ┌─────────────────┐
│  pcap_parser.py │───▶│ dns_extractor.py│
└─────────────────┘    └─────────────────┘
```

## Individual File External Interactions

### pcap_parser.py
```
┌─────────────────┐
│  pcap_parser.py │
└─────────────────┘
         │
         ▼
┌─────────────────────┐
│   ┌─models─────┐    │
│   │dns_query.py│    │
│   └────────────┘    │
└─────────────────────┘
```

### dns_extractor.py
```
┌─────────────────┐
│ dns_extractor.py│
└─────────────────┘
         │
         ▼
┌─────────────────────┐
│   ┌─filters────┐    │
│   │statistical_│    │
│   │filter.py   │    │
│   └────────────┘    │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│   ┌─models─────┐    │
│   │dns_query.py│    │
│   └────────────┘    │
└─────────────────────┘
```

## Purpose
- **pcap_parser.py**: Reads PCAP files and extracts raw packet data
- **dns_extractor.py**: Extracts DNS queries from parsed packets and creates DNSQuery objects