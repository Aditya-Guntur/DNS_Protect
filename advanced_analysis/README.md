# Advanced Analysis Module

## File Interactions Within Folder
```
┌─────────────────────┐    ┌─────────────────────┐
│ semantic_analyzer.py│───▶│ stealth_crawler.py  │
└─────────────────────┘    └─────────────────────┘
         │                          │
         ▼                          ▼
┌─────────────────────┐    ┌─────────────────────┐
│   ┌─models─────┐    │    │ ../intelligence.py  │
│   │website_    │    │    │  (combined system)  │
│   │profile.py  │    │    │                     │
│   └────────────┘    │    └─────────────────────┘
└─────────────────────┘
```

## Individual File External Interactions

### semantic_analyzer.py
```
┌─────────────────────┐
│ semantic_analyzer.py│
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│   ┌─models─────┐    │
│   │website_    │    │
│   │profile.py  │    │
│   └────────────┘    │
└─────────────────────┘
```

### stealth_crawler.py
```
┌─────────────────────┐
│ stealth_crawler.py  │
│ (with automatic     │
│ history saving)     │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│   ┌─utils──────┐    │
│   │stealth_    │    │
│   │tools.py    │    │
│   └────────────┘    │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│   ┌─utils──────┐    │
│   │web_utils.py│    │
│   └────────────┘    │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│ ../intelligence.py  │
│ (combined analysis) │
└─────────────────────┘
```

## Purpose
- **semantic_analyzer.py**: NLP analysis of domain names for suspicious patterns
- **stealth_crawler.py**: Secret web crawling with anti-detection measures and automatic website history saving

## Integration
All analysis results are fed into the main **intelligence.py** system which combines semantic analysis, web crawling data, and website history into a comprehensive security assessment.