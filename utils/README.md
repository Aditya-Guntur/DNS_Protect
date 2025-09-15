# Utils Module

## File Interactions Within Folder
```
┌─────────────────────┐    ┌─────────────────────┐
│   entropy_calc.py   │    │ string_operations.py│
└─────────────────────┘    └─────────────────────┘
         │                          │
         └──────────┬─────────────────┘
                    ▼
┌─────────────────────┐    ┌─────────────────────┐
│  stealth_tools.py   │    │    web_utils.py     │
└─────────────────────┘    └─────────────────────┘
```

## Individual File External Interactions

### entropy_calc.py
```
┌─────────────────────┐
│   entropy_calc.py   │
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

### string_operations.py
```
┌─────────────────────┐
│ string_operations.py│
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│   ┌─filters────┐    │
│   │string_     │    │
│   │analyzer.py │    │
│   └────────────┘    │
└─────────────────────┘
```

### stealth_tools.py
```
┌─────────────────────┐
│  stealth_tools.py   │
└─────────────────────┘
         │
         ▼
┌─────────────────────────┐
│   ┌─advanced_analysis─┐ │
│   │stealth_crawler.py  │ │
│   └────────────────────┘ │
└─────────────────────────┘
```

### web_utils.py
```
┌─────────────────────┐
│    web_utils.py     │
└─────────────────────┘
         │
         ▼
┌─────────────────────────┐
│   ┌─advanced_analysis─┐ │
│   │stealth_crawler.py  │ │
│   │ (with history)     │ │
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
- **entropy_calc.py**: Shannon entropy calculation for domain randomness analysis
- **string_operations.py**: Edit distance, compression, pattern matching utilities
- **stealth_tools.py**: Anti-detection tools for web crawling (IP rotation, delays)
- **web_utils.py**: Web scraping utilities, HTTP requests, HTML parsing