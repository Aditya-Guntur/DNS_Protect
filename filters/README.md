# Filters Module

## File Interactions Within Folder
```
┌─────────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ statistical_filter.py│───▶│ string_analyzer.py│───▶│ set_analyzer.py │
└─────────────────────┘    └─────────────────┘    └─────────────────┘
```

## Individual File External Interactions

### statistical_filter.py
```
┌─────────────────────┐
│ statistical_filter.py│
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│   ┌─utils──────┐    │
│   │entropy_calc│    │
│   │.py         │    │
│   └────────────┘    │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│   ┌─models─────┐    │
│   │suspicious_ │    │
│   │domain.py   │    │
│   └────────────┘    │
└─────────────────────┘
```

### string_analyzer.py
```
┌─────────────────┐
│ string_analyzer.py│
└─────────────────┘
         │
         ▼
┌─────────────────────┐
│   ┌─utils──────┐    │
│   │string_     │    │
│   │operations.py│   │
│   └────────────┘    │
└─────────────────────┘
```

### set_analyzer.py
```
┌─────────────────┐
│ set_analyzer.py │
└─────────────────┘
         │
         ▼
┌─────────────────────────┐
│   ┌─advanced_analysis─┐ │
│   │semantic_analyzer.py│ │
│   └────────────────────┘ │
└─────────────────────────┘
```

## Purpose
- **statistical_filter.py**: Initial filtering based on frequency, entropy, subdomain length
- **string_analyzer.py**: String pattern analysis on suspicious domains
- **set_analyzer.py**: Set-based analysis and cardinality checks