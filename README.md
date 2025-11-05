# VANGUARD - Bug Bounty Automation Scanner

[![Status](https://img.shields.io/badge/Status-Week%201%20Prototype-yellow)](https://github.com)
[![Python](https://img.shields.io/badge/Python-3.11+-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

> Intelligent web vulnerability scanner that mimics human behavior to avoid WAF/IDS detection

⚠️ **Current Status**: Week 1 Prototype - Crawler Only

---

## Quick Start

### Installation

```bash
# Clone repository
git clone <repository-url>
cd vanguard

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install chromium
```

### Usage

```bash
# Basic scan
python main.py scan --target https://example.com

# Stealth mode scan
python main.py scan --target https://example.com --mode stealth

# Custom depth and URL limits
python main.py scan --target https://example.com --max-depth 5 --max-urls 1000

# Show version
python main.py version
```

---

## Week 1 Deliverables ✅

### Implemented Features

- ✅ **Core Infrastructure**
  - `core/orchestrator.py` - Task queue + state management
  - `core/rate_limiter.py` - Adaptive delay system

- ✅ **Crawler Engine**
  - `crawler/playwright_crawler.py` - Dynamic crawling
  - Network request interception
  - BFS link discovery

- ✅ **Development Tools**
  - Unit tests with pytest
  - .gitignore configuration
  - Requirements.txt

### What Works Now

1. **Crawling**: Discovers URLs and endpoints from target website
2. **Network Interception**: Captures API calls (XHR/Fetch)
3. **Rate Limiting**: Adaptive delays to avoid detection
4. **Scope Management**: Stays within target domain

### Example Output

```
VANGUARD Scanner v1.0.0
⚠ Week 1 Prototype - Crawler Only

Target: https://example.com
Mode: stealth
Max Depth: 3

Initializing crawler...
✓ Crawler initialized

Starting crawl of https://example.com...
✓ Crawl completed!

┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┓
┃ Metric                ┃ Value                 ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━┩
│ URLs Visited          │ 127                   │
│ Endpoints Discovered  │ 89                    │
│ Network Requests      │ 34                    │
└──────────────────────┴───────────────────────┘
```

---

## Project Structure

```
vanguard/
├── main.py                    # CLI entry point
├── requirements.txt           # Python dependencies
├── .gitignore                # Git ignore rules
├── src/vanguard/             # Source code
│   ├── core/                 # Core infrastructure
│   │   ├── orchestrator.py   # Task coordination
│   │   └── rate_limiter.py   # Rate limiting
│   ├── crawler/              # Crawling engine
│   │   └── playwright_crawler.py
│   ├── scanners/             # (Week 2-3)
│   ├── verifier/             # (Week 4)
│   └── stealth/              # (Week 4)
└── tests/                    # Test suite
    └── unit/                 # Unit tests
```

---

## Development Roadmap

### ✅ Week 1: Foundation (COMPLETED)
- Core infrastructure (orchestrator, rate limiter)
- Crawler prototype (Playwright)
- Network interception

### 🔄 Week 2: Crawler Complete + XSS Scanner (NEXT)
- Complete dynamic crawler
- Dalfox + XSStrike integration
- Static crawler (ParamSpider, Waybackurls)

### 📋 Week 3: SSRF + IDOR Scanners
- Interactsh OOB server
- SSRF detection
- IDOR multi-session testing

### 📋 Week 4: Verification + Stealth
- Browser-based POC verification
- UA rotation + fingerprint spoofing

### 📋 Week 5-6: Testing + Deployment
- Integration tests (DVWA, PortSwigger Labs)
- Reporting (JSON, Markdown)
- Docker + CI/CD

---

## Testing

```bash
# Run all tests
pytest tests/unit/ -v

# Run specific test file
pytest tests/unit/test_orchestrator.py -v

# Run with coverage
pytest --cov=src.vanguard tests/unit/

# Test crawler specifically
pytest tests/unit/test_playwright_crawler.py -v
```

### Test Coverage (Week 1)

| Module | Coverage | Status |
|--------|----------|--------|
| orchestrator.py | ~70% | ✅ |
| rate_limiter.py | ~85% | ✅ |
| playwright_crawler.py | ~60% | ✅ |

---

## Architecture Overview

```
[User Input] → [Orchestrator]
                     ↓
            [Task Queue] → [Rate Limiter]
                     ↓
  [Playwright Crawler] (Week 1 ✅)
                     ↓
  [Endpoint Manager] (Week 2)
                     ↓
  [Vulnerability Scanners] (Week 2-3)
    ├── XSS (Dalfox + XSStrike)
    ├── SSRF (Interactsh)
    └── IDOR (Multi-session)
                     ↓
  [Browser Verifier] (Week 4)
                     ↓
  [Reporter] (Week 5)
```

---

## Configuration

### Rate Limiting

Default configuration in `core/rate_limiter.py`:
- Base delay: 3 seconds
- Min delay: 2 seconds
- Max delay: 10 seconds
- Max errors before abort: 10

### Crawler

Default configuration in `crawler/playwright_crawler.py`:
- Max depth: 3
- Max URLs: 500
- Headless: True
- Browser: Chromium

---

## Contributing

### Development Setup

```bash
# Install dev dependencies
pip install -r requirements.txt

# Run code quality checks
black src/ tests/
flake8 src/ tests/
mypy src/

# Run tests
pytest tests/unit/ -v
```

### Code Style

- Follow PEP 8
- Use type hints
- Write docstrings (Google style)
- Async/await for all I/O operations

---

## Security & Compliance

⚠️ **IMPORTANT**: This tool is for **authorized bug bounty testing only**

### Required Before Scanning

1. ✅ Target is in authorized bug bounty scope
2. ✅ VPN is active
3. ✅ Bug bounty headers configured
4. ✅ Rate limits set appropriately

### What's NOT Allowed

- ❌ Scanning unauthorized targets
- ❌ SQL Injection testing (too risky)
- ❌ DoS attacks
- ❌ RCE exploitation

---

## Troubleshooting

### Playwright Installation Issues

```bash
# Reinstall Playwright browsers
playwright install --force chromium

# Install with system dependencies (Linux)
playwright install --with-deps chromium
```

### ImportError

```bash
# Make sure you're in venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Reinstall dependencies
pip install -r requirements.txt
```

### Permission Issues

```bash
# Windows: Run as Administrator
# Linux/Mac: Check file permissions
chmod +x main.py
```

---

## License

MIT License - See LICENSE file for details

---

## Acknowledgments

- Playwright Team - Browser automation
- ProjectDiscovery - Inspiration for tool design
- Bug Bounty Community - Testing methodology

---

**⚠️ Week 1 Status**: Crawler working, vulnerability scanning coming in Week 2!

For detailed documentation, see the full project documentation (excluded from this repository).
