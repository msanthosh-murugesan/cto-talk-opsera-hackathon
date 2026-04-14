# ⛨ Code Guardian — Opsera Security & Architecture Scanner

> **One scan. Two AI agents. Complete codebase health in under 60 seconds.**

Code Guardian leverages **Opsera's AI-powered Security Agent** and **Architecture Agent** in parallel to deliver a unified report covering vulnerabilities (OWASP Top 10, CVEs, secrets, dependency risks) and structural anti-patterns (god classes, circular deps, complexity hotspots) — with actionable fix suggestions for every issue found.

---

## 🎯 Problem Statement

Developers push code daily without knowing if it's **secure** or **well-architected**. Security scanning and architecture review are typically separate, slow, and disconnected workflows — often skipped under deadline pressure.

**Result:** Vulnerabilities ship to production. Technical debt compounds silently. Teams discover problems only after incidents.

## 💡 Solution

Code Guardian combines **two Opsera AI agents** into a single, fast pipeline:

```
GitHub URL / Local Path
        ↓
  ┌─────────────┐    ┌──────────────────┐
  │   Opsera     │    │     Opsera        │
  │  Security    │    │  Architecture     │     ← Run in parallel
  │   Agent      │    │     Agent         │
  └──────┬──────┘    └───────┬──────────┘
         └──────┬────────────┘
                ↓
     Normalize & Risk Score
                ↓
     Unified JSON Report
                ↓
     Web Dashboard + CLI Output
```

**Input:** A GitHub repository URL or local project path  
**Output:** Combined security + architecture report with severity ratings, risk scores, and fix suggestions  
**Display:** Clean web dashboard with visual charts + terminal-friendly CLI output

## ✨ Key Features

- **Dual-Agent Orchestration** — Security and Architecture agents run concurrently via `asyncio.gather()`, halving total scan time
- **Unified Risk Scoring** — All findings normalized to a consistent schema with severity (Critical/High/Medium/Low) and confidence-weighted 0-100 scores
- **OWASP Top 10 Coverage** — SQL injection, XSS, SSRF, broken access control, cryptographic failures, vulnerable dependencies, security misconfiguration
- **Architecture Anti-Patterns** — God classes, circular dependencies, high cyclomatic complexity, tight coupling, missing abstractions
- **Actionable Fix Suggestions** — Every finding includes specific, copy-pasteable remediation advice
- **Interactive Dashboard** — Score gauges, severity breakdown pie chart, category distribution, issue type analysis, expandable finding cards with code snippets
- **CLI with Color Output** — Full terminal experience with ASCII score bars, severity badges, and structured output
- **Mock Mode** — Demo the tool without Opsera agent installation for evaluation/testing
- **Background Scan Jobs** — Non-blocking API with polling for scan progress

## 🛠️ Tech Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| **Backend** | Python + FastAPI | Native async for concurrent agent calls, Pydantic for type safety, auto-generated OpenAPI docs |
| **Frontend** | HTML/CSS/JS + Chart.js | Zero build step — judges can open `index.html` directly. Also available as React (JSX) |
| **Agents** | Opsera Security Agent + Opsera Architecture Agent | AI-powered code analysis via CLI/API |
| **Data** | JSON files | No database dependency — reports saved as portable JSON |

## 📦 Project Structure

```
opsera-code-guardian/
├── backend/
│   ├── main.py                  # FastAPI server — routes, scan pipeline, background jobs
│   ├── cli.py                   # CLI interface with colored terminal output
│   ├── requirements.txt         # Python dependencies
│   ├── agents/
│   │   ├── security_agent.py    # Opsera Security Agent integration (real + mock)
│   │   └── architecture_agent.py # Opsera Architecture Agent integration (real + mock)
│   ├── parsers/
│   │   └── normalizer.py        # Raw output → unified finding schema + risk scoring
│   ├── models/
│   │   └── report.py            # Pydantic models (Finding, Scores, ScanReport, etc.)
│   └── utils/
│       ├── repo_loader.py       # Git clone / local path validation
│       └── score_calculator.py  # Health score computation (0-100)
├── frontend/
│   └── index.html               # Self-contained dashboard (Chart.js, no build step)
├── reports/                     # Generated scan reports (JSON)
├── README.md
└── .env.example
```

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Git (for scanning GitHub repos)
- Opsera IDE Extension (optional — mock mode works without it)

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/opsera-code-guardian.git
cd opsera-code-guardian

# 2. Install backend dependencies
cd backend
pip install -r requirements.txt

# 3. (Optional) Configure Opsera API access
cp ../.env.example ../.env
# Edit .env with your Opsera API key
```

### Run — CLI Mode

```bash
# Scan with mock data (no Opsera agent needed)
python cli.py ./path/to/project --mock

# Scan a GitHub repo with mock agents
python cli.py https://github.com/user/repo --mock

# Scan with real Opsera agents (requires Opsera IDE extension)
python cli.py https://github.com/user/repo

# Save report to file
python cli.py ./project --mock --output report.json
```

### Run — Web Dashboard

```bash
# Start the API server
cd backend
uvicorn main:app --reload --port 8000

# Open the dashboard
# Option A: Open frontend/index.html directly in your browser
# Option B: Visit http://localhost:8000/docs for the API explorer
```

Then navigate to `frontend/index.html` in your browser, enter a target, and click **Scan Now**.

## 📊 Screenshots

> *Add screenshots of the dashboard here showing:*
> 1. *The scan input form*
> 2. *Score gauges (Security: 38, Architecture: 52, Combined: 44)*
> 3. *Charts — severity pie, category bar, issue types*
> 4. *Expanded finding cards with code snippets and fix suggestions*
> 5. *CLI output with colored severity badges*

## 🔗 How Opsera Agents Are Used

### Opsera Security Agent
- **Invocation**: Via CLI (`opsera-agent security scan --path <repo> --format json`) or REST API
- **Analysis scope**: Source files, dependency manifests (package.json, requirements.txt, pom.xml), config files, environment files
- **Detection**: SQL injection, XSS, SSRF, path traversal, hardcoded secrets, insecure deserialization, weak cryptography, missing authentication, CORS misconfiguration, vulnerable dependencies
- **Output**: Structured JSON with findings including OWASP mapping, CWE IDs, affected files, line numbers, code snippets, and fix suggestions

### Opsera Architecture Agent
- **Invocation**: Via CLI (`opsera-agent architecture review --path <repo> --format json`) or REST API
- **Analysis scope**: Code structure, module dependencies, class/function metrics, configuration patterns
- **Detection**: God classes, circular dependencies, high cyclomatic/cognitive complexity, tight coupling, missing abstractions, no dependency injection, layer violations, configuration sprawl
- **Output**: Structured JSON with findings including severity, affected files, quantitative metrics, and improvement suggestions

### Multi-Agent Orchestration
Both agents are invoked **concurrently** using Python's `asyncio.gather()`, meaning a scan that would take 2 minutes sequentially completes in ~1 minute. The normalizer then merges both outputs into a unified schema with consistent severity ratings and risk scores.

## 🔮 Future Scope

- **CI/CD Integration** — GitHub Actions / GitLab CI plugin to run Code Guardian on every PR
- **Trend Tracking** — Historical score charts showing security/architecture health over time
- **PR Comments** — Auto-comment on pull requests with new findings
- **Custom Rules** — Allow teams to define their own security and architecture rules
- **Multi-Language Support** — Extended analysis for Go, Rust, Java, C# codebases
- **AI-Powered Fix Generation** — Use Opsera agents to not just find issues but generate code fixes
- **Team Dashboard** — Aggregate view across multiple repositories for engineering managers

## 📄 License

MIT — See [LICENSE](LICENSE) for details.

---

**Built for the Opsera × Kissflow CTO Talks AI Hackathon 2026**  
*Powered by Opsera AI Agents*
# cto-talk-opsera-hackathon
