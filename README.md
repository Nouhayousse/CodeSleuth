# CodeSleuth 🔍

> **Multi-agent GitHub repository auditor powered by Google ADK and Gemini.**  
> Automatically scans, analyzes, and audits any public GitHub repository for code quality issues, security vulnerabilities, and technical debt — and delivers a structured Markdown report with an actionable remediation plan.

---

## Overview

CodeSleuth is a **5-agent sequential pipeline** built with the [Google Agent Development Kit (ADK)](https://google.github.io/adk-docs/). Given a public GitHub repository, it:

1. **Scans** the full repository structure and dependencies in a single API call.
2. **Analyzes** the most important Python source files for code quality and **hotspot analysis** (complexity × commit frequency).
3. **Audits security**: CVE checks via [OSV.dev](https://osv.dev/), dangerous API pattern detection (Python + Java), attack surface analysis, OWASP Top 10 mapping, and an explained security score.
4. **Reports**: synthesizes all findings into a scored, prioritized technical debt audit in Markdown.
5. **Validates**: a Critic Agent challenges the report's coherence (LLM-as-judge pattern) before final delivery.

```
User Prompt: "Audit google/adk-python"
        │
        ▼
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│   Scanner   │ → │   Analyst   │ → │  Security   │ → │  Reporter   │ → │   Critic    │
│   Agent     │   │   Agent     │   │   Agent     │   │   Agent     │   │   Agent     │
│             │   │             │   │             │   │             │   │             │
│ scan_github │   │ analyze_    │   │ analyze_    │   │ (LLM-only)  │   │ (LLM-only)  │
│ _repository │   │ file_with_  │   │ repo_       │   │ Synthesizes │   │ Validates   │
│ (1 MCP)     │   │ hotspot     │   │ security_   │   │ into report │   │ coherence   │
│             │   │ (per file)  │   │ deep (1MCP) │   │             │   │             │
└─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
```

**Total LLM calls**: 5 (one per agent) — designed to stay within free-tier quotas.

---

## Architecture

### Agents

| Agent | Role | Tools |
|-------|------|-------|
| `scanner_agent` | Collects repo structure, dependencies, and commit activity | `scan_github_repository` (MCP) |
| `analyst_agent` | Analyzes Python files for code quality + hotspot analysis | `analyze_file_with_hotspot` (MCP) |
| `security_agent` | CVEs, dangerous APIs, attack surface, OWASP mapping, score | `analyze_repo_security_deep` (MCP) |
| `reporter_agent` | Synthesizes all outputs into a scored Markdown report | None (pure LLM) |
| `critic_agent` | Challenges report coherence before final delivery (LLM-as-judge) | None (pure LLM) |

### MCP Tools (via `github_mcp_server.py`)

| Tool | Description |
|------|-------------|
| `scan_github_repository` | Full repo structure (Git Trees API), dependency file, commit activity |
| `analyze_repo_files` | Downloads & runs code metrics on a list of Python files |
| `analyze_file_with_hotspot` | All-in-one: quality metrics + commit churn + hotspot score for one file |
| `get_file_commit_frequency` | Number of commits touching a specific file in the last N days |
| `analyze_repo_security` | OSV.dev CVE check + regex secret detection |
| `analyze_repo_security_deep` | Full security audit: CVEs, dangerous APIs, attack surface, OWASP, score |
| `get_file_content` | Fetches a single file's content |
| `get_dependency_file` | Finds and returns the project's dependency file |
| `get_commit_activity` | Returns last commit date and message |

### Code Analysis Heuristics (deterministic, no LLM)

| Metric | Tool | Severity |
|--------|------|----------|
| Cyclomatic complexity > 10 | `radon` | MAJOR |
| Cyclomatic complexity > 15 | `radon` | CRITICAL |
| Function length > 50 lines | AST parser | MAJOR |
| Code duplication > 60% | Line-set intersection | MAJOR |
| Code duplication > 80% | Line-set intersection | CRITICAL |
| Documentation ratio < 30% | AST docstring check | MINOR |
| TODO/FIXME count > 5 | String scan | MINOR |
| Hotspot Score > 100 (complexity × commits) | Hotspot analysis | CRITICAL HOTSPOT |
| Hotspot Score 41-100 | Hotspot analysis | MODERATE HOTSPOT |
| Hotspot Score ≤ 40 | Hotspot analysis | STABLE |

### Security Detection

| Type | Method | Patterns Covered |
|------|--------|-----------------|
| OSV.dev CVE check | REST API call | All PyPI ecosystem packages |
| AWS Access Key ID | Regex | `AKIA[0-9A-Z]{16}` |
| GitHub Personal Token | Regex | `ghp_[a-zA-Z0-9]{36}` |
| Generic API Key | Regex | `api_key = "..."` patterns |
| Private RSA/EC Key | Regex | `-----BEGIN PRIVATE KEY-----` |
| Google API Key | Regex | `AIza[0-9A-Za-z-_]{35}` |
| Stripe Secret Key | Regex | `sk_live_[...]` |
| Generic Password | Regex | `password = "..."` patterns |

---

## Installation

### Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- A GitHub account (for personal access token)
- A Google AI Studio API key

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/codesleuth.git
cd codesleuth

# 2. Create and activate virtual environment
uv venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS/Linux

# 3. Install dependencies
uv pip install -e .

# 4. Configure environment
cp .env.example .env
# Edit .env with your tokens (see Configuration section)
```

### Configuration

Edit `.env` with your credentials:

```env
# Required: GitHub personal access token (read-only, public_repo scope)
GITHUB_TOKEN=ghp_your_token_here

# Required: Google AI Studio API key
GOOGLE_API_KEY=your_google_api_key_here

# Optional: Override the Gemini model (default: gemini-2.5-flash)
CODESLEUTH_MODEL=gemini-2.5-flash
```

> **Security**: Never commit your `.env` file. It is already in `.gitignore`.
> 
> **GitHub Token Scopes**: Only `public_repo` (read-only) is required. Do not grant write permissions.

---

## Usage

### Web UI (recommended for development)

```bash
# Start the ADK development server
adk web

# Navigate to http://localhost:8000
# Select the "codesleuth" app
# Type your audit request, e.g.:
# "Audit the repository google/adk-python"
```

### Streamlit Web App (Recommended for Demos)

For a beautiful, styled, interactive visual dashboard that displays the agent reasoning sequence and detailed findings, run the Streamlit application:

```bash
# Install dependencies
uv add streamlit

# Launch the app
streamlit run streamlit_app.py
```


### API Server

```bash
# Start the ADK API server
adk api_server codesleuth

# Then POST to the API:
curl -X POST http://localhost:8000/run \
  -H "Content-Type: application/json" \
  -d '{"query": "Audit googleapis/python-bigquery"}'
```

### CLI

```bash
adk run codesleuth
# Enter your prompt: Audit the repo huggingface/transformers
```

---

## Running Tests

```bash
# Run all unit tests (no network required)
pytest -m "not network" -v

# Run with network tests (requires internet + valid GITHUB_TOKEN)
pytest -v

# Run a specific test file
pytest tests/test_code_analysis.py -v
pytest tests/test_osv_tools.py -v
pytest tests/test_github_tools.py -v
```

### Test Coverage

| Test File | What It Tests |
|-----------|--------------|
| `test_code_analysis.py` | Long functions, complexity, documentation ratio, TODOs, duplication |
| `test_osv_tools.py` | Secret detection regex, requirements parsing, OSV.dev mocked/live calls |
| `test_github_tools.py` | Repo structure mapping, file filtering logic, report structure validation |

---

## Deployment

### Docker

```bash
# Build the image
docker build -t codesleuth:latest .

# Run locally
docker run -p 8080:8080 \
  -e GITHUB_TOKEN=your_token \
  -e GOOGLE_API_KEY=your_key \
  codesleuth:latest
```

### Google Cloud Run

```bash
# 1. Authenticate
gcloud auth login
gcloud config set project YOUR_PROJECT_ID

# 2. Build and push to Container Registry
gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/codesleuth

# 3. Create secrets in Secret Manager
echo -n "your_github_token" | gcloud secrets create codesleuth-github-token --data-file=-
echo -n "your_google_api_key" | gcloud secrets create codesleuth-google-api-key --data-file=-

# 4. Deploy using the manifest
# Edit deployment/cloudrun.yaml to replace YOUR_PROJECT_ID
gcloud run services replace deployment/cloudrun.yaml --region=us-central1
```

---

## Project Structure

```
codesleuth/
├── codesleuth/                  # Main package
│   ├── agent.py                 # Root SequentialAgent orchestrator (5 agents)
│   ├── config.py                # Shared thresholds and constants
│   ├── agents/
│   │   ├── scanner_agent.py     # Scanner Agent (GitHub structure)
│   │   ├── analyst_agent.py     # Analyst Agent (code quality & hotspots)
│   │   ├── security_agent.py    # Security Agent (CVEs + secrets + deep audit)
│   │   ├── reporter_agent.py    # Reporter Agent (Markdown report)
│   │   └── critic_agent.py      # Critic Agent (coherence verification)
│   ├── mcp/
│   │   └── github_mcp_server.py # FastMCP server exposing all tools
│   └── tools/
│       ├── code_analysis.py     # Deterministic code metrics (AST + radon)
│       └── osv_tools.py         # OSV.dev + regex secret detection
├── tests/
│   ├── test_code_analysis.py    # Unit tests for code metrics
│   ├── test_osv_tools.py        # Unit tests for security tools
│   ├── test_github_tools.py     # Unit tests for GitHub tool logic
│   └── test_hotspot.py          # Unit tests for hotspot calculation
├── deployment/
│   └── cloudrun.yaml            # Google Cloud Run deployment manifest
├── .env.example                 # Environment variable template
├── Dockerfile                   # Multi-stage production Dockerfile
├── pyproject.toml               # Project metadata and dependencies
├── requirements_streamlit.txt   # Streamlit-specific dependencies
├── streamlit_app.py             # Streamlit front-end entrypoint
└── README.md                    # This file
```

---

## Model Configuration

CodeSleuth supports switching Gemini models at runtime via the `CODESLEUTH_MODEL` environment variable:

| Model | Notes |
|-------|-------|
| `gemini-2.5-flash` | Default. Fast, good quality, reasonable free tier |
| `gemini-2.5-pro` | Higher quality, lower free-tier quota |
| `gemini-2.0-flash` | Even faster, experimental |

```bash
# Switch model for a session
export CODESLEUTH_MODEL=gemini-2.5-pro
adk web
```

---

## Capstone Context

This project was built for the **Kaggle AI Agents Intensive — Vibe Coding Freestyle Track**.

**Key design decisions:**
- **4-agent sequential pipeline** to minimize LLM calls and stay within free-tier rate limits.
- **Deterministic tools** for code metrics (no LLM involved in measurement, only in interpretation).
- **OSV.dev** for CVE checks (free, no auth required, comprehensive PyPI coverage).
- **Regex-based secret detection** for fast, offline secret scanning without external services.
- **MCP protocol** for tool-agent communication, enabling hot-swap of tool implementations.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Run tests before submitting: `pytest -m "not network"`
4. Open a Pull Request

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built with [Google Agent Development Kit (ADK)](https://google.github.io/adk-docs/) and [Gemini](https://ai.google.dev/).*
