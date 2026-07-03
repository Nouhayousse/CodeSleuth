# CodeSleuth 🔍

> **Multi-agent GitHub repository auditor powered by Google ADK and Gemini.**  
> Automatically scans, analyzes, and audits any public GitHub repository for code quality issues, security vulnerabilities, and technical debt — and delivers a structured Markdown report with an actionable remediation plan.

---

## Overview

CodeSleuth is a **4-agent sequential pipeline** built with the [Google Agent Development Kit (ADK)](https://google.github.io/adk-docs/). Given a public GitHub repository, it:

1. **Scans** the full repository structure and dependencies in a single API call.
2. **Analyzes** the most important Python source files for code smells (complexity, duplication, documentation, TODOs).
3. **Audits security**: checks all PyPI dependencies against [OSV.dev](https://osv.dev/) for known CVEs, and scans source files with regex patterns to detect accidentally exposed secrets.
4. **Reports**: synthesizes all findings into a scored, prioritized technical debt report in Markdown.

```
User Prompt: "Audit google/adk-python"
        │
        ▼
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│  Scanner Agent   │ -> │  Analyst Agent   │ -> │  Security Agent  │ -> │  Reporter Agent  │
│                  │    │                  │    │                  │    │                  │
│ scan_github_     │    │ analyze_repo_    │    │ analyze_repo_    │    │ (LLM-only)       │
│ repository       │    │ files            │    │ security         │    │ Synthesizes all  │
│ (1 MCP call)     │    │ (1 MCP call)     │    │ (1 MCP call)     │    │ into a report    │
└──────────────────┘    └──────────────────┘    └──────────────────┘    └──────────────────┘
```

**Total LLM calls**: 4 (one per agent) — designed to stay within free-tier quotas.

---

## Architecture

### Agents

| Agent | Role | Tools |
|-------|------|-------|
| `scanner_agent` | Collects repo structure, dependencies, and commit activity | `scan_github_repository` (MCP) |
| `analyst_agent` | Analyzes Python files for code smells | `analyze_repo_files` (MCP) |
| `security_agent` | Checks OSV.dev CVEs + scans for secrets | `analyze_repo_security` (MCP) |
| `reporter_agent` | Synthesizes all outputs into a scored Markdown report | None (pure LLM) |

### MCP Tools (via `github_mcp_server.py`)

| Tool | Description |
|------|-------------|
| `scan_github_repository` | Full repo structure (Git Trees API), dependency file, commit activity |
| `analyze_repo_files` | Downloads & runs code metrics on a list of Python files |
| `analyze_repo_security` | OSV.dev CVE check + regex secret detection |
| `get_file_content` | Fetches a single file's content |
| `get_dependency_file` | Finds and returns the project's dependency file |
| `get_commit_activity` | Returns last commit date and message |

### Code Analysis Heuristics (deterministic, no LLM)

| Metric | Tool | Severity |
|--------|------|----------|
| Cyclomatic complexity > 10 | `radon` | MAJEUR |
| Cyclomatic complexity > 15 | `radon` | CRITIQUE |
| Function length > 50 lines | AST parser | MAJEUR |
| Code duplication > 60% | Line-set intersection | MAJEUR |
| Code duplication > 80% | Line-set intersection | CRITIQUE |
| Documentation ratio < 30% | AST docstring check | MINEUR |
| TODO/FIXME count > 5 | String scan | MINEUR |

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
│   ├── agent.py                 # Root SequentialAgent orchestrator
│   ├── config.py                # Shared thresholds and constants
│   ├── agents/
│   │   ├── scanner_agent.py     # Scanner Agent (GitHub structure)
│   │   ├── analyst_agent.py     # Analyst Agent (code smells)
│   │   ├── security_agent.py    # Security Agent (CVEs + secrets)
│   │   └── reporter_agent.py    # Reporter Agent (Markdown report)
│   ├── mcp/
│   │   └── github_mcp_server.py # FastMCP server exposing all tools
│   └── tools/
│       ├── code_analysis.py     # Deterministic code metrics (AST + radon)
│       └── osv_tools.py         # OSV.dev + regex secret detection
├── tests/
│   ├── test_code_analysis.py    # Unit tests for code metrics
│   ├── test_osv_tools.py        # Unit tests for security tools
│   └── test_github_tools.py     # Unit tests for GitHub tool logic
├── deployment/
│   └── cloudrun.yaml            # Google Cloud Run deployment manifest
├── .env.example                 # Environment variable template
├── Dockerfile                   # Multi-stage production Dockerfile
├── pyproject.toml               # Project metadata and dependencies
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
