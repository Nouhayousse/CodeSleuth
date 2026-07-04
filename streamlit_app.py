"""
CodeSleuth — Streamlit Front-End
Pilots the 5-agent ADK pipeline (Scanner → Analyst → Security → Reporter → Critic)
directly from Python, without going through `adk web`.

Run from the project root:
    streamlit run streamlit_app.py
"""

# ── Must load .env BEFORE any codesleuth import so that GOOGLE_API_KEY and
#    GITHUB_TOKEN are available when agents and MCP servers are initialised.
import os
from dotenv import load_dotenv
load_dotenv()

import asyncio
import re
import sys
import traceback

import streamlit as st
from google.genai import types
from google.adk.runners import InMemoryRunner


# ─────────────────────────────────────────────────────────────────────────────
# Page configuration (must be the very first Streamlit call)
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CodeSleuth — Audit multi-agents",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ─────────────────────────────────────────────────────────────────────────────
# Inline CSS — minimal, purposeful, demo-ready
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* ── Global ── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* ── Hero banner ── */
.hero-banner {
    background: linear-gradient(135deg, #0f1117 0%, #1a1f35 50%, #0d1b2a 100%);
    border: 1px solid rgba(99, 179, 237, 0.2);
    border-radius: 16px;
    padding: 2.5rem 3rem;
    margin-bottom: 2rem;
    position: relative;
    overflow: hidden;
}
.hero-banner::before {
    content: '';
    position: absolute;
    top: -50%;
    right: -10%;
    width: 400px;
    height: 400px;
    background: radial-gradient(circle, rgba(99, 179, 237, 0.08) 0%, transparent 70%);
    pointer-events: none;
}
.hero-title {
    font-size: 2.4rem;
    font-weight: 700;
    color: #e2e8f0;
    margin: 0 0 0.4rem 0;
    letter-spacing: -0.5px;
}
.hero-subtitle {
    font-size: 1.05rem;
    color: #7fa8c9;
    margin: 0;
    font-weight: 400;
}
.hero-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    background: rgba(99, 179, 237, 0.1);
    border: 1px solid rgba(99, 179, 237, 0.3);
    border-radius: 100px;
    padding: 0.25rem 0.8rem;
    font-size: 0.78rem;
    color: #63b3ed;
    font-weight: 500;
    margin-top: 0.8rem;
}

/* ── Score cards ── */
.score-card {
    background: linear-gradient(135deg, #1a1f35, #141928);
    border-radius: 12px;
    padding: 1.2rem 1.5rem;
    border: 1px solid rgba(255,255,255,0.07);
    text-align: center;
}
.score-label {
    font-size: 0.78rem;
    color: #718096;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 0.4rem;
}
.score-value-critical { font-size: 2.2rem; font-weight: 700; color: #fc8181; }
.score-value-warning  { font-size: 2.2rem; font-weight: 700; color: #f6ad55; }
.score-value-good     { font-size: 2.2rem; font-weight: 700; color: #68d391; }
.score-value-neutral  { font-size: 2.2rem; font-weight: 700; color: #63b3ed; }
.score-sub { font-size: 0.8rem; color: #4a5568; margin-top: 0.2rem; }

/* ── Agent timeline ── */
.agent-row {
    display: flex;
    align-items: flex-start;
    gap: 1rem;
    padding: 0.9rem 0;
    border-bottom: 1px solid rgba(255,255,255,0.05);
}
.agent-row:last-child { border-bottom: none; }
.agent-icon {
    width: 36px;
    height: 36px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1rem;
    flex-shrink: 0;
    margin-top: 2px;
}
.agent-name {
    font-size: 0.88rem;
    font-weight: 600;
    color: #e2e8f0;
    margin-bottom: 0.2rem;
}
.agent-detail {
    font-size: 0.8rem;
    color: #718096;
    font-family: 'JetBrains Mono', monospace;
    line-height: 1.5;
}
.tool-chip {
    display: inline-block;
    background: rgba(99, 179, 237, 0.1);
    border: 1px solid rgba(99, 179, 237, 0.25);
    border-radius: 4px;
    padding: 1px 7px;
    font-size: 0.73rem;
    color: #63b3ed;
    margin: 2px 2px 0 0;
    font-family: 'JetBrains Mono', monospace;
}

/* ── Severity badges ── */
.badge-critical { background:#742a2a; color:#fc8181; border:1px solid #9b2c2c; padding:2px 8px; border-radius:4px; font-size:0.73rem; font-weight:600; }
.badge-high     { background:#7b341e; color:#f6ad55; border:1px solid #9c4221; padding:2px 8px; border-radius:4px; font-size:0.73rem; font-weight:600; }
.badge-medium   { background:#744210; color:#f6e05e; border:1px solid #975a16; padding:2px 8px; border-radius:4px; font-size:0.73rem; font-weight:600; }
.badge-low      { background:#2d3748; color:#a0aec0; border:1px solid #4a5568; padding:2px 8px; border-radius:4px; font-size:0.73rem; font-weight:600; }

/* ── Misc ── */
.stTabs [data-baseweb="tab-list"] { gap: 4px; }
.stTabs [data-baseweb="tab"] { padding: 0.5rem 1.2rem; border-radius: 8px 8px 0 0; }
div[data-testid="stExpander"] { border: 1px solid rgba(255,255,255,0.07); border-radius: 10px; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Runner — created once, cached for the whole Streamlit session
# ─────────────────────────────────────────────────────────────────────────────
@st.cache_resource(show_spinner=False)
def get_runner():
    from codesleuth.agent import root_agent
    return InMemoryRunner(agent=root_agent)


# ─────────────────────────────────────────────────────────────────────────────
# Core async audit function
# ─────────────────────────────────────────────────────────────────────────────
async def _run_audit(owner: str, repo: str, user_id: str = "streamlit_user"):
    runner = get_runner()

    session = await runner.session_service.create_session(
        app_name=runner.app_name,
        user_id=user_id,
    )

    message = types.Content(
        role="user",
        parts=[types.Part(text=f"Audit the repository {owner}/{repo}")],
    )

    final_text_chunks = []
    all_events = []

    async for event in runner.run_async(
        user_id=user_id,
        session_id=session.id,
        new_message=message,
    ):
        all_events.append(event)
        if event.is_final_response() and event.content and event.content.parts:
            for part in event.content.parts:
                if hasattr(part, "text") and part.text:
                    final_text_chunks.append(part.text)

    return "\n".join(final_text_chunks), all_events


def run_audit_sync(owner: str, repo: str) -> tuple[str, list]:
    """Synchronous wrapper for Streamlit (which cannot await directly)."""
    return asyncio.run(_run_audit(owner, repo))


# ─────────────────────────────────────────────────────────────────────────────
# Report parsing helpers
# ─────────────────────────────────────────────────────────────────────────────

def _extract_score(text: str, pattern: str, default: int | None = None) -> int | None:
    """Extract the first integer matching `pattern` from the report text."""
    m = re.search(pattern, text, re.IGNORECASE)
    if m:
        try:
            return int(m.group(1))
        except (IndexError, ValueError):
            pass
    return default


def _score_color(score: int | None) -> str:
    if score is None:
        return "score-value-neutral"
    if score < 40:
        return "score-value-critical"
    if score < 70:
        return "score-value-warning"
    return "score-value-good"


def _split_report_into_sections(text: str) -> dict[str, str]:
    """
    Splits a Markdown report on ## headings into a dict {heading: content}.
    Robust: falls back gracefully if structure differs from expected.
    """
    sections: dict[str, str] = {}
    # Match "## N. Title" or "## Title" at the start of a line
    pattern = re.compile(r'^#{1,3}\s+(.+)$', re.MULTILINE)
    matches = list(pattern.finditer(text))

    if not matches:
        return {"Full Report": text}

    for i, match in enumerate(matches):
        heading = match.group(1).strip()
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        content = text[start:end].strip()
        sections[heading] = content

    return sections


def _find_section(sections: dict, keywords: list[str]) -> str:
    """Return the first section whose key contains any of the given keywords (case-insensitive)."""
    for key, content in sections.items():
        key_lower = key.lower()
        if any(kw in key_lower for kw in keywords):
            return content
    return ""


def _count_pattern(text: str, pattern: str) -> int:
    return len(re.findall(pattern, text, re.IGNORECASE))


# ─────────────────────────────────────────────────────────────────────────────
# Agent timeline helpers
# ─────────────────────────────────────────────────────────────────────────────

AGENT_META = {
    "scanner_agent":  {"emoji": "📡", "color": "#2b6cb0", "label": "Scanner Agent"},
    "analyst_agent":  {"emoji": "🔬", "color": "#276749", "label": "Analyst Agent"},
    "security_agent": {"emoji": "🔒", "color": "#744210", "label": "Security Agent"},
    "reporter_agent": {"emoji": "📝", "color": "#553c9a", "label": "Reporter Agent"},
    "critic_agent":   {"emoji": "✅", "color": "#c53030", "label": "Critic Agent"},
    "codesleuth_orchestrator": {"emoji": "🎯", "color": "#2d3748", "label": "Orchestrator"},
}

def _get_meta(author: str) -> dict:
    return AGENT_META.get(author, {
        "emoji": "🤖",
        "color": "#4a5568",
        "label": author,
    })


def _build_timeline(all_events: list) -> list[dict]:
    """
    Build a per-agent summary from the event stream.
    Returns a list of dicts: {author, tools_called, text_preview, event_count}.
    """
    seen: dict[str, dict] = {}
    order: list[str] = []

    for event in all_events:
        author = getattr(event, "author", None) or "unknown"
        if author not in seen:
            seen[author] = {"tools_called": [], "text_chunks": [], "event_count": 0}
            order.append(author)
        seen[author]["event_count"] += 1

        # Collect tool calls (function calls the agent made)
        try:
            fc = event.get_function_calls()
            if fc:
                for call in fc:
                    name = getattr(call, "name", str(call))
                    if name not in seen[author]["tools_called"]:
                        seen[author]["tools_called"].append(name)
        except Exception:
            pass

        # Collect text from intermediate responses (not just final)
        try:
            if event.content and event.content.parts:
                for part in event.content.parts:
                    if hasattr(part, "text") and part.text and len(part.text) > 20:
                        seen[author]["text_chunks"].append(part.text[:300])
        except Exception:
            pass

    timeline = []
    for author in order:
        data = seen[author]
        preview = data["text_chunks"][0] if data["text_chunks"] else None
        timeline.append({
            "author": author,
            "meta": _get_meta(author),
            "tools_called": data["tools_called"],
            "text_preview": preview,
            "event_count": data["event_count"],
        })
    return timeline


# ─────────────────────────────────────────────────────────────────────────────
# UI — Hero header
# ─────────────────────────────────────────────────────────────────────────────

st.markdown("""
<div class="hero-banner">
    <div class="hero-title">🔍 CodeSleuth</div>
    <div class="hero-subtitle">Technical debt audit — multi-agent pipeline powered by Google ADK &amp; Gemini</div>
    <span class="hero-badge">⚡ Scanner → Analyst → Security → Reporter → Critic</span>
</div>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# UI — Input form
# ─────────────────────────────────────────────────────────────────────────────

with st.container():
    col_input, col_btn = st.columns([5, 1], vertical_alignment="bottom")

    with col_input:
        repo_input = st.text_input(
            label="GitHub Repository",
            placeholder="owner/repo  — e.g.  Nouhayousse/learn_RAG",
            help="Enter a public GitHub repository in the format owner/repo",
            label_visibility="visible",
        )

    with col_btn:
        launch = st.button("🔍 Launch audit", type="primary", use_container_width=True)


# ─────────────────────────────────────────────────────────────────────────────
# UI — Previous result persistence
# ─────────────────────────────────────────────────────────────────────────────
if "last_report" not in st.session_state:
    st.session_state.last_report = None
    st.session_state.last_events = []
    st.session_state.last_repo = ""
    st.session_state.last_error = None


# ─────────────────────────────────────────────────────────────────────────────
# UI — Trigger audit
# ─────────────────────────────────────────────────────────────────────────────
if launch:
    raw = repo_input.strip()
    if not raw or "/" not in raw:
        st.error("⚠️  Please enter a valid `owner/repo` (e.g. `pallets/flask`).")
    else:
        parts = raw.split("/", 1)
        owner, repo = parts[0].strip(), parts[1].strip()

        st.session_state.last_error = None
        st.session_state.last_report = None
        st.session_state.last_events = []
        st.session_state.last_repo = f"{owner}/{repo}"

        with st.spinner(
            f"⏳ Auditing **{owner}/{repo}** — Scanner → Analyst → Security → Reporter → Critic …  "
            "(this takes 30-90 seconds — please wait)"
        ):
            try:
                report_text, events = run_audit_sync(owner, repo)
                st.session_state.last_report = report_text
                st.session_state.last_events = events
            except Exception as exc:
                tb = traceback.format_exc()
                st.session_state.last_error = (str(exc), tb)


# ─────────────────────────────────────────────────────────────────────────────
# UI — Error display
# ─────────────────────────────────────────────────────────────────────────────
if st.session_state.last_error:
    exc_msg, tb = st.session_state.last_error
    st.error(f"❌ The audit failed: **{exc_msg}**")
    
    # Friendly advice for network/DNS failures
    if "getaddrinfo failed" in tb or "ConnectError" in tb or "ConnectionError" in tb or "11001" in tb:
        st.warning("""
        🛜 **Network Connection Issue Detected**
        
        This error usually happens when:
        1. Your internet connection is offline or unstable.
        2. A local firewall or antivirus software is blocking Python/Streamlit network requests.
        3. DNS resolution is failing to resolve `generativelanguage.googleapis.com` or `api.github.com`.
        
        Please check your network settings and click **Retry** below.
        """)

    with st.expander("🪲 Technical details (traceback)"):
        st.code(tb, language="python")
    if st.button("🔄 Retry"):
        st.session_state.last_error = None
        st.rerun()



# ─────────────────────────────────────────────────────────────────────────────
# UI — Report display
# ─────────────────────────────────────────────────────────────────────────────
if st.session_state.last_report:
    report = st.session_state.last_report
    events = st.session_state.last_events
    repo_label = st.session_state.last_repo

    st.divider()

    # ── Extract key metrics ──────────────────────────────────────────────────
    global_score  = _extract_score(report, r'(?:global|overall|technical debt)[^0-9]*(\d{1,3})\s*/\s*100')
    quality_score = _extract_score(report, r'(?:qualit[eé]|quality)[^0-9]*(\d{1,2})\s*/\s*40')
    security_score= _extract_score(report, r'(?:s[eé]curit[eé]|security)[^0-9]*(\d{1,2})\s*/\s*30')
    structure_score=_extract_score(report, r'(?:structure)[^0-9]*(\d{1,2})\s*/\s*30')

    # Count critical CVEs mentioned in the report
    cve_count = _count_pattern(report, r'\bCVE-\d{4}-\d+\b')
    hotspot_critical = _count_pattern(report, r'CRITICAL HOTSPOT')

    # ── Score dashboard ──────────────────────────────────────────────────────
    st.markdown(f"### 📊 Audit results — `{repo_label}`")

    num_cols = sum([
        1,                              # always show global
        quality_score is not None,
        security_score is not None,
        structure_score is not None,
        1,                              # always show CVE count
    ])
    cols = st.columns(num_cols)
    col_idx = 0

    def _score_card(col, label: str, value, denom: str, css_class: str, sub: str = ""):
        display = f"{value}/{denom}" if value is not None else "N/A"
        col.markdown(f"""
<div class="score-card">
    <div class="score-label">{label}</div>
    <div class="{css_class}">{display}</div>
    <div class="score-sub">{sub}</div>
</div>""", unsafe_allow_html=True)

    # Global score
    _score_card(
        cols[col_idx], "Technical Debt Score",
        global_score, "100",
        _score_color(global_score),
        "global index",
    )
    col_idx += 1

    if quality_score is not None:
        _score_card(cols[col_idx], "Code Quality", quality_score, "40",
                    _score_color(int(quality_score / 40 * 100) if quality_score else None), "analyst")
        col_idx += 1

    if security_score is not None:
        _score_card(cols[col_idx], "Security", security_score, "30",
                    _score_color(int(security_score / 30 * 100) if security_score else None), "security agent")
        col_idx += 1

    if structure_score is not None:
        _score_card(cols[col_idx], "Structure", structure_score, "30",
                    _score_color(int(structure_score / 30 * 100) if structure_score else None), "scanner")
        col_idx += 1

    # CVE count card
    cve_class = "score-value-critical" if cve_count > 0 else "score-value-good"
    cols[col_idx].markdown(f"""
<div class="score-card">
    <div class="score-label">CVEs Detected</div>
    <div class="{cve_class}">{cve_count}</div>
    <div class="score-sub">{"⚠️ review required" if cve_count > 0 else "✅ none detected"}</div>
</div>""", unsafe_allow_html=True)

    if hotspot_critical > 0:
        st.warning(f"🔥 **{hotspot_critical} critical hotspot(s)** detected — high regression risk.")

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Report in tabs ───────────────────────────────────────────────────────
    sections = _split_report_into_sections(report)

    summary_content   = _find_section(sections, ["summary", "résumé", "executive", "exécutif", "overview"])
    structure_content = _find_section(sections, ["structure", "scanner", "structure analysis"])
    quality_content   = _find_section(sections, ["quality", "qualité", "analyst", "hotspot", "code quality"])
    security_content  = _find_section(sections, ["security", "sécurité", "vulnerab", "cve"])
    action_content    = _find_section(sections, ["action", "priority", "priorit", "plan", "remediat"])
    critic_content    = _find_section(sections, ["critic", "validation", "critique"])

    tab_labels = ["📋 Summary", "🏗️ Structure", "🔬 Code Quality", "🔒 Security", "✅ Action Plan", "📄 Full Report"]
    tabs = st.tabs(tab_labels)

    # Tab 0 — Summary
    with tabs[0]:
        if summary_content:
            st.markdown(summary_content)
        elif sections:
            # Show the first section as summary
            first_key = next(iter(sections))
            st.markdown(sections[first_key])
        else:
            st.markdown(report[:2000])

        if critic_content:
            st.divider()
            st.markdown("#### 🎯 Critic Agent Validation")
            st.markdown(critic_content)

    # Tab 1 — Structure
    with tabs[1]:
        if structure_content:
            st.markdown(structure_content)
        else:
            st.info("Structure analysis data is included in the full report below.")
            st.markdown(report)

    # Tab 2 — Code Quality / Hotspots
    with tabs[2]:
        if quality_content:
            # Highlight hotspot lines with colored badges
            lines = quality_content.split("\n")
            rendered = []
            for line in lines:
                if "CRITICAL HOTSPOT" in line:
                    line = line.replace(
                        "CRITICAL HOTSPOT",
                        '<span class="badge-critical">CRITICAL HOTSPOT</span>'
                    )
                    rendered.append(line)
                elif "MODERATE HOTSPOT" in line:
                    line = line.replace(
                        "MODERATE HOTSPOT",
                        '<span class="badge-high">MODERATE HOTSPOT</span>'
                    )
                    rendered.append(line)
                elif "STABLE" in line and "hotspot" in line.lower():
                    line = line.replace(
                        "STABLE",
                        '<span class="badge-low">STABLE</span>'
                    )
                    rendered.append(line)
                else:
                    rendered.append(line)
            st.markdown("\n".join(rendered), unsafe_allow_html=True)
        else:
            st.info("Quality analysis data is included in the full report below.")
            st.markdown(report)

    # Tab 3 — Security (with severity badge replacement)
    with tabs[3]:
        if security_content:
            enhanced = security_content
            # Replace severity labels with colored badges
            for word, css in [
                ("CRITICAL", "badge-critical"), ("CRITIQUE", "badge-critical"),
                ("HIGH", "badge-high"), ("ÉLEVÉ", "badge-high"), ("ELEVE", "badge-high"),
                ("MEDIUM", "badge-medium"), ("MOYEN", "badge-medium"),
                ("LOW", "badge-low"), ("FAIBLE", "badge-low"),
            ]:
                enhanced = re.sub(
                    rf'\b{word}\b',
                    f'<span class="{css}">{word}</span>',
                    enhanced,
                )
            st.markdown(enhanced, unsafe_allow_html=True)
        else:
            st.info("Security analysis data is included in the full report below.")
            st.markdown(report)

    # Tab 4 — Action Plan
    with tabs[4]:
        if action_content:
            st.markdown(action_content)
        else:
            st.info("Action plan data is included in the full report below.")
            st.markdown(report)

    # Tab 5 — Full Report (always the safe fallback)
    with tabs[5]:
        st.markdown(report)
        st.download_button(
            label="⬇️ Download report (.md)",
            data=report,
            file_name=f"codesleuth_{repo_label.replace('/', '_')}_audit.md",
            mime="text/markdown",
        )

    # ── Agent reasoning expander ─────────────────────────────────────────────
    st.divider()
    timeline = _build_timeline(events)

    with st.expander("🤖 What each agent did — pipeline transparency", expanded=False):
        if not timeline:
            st.info("No event data available.")
        else:
            for entry in timeline:
                meta = entry["meta"]
                tools_html = "".join(
                    f'<span class="tool-chip">{t}</span>'
                    for t in entry["tools_called"]
                ) if entry["tools_called"] else '<span style="color:#4a5568;font-size:0.78rem;">no tool call</span>'

                preview_html = ""
                if entry["text_preview"]:
                    snippet = entry["text_preview"].replace("<", "&lt;").replace(">", "&gt;")
                    preview_html = f'<div class="agent-detail" style="margin-top:0.4rem;color:#a0aec0;">"{snippet}…"</div>'

                st.markdown(f"""
<div class="agent-row">
    <div class="agent-icon" style="background:{meta['color']}22; border: 1px solid {meta['color']}55;">
        {meta['emoji']}
    </div>
    <div style="flex:1">
        <div class="agent-name">{meta['label']}</div>
        <div class="agent-detail">
            {entry['event_count']} events &nbsp;·&nbsp; Tools: {tools_html}
        </div>
        {preview_html}
    </div>
</div>""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# UI — Footer
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("<br>", unsafe_allow_html=True)
st.markdown("""
<div style="text-align:center; color:#4a5568; font-size:0.78rem; padding:1rem 0;">
    CodeSleuth v0.3 &nbsp;·&nbsp; Google ADK + Gemini &nbsp;·&nbsp;
    Scanner → Analyst → Security → Reporter → Critic
</div>
""", unsafe_allow_html=True)
