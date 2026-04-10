"""
PDF Report Generator — ASPM Red Team Engine
============================================
Produces a professional, printable security audit PDF using fpdf2.
All Unicode special characters are sanitized for Latin-1 core font compatibility.
"""
from fpdf import FPDF
from datetime import datetime, timezone
from typing import Dict


# ── Unicode → ASCII sanitizer for fpdf2 core fonts ───────────────────────────
def _safe(text: str) -> str:
    """Replace Unicode glyphs that Latin-1 core fonts cannot render."""
    if not isinstance(text, str):
        text = str(text)
    replace_map = [
        # Common symbols
        ('\u2713', 'PASS'), ('\u2717', 'FAIL'), ('\u2714', 'PASS'), ('\u2718', 'FAIL'),
        ('✓', 'PASS'), ('✗', 'FAIL'), ('⚠', 'WARN'), ('⚡', '*'),
        # Arrows
        ('→', '->'),   ('←', '<-'),   ('↑', '^'),    ('↓', 'v'),
        ('⇒', '=>'),   ('⇐', '<='),
        # Box drawing
        ('─', '-'),    ('═', '='),    ('━', '-'),
        ('║', '|'),    ('│', '|'),
        ('╔', '+'),    ('╗', '+'),    ('╚', '+'),    ('╝', '+'),
        ('┌', '+'),    ('┐', '+'),    ('└', '+'),    ('┘', '+'),
        ('├', '+'),    ('┤', '+'),    ('┬', '+'),    ('┴', '+'),
        ('╠', '+'),    ('╣', '+'),    ('╦', '+'),    ('╩', '+'),
        # Dashes (the most common crash source!)
        ('\u2014', '--'),  # em dash
        ('\u2013', '-'),   # en dash
        ('\u2012', '-'),   # figure dash
        ('\u2015', '--'),  # horizontal bar
        ('\u2010', '-'),   # hyphen
        ('\u2011', '-'),   # non-breaking hyphen
        ('\u2212', '-'),   # minus sign
        # Quotes
        ('\u2018', "'"),   # left single quote
        ('\u2019', "'"),   # right single quote
        ('\u201C', '"'),   # left double quote
        ('\u201D', '"'),   # right double quote
        ('\u201A', ','),   # single low-9 quote
        ('\u201E', '"'),   # double low-9 quote
        # Dots and bullets
        ('▸', '>'),    ('•', '*'),    ('·', '.'),    ('…', '...'),
        ('\u2022', '*'),   # bullet
        ('\u2026', '...'), # ellipsis
        # Math
        ('≤', '<='),   ('≥', '>='),   ('≠', '!='),   ('≈', '~='),
        ('±', '+/-'),  ('×', 'x'),    ('÷', '/'),
        # Emojis
        ('🔥', '[!]'),   ('🛡', '[S]'),   ('📊', '[G]'),  ('🧠', '[AI]'),
        ('💀', '[!]'),   ('🧬', '[DNA]'), ('🚨', '[!]'),  ('🤖', '[BOT]'),
        ('📈', '[UP]'),  ('📉', '[DN]'),  ('🔴', '[R]'),  ('🟢', '[G]'),
        ('✅', '[OK]'),  ('❌', '[X]'),   ('⭐', '[*]'),
        # Misc
        ('\u00a0', ' '),  # non-breaking space
        ('ε', 'e'),       # epsilon
        ('α', 'a'),       # alpha
        ('γ', 'g'),       # gamma
        ('Σ', 'Sum'),     # sigma
        ('Δ', 'Delta'),   # delta
    ]
    for old, new in replace_map:
        text = text.replace(old, new)
    # Final safety net: encode to latin-1, replacing anything that still can't be represented
    return text.encode('latin-1', errors='replace').decode('latin-1')


# ── Custom PDF class with footer ──────────────────────────────────────────────
class _ASPMReport(FPDF):
    def footer(self):
        self.set_y(-14)
        self.set_font('Helvetica', 'I', 7)
        self.set_text_color(140, 140, 140)
        self.cell(
            0, 10,
            f'ASPM Red Team Engine v3.0  |  Confidential Security Report  |  Page {self.page_no()}',
            align='C'
        )


# ── Main generator ────────────────────────────────────────────────────────────
def generate_pdf_report(results: Dict, job_id: str) -> bytes:
    """Generate a full security audit PDF and return as bytes."""
    pdf = _ASPMReport()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_left_margin(10)
    pdf.set_right_margin(10)
    W = 190  # usable width = 210 - 10 - 10
    pdf.add_page()

    # ── Header banner ─────────────────────────────────────────────────────────
    pdf.set_fill_color(13, 17, 23)
    pdf.rect(0, 0, 210, 42, 'F')

    pdf.set_font('Helvetica', 'B', 22)
    pdf.set_text_color(88, 166, 255)
    pdf.set_xy(10, 7)
    pdf.cell(W, 10, 'ASPM Red Team Engine', ln=True)

    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(190, 190, 190)
    pdf.set_xy(10, 19)
    pdf.cell(W, 7, 'AI Security Posture Report  |  OWASP LLM Top 10 Assessment', ln=True)

    pdf.set_font('Helvetica', '', 8)
    pdf.set_xy(10, 28)
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    jid_display = job_id[:20] + ('...' if len(job_id) > 20 else '')
    pdf.cell(W, 6, _safe(f'Generated: {ts}   |   Job ID: {jid_display}'), ln=True)

    # ── Scan metadata ─────────────────────────────────────────────────────────
    pdf.set_text_color(0, 0, 0)
    pdf.set_xy(10, 50)
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(W, 7, 'Scan Configuration', ln=True)

    completed_raw = results.get('completed_at', 'N/A')
    completed_fmt = completed_raw[:19].replace('T', ' ') if completed_raw != 'N/A' else 'N/A'

    meta_rows = [
        ('Target Model',  _safe(str(results.get('target', 'N/A')))),
        ('Scan Mode',     results.get('scan_mode', 'simulation').replace('_', ' ').title()),
        ('Temperature',   str(results.get('temperature', 'N/A'))),
        ('Engine',        _safe(str(results.get('scan_engine', 'N/A')))),
        ('Completed At',  completed_fmt),
    ]
    for label, value in meta_rows:
        pdf.set_x(10)
        pdf.set_font('Helvetica', 'B', 8)
        pdf.cell(42, 6, f'{label}:', border='B')
        pdf.set_font('Helvetica', '', 8)
        pdf.cell(148, 6, _safe(value), border='B', ln=True)

    pdf.ln(8)

    # ── Security score ────────────────────────────────────────────────────────
    score   = results.get('score', 0)
    summary = results.get('summary', {})
    r, g, b = (63, 185, 80) if score >= 75 else (227, 179, 65) if score >= 50 else (248, 81, 73)

    pdf.set_x(10)
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(W, 7, 'Security Score', ln=True)

    pdf.set_x(10)
    pdf.set_fill_color(r, g, b)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font('Helvetica', 'B', 30)
    pdf.cell(W, 18, f'{score}/100', align='C', fill=True, ln=True)

    pdf.set_text_color(0, 0, 0)
    pdf.set_font('Helvetica', '', 9)
    pdf.set_fill_color(245, 245, 245)
    pdf.set_x(10)
    pdf.cell(63, 7, f"Passed: {summary.get('passed', 0)}",          align='C', fill=True, border=1)
    pdf.cell(63, 7, f"Failed: {summary.get('failed', 0)}",          align='C', fill=True, border=1)
    pdf.cell(64, 7, f"Critical: {summary.get('critical_count', 0)}", align='C', fill=True, border=1, ln=True)
    pdf.ln(8)

    # ── Vulnerability table ───────────────────────────────────────────────────
    pdf.set_x(10)
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(W, 7, 'OWASP LLM Top 10 -- Vulnerability Assessment', ln=True)

    headers    = ['OWASP',  'Vulnerability',  'Status', 'Risk',  'Mode',  'Ep.']
    col_widths = [20,        68,               20,       22,      48,      12]

    pdf.set_fill_color(30, 41, 59)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_x(10)
    for w, h in zip(col_widths, headers):
        pdf.cell(w, 7, h, border=1, fill=True, align='C')
    pdf.ln()

    pdf.set_font('Helvetica', '', 8)
    for v in results.get('vulnerabilities', []):
        failed = v.get('status') == 'Failed'
        pdf.set_fill_color(255, 242, 242) if failed else pdf.set_fill_color(242, 255, 244)
        pdf.set_text_color(0, 0, 0)
        row = [
            v.get('owasp_id', ''),
            _safe(v.get('type', '').split(': ')[-1][:35]),
            v.get('status', ''),
            v.get('risk_level', ''),
            v.get('scan_mode', '').replace('_', ' '),
            str(v.get('epochs', 2)),
        ]
        pdf.set_x(10)
        for w, cell_text in zip(col_widths, row):
            pdf.cell(w, 6, _safe(cell_text), border=1, fill=True,
                     align='C' if w <= 22 else 'L')
        pdf.ln()

    pdf.ln(8)

    # ── Remediation guidance ──────────────────────────────────────────────────
    failed_vulns = [v for v in results.get('vulnerabilities', []) if v.get('status') == 'Failed']
    if failed_vulns:
        pdf.set_x(10)
        pdf.set_font('Helvetica', 'B', 12)
        pdf.cell(W, 7, 'Remediation Guidance', ln=True)
        for v in failed_vulns:
            pdf.set_x(10)
            pdf.set_font('Helvetica', 'B', 9)
            pdf.set_text_color(180, 0, 0)
            label = _safe(f"{v.get('owasp_id', '')} - {v.get('type', '').split(': ')[-1]}")
            pdf.multi_cell(W, 5, label)
            pdf.set_x(10)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font('Helvetica', '', 8)
            mit = _safe(v.get('mitigation', 'No mitigation details available.'))
            pdf.multi_cell(W, 5, mit)
            pdf.ln(3)

    # ── Hardened system prompt ────────────────────────────────────────────────
    hardened = results.get('hardened_prompt', '')
    if hardened:
        pdf.add_page()
        pdf.set_x(10)
        pdf.set_font('Helvetica', 'B', 12)
        pdf.cell(W, 7, 'Auto-Generated Hardened System Prompt', ln=True)
        pdf.set_x(10)
        pdf.set_font('Helvetica', '', 8)
        pdf.set_text_color(80, 80, 80)
        pdf.multi_cell(W, 5, 'Apply the following system prompt to patch all identified vulnerabilities:')
        pdf.ln(3)
        pdf.set_x(10)
        pdf.set_fill_color(248, 248, 252)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font('Courier', '', 7)
        pdf.multi_cell(W, 5, _safe(hardened), fill=True)

    # ── XAI breakdown ─────────────────────────────────────────────────────────
    xai = results.get('xai_explanation', {})
    if xai and xai.get('contributions'):
        pdf.ln(6)
        pdf.set_x(10)
        pdf.set_font('Helvetica', 'B', 12)
        pdf.set_text_color(0, 0, 0)
        tier = _safe(str(xai.get('risk_tier', 'N/A')))
        pdf.cell(W, 7, f'XAI Risk Score Breakdown  |  Risk Tier: {tier}', ln=True)
        pdf.set_font('Helvetica', '', 8)
        for c in xai.get('contributions', []):
            impact = c.get('impact', 0)
            sign   = '+' if impact >= 0 else ''
            clr    = (0, 120, 0) if impact >= 0 else (160, 0, 0)
            pdf.set_text_color(*clr)
            pdf.set_x(10)
            line = _safe(f"{sign}{impact}  {c.get('feature', '')}  -  {c.get('reason', '')}")
            pdf.multi_cell(W, 5, line)
        pdf.set_text_color(0, 0, 0)

    return bytes(pdf.output())

