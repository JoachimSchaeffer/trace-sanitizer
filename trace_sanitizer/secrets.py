"""Detect and redact secrets in conversation data."""

import math
import re
import unicodedata

REDACTED = "[REDACTED]"

# Zero-width and invisible Unicode characters that can be inserted into
# secrets to evade regex detection while remaining visually identical.
_INVISIBLE_CHARS = re.compile(
    "[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\ufeff\u00ad\u034f\u061c\u180e]"
)


def _normalize_unicode(text: str) -> str:
    """Strip invisible characters and normalize Unicode to ASCII-compatible form.

    NFKC normalization collapses fullwidth characters (e.g. \uff53\uff4b -> sk)
    and other confusables to their ASCII equivalents.
    """
    text = _INVISIBLE_CHARS.sub("", text)
    return unicodedata.normalize("NFKC", text)

# Ordered from most specific to least specific
SECRET_PATTERNS = [
    # JWT tokens — full 3-segment form
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}")),

    # JWT tokens — partial (header only or header+partial payload, e.g. truncated)
    ("jwt_partial", re.compile(r"eyJ[A-Za-z0-9_-]{15,}")),

    # Orphaned JWT segments after partial redaction (e.g. [REDACTED].[REDACTED].<payload>.<sig>)
    # Allow optional newlines between segments (terminal line-wrapping)
    ("jwt_orphan_sig", re.compile(
        r"\[REDACTED\]\.\[REDACTED\]\s*\.?\s*[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{10,})?"
    )),

    # PostgreSQL/database connection strings with passwords
    ("db_url", re.compile(r"postgres(?:ql)?://[^:]+:[^@\s]+@[^\s\"'`]+")),

    # Anthropic API keys
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),

    # OpenAI API keys (including sk-proj- format with hyphens/underscores)
    # Require at least one uppercase letter to avoid matching URL slugs like sk-assessment-in-...
    ("openai_key", re.compile(r"sk-(?=[A-Za-z0-9_-]*[A-Z])[A-Za-z0-9_-]{40,}")),

    # Docent API keys — require mixed case to avoid matching filenames like dk_dv_pipeline_kr
    ("docent_key", re.compile(r"dk_(?=[A-Za-z0-9_-]*[A-Z])[A-Za-z0-9_-]{20,}")),

    # Hugging Face tokens — require mixed case to avoid matching function names like hf_hub_download
    ("hf_token", re.compile(r"hf_(?=[A-Za-z0-9_-]*[A-Z])[A-Za-z0-9_-]{20,}")),

    # GitHub tokens
    ("github_token", re.compile(r"(?:ghp|gho|ghs|ghr)_[A-Za-z0-9_-]{30,}")),

    # PyPI tokens
    ("pypi_token", re.compile(r"pypi-[A-Za-z0-9_-]{50,}")),

    # NPM tokens
    ("npm_token", re.compile(r"npm_[A-Za-z0-9_-]{30,}")),

    # AWS access key IDs (but not in regex pattern context)
    ("aws_key", re.compile(r"(?<![A-Za-z0-9\[])AKIA[0-9A-Z]{16}(?![0-9A-Z\]{}])")),

    # AWS secret keys (40 chars, mixed case + special)
    ("aws_secret", re.compile(
        r"(?:aws_secret_access_key|secret_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        re.IGNORECASE,
    )),

    # Google Cloud API keys
    ("gcloud_key", re.compile(r"AIza[A-Za-z0-9_-]{35}")),

    # Telegram bot tokens: 8-10 digit bot ID + colon + 35-char secret
    ("telegram_bot_token", re.compile(r"\d{8,10}:AA[A-Za-z0-9_-]{30,}")),

    # Feishu/Lark app IDs
    ("feishu_app_id", re.compile(r"cli_[a-f0-9]{16,}")),

    # ZhipuAI/GLM API keys: 32-char hex + dot + 8+ char alphanumeric (mixed case)
    # Reject blob hashes (.incomplete) and CDN hostnames (.cloudfront, .amazonaws)
    ("zhipuai_key", re.compile(
        r"[0-9a-f]{32}\.(?!incomplete|cloudfront|amazonaws|blob)[A-Za-z0-9]{8,}"
    )),

    # Stripe keys (secret, publishable, restricted)
    ("stripe_key", re.compile(r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9_-]{20,}")),

    # SendGrid API keys
    ("sendgrid_key", re.compile(r"SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,}")),

    # Twilio account SIDs and auth tokens
    ("twilio_key", re.compile(r"(?:AC|SK)[a-f0-9]{32}")),

    # DigitalOcean tokens
    ("digitalocean_token", re.compile(r"dop_v1_[a-f0-9]{64}")),

    # Mailgun API keys — require mixed alphanumeric (not URL slugs like key-projects-strategies)
    ("mailgun_key", re.compile(r"key-(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{32}")),

    # Slack tokens
    ("slack_token", re.compile(r"xox[bpsa]-[A-Za-z0-9-]{20,}")),

    # Discord webhook URLs (contain a secret token in the path)
    ("discord_webhook", re.compile(
        r"https?://(?:discord\.com|discordapp\.com)/api/webhooks/\d+/[A-Za-z0-9_-]{20,}"
    )),

    # MAC addresses (hardware fingerprinting)
    # Require colon or dash separator consistently; reject time ranges (HH:MM:SS-HH:MM:SS)
    ("mac_address", re.compile(
        r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b"
        r"|\b[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}\b"
    )),

    # Windows hostnames (device fingerprinting)
    ("windows_hostname", re.compile(r"\bDESKTOP-[A-Z0-9]{6,8}\b")),

    # Private keys (body capped at 10KB to prevent ReDoS on unmatched BEGIN)
    ("private_key", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        r"[\s\S]{0,10000}?"
        r"-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    )),

    # CLI flags that pass tokens/secrets: --token VALUE, --access-token VALUE, etc.
    ("cli_token_flag", re.compile(
        r"(?:--|-)(?:access[_-]?token|auth[_-]?token|api[_-]?key|secret|password|token)"
        r"[\s=]+([A-Za-z0-9_/+=.-]{8,})",
        re.IGNORECASE,
    )),

    # Environment variable assignments with secret-like names (with or without quotes)
    ("env_secret", re.compile(
        r"(?:SECRET|PASSWORD|TOKEN|API_KEY|AUTH_KEY|ACCESS_KEY|SERVICE_KEY|DB_PASSWORD"
        r"|SUPABASE_KEY|SUPABASE_SERVICE|ANON_KEY|SERVICE_ROLE)"
        r"\s*[=]\s*['\"]?([^\s'\"]{6,})['\"]?",
        re.IGNORECASE,
    )),

    # Generic secret assignments: SECRET_KEY = "value", api_key: "value", etc.
    ("generic_secret", re.compile(
        r"""(?:secret[_-]?key|api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token"""
        r"""|service[_-]?role[_-]?key|private[_-]?key)"""
        r"""\s*[=:]\s*['"]([A-Za-z0-9_/+=.-]{20,})['"]""",
        re.IGNORECASE,
    )),

    # Bearer tokens in headers — catch both JWT and non-JWT tokens
    ("bearer", re.compile(
        r"Bearer\s+([A-Za-z0-9_.-]{20,}(?:\.[A-Za-z0-9_.-]{8,})*)"
    )),

    # Authorization header (case-insensitive, catches "Authorization: Bearer <token>")
    ("auth_header", re.compile(
        r"Authorization:\s*Bearer\s+([A-Za-z0-9_./+=:-]{20,})",
        re.IGNORECASE,
    )),

    # IP addresses (public, non-loopback, non-private-by-default)
    ("ip_address", re.compile(
        r"\b(?!127\.0\.0\.)(?!0\.0\.0\.0)(?!255\.255\.)"
        r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
    )),

    # URL query params with secrets: ?key=VALUE, &token=VALUE, etc.
    ("url_token", re.compile(
        r"[?&](?:key|token|secret|password|apikey|api_key|access_token|auth)"
        r"=([A-Za-z0-9_/+=.-]{8,})",
        re.IGNORECASE,
    )),

    # Social media profile URLs — redact username/slug component
    ("social_profile_url", re.compile(
        r"(?:linkedin\.com/(?:in|pub|posts)/[A-Za-z0-9._-]+)"
        r"|(?:facebook\.com/[A-Za-z0-9._-]+)"
        r"|(?:x\.com/[A-Za-z0-9._-]+)"
        r"|(?:twitter\.com/[A-Za-z0-9._-]+)"
        r"|(?:instagram\.com/[A-Za-z0-9._-]+)",
        re.IGNORECASE,
    )),

    # Email addresses (for PII removal) — require at least 2-char local part
    # Negative lookbehind for \n to avoid matching Python decorators (\n@module.func)
    ("email", re.compile(r"(?<!\n)\b[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),

    # Long base64-like strings in quotes (checked for entropy — see scan_text)
    ("high_entropy", re.compile(r"""['"][A-Za-z0-9_/+=.-]{40,}['"]""")),

    # Unquoted high-entropy alphanumeric strings (24+ chars, checked for entropy)
    ("high_entropy_unquoted", re.compile(r"\b[A-Za-z0-9_-]{24,}\b")),

    # Supabase project URLs (20-char lowercase alpha project ref)
    ("supabase_project", re.compile(r"[a-z]{20}\.supabase\.co")),
]

ALLOWLIST = [
    re.compile(r"noreply@"),
    re.compile(r"@example\.com"),
    re.compile(r"@localhost"),
    re.compile(r"@anthropic\.com"),
    re.compile(r"@github\.com"),
    re.compile(r"@users\.noreply\.github\.com"),
    re.compile(r"AKIA\["),  # regex patterns about AWS keys
    re.compile(r"sk-ant-\.\*"),  # regex patterns about API keys
    re.compile(r"postgres://user:pass@"),  # example/documentation URLs
    re.compile(r"postgres://username:password@"),
    re.compile(r"@pytest"),  # Python decorator false positives
    re.compile(r"@tasks\."),
    re.compile(r"@mcp\."),
    re.compile(r"@server\."),
    re.compile(r"@app\."),
    re.compile(r"@router\."),
    re.compile(r"192\.168\."),  # private IPs (low risk)
    re.compile(r"10\.\d+\.\d+\.\d+"),
    re.compile(r"172\.(?:1[6-9]|2\d|3[01])\."),
    re.compile(r"8\.8\.8\.8"),  # Google DNS
    re.compile(r"8\.8\.4\.4"),
    re.compile(r"1\.1\.1\.1"),  # Cloudflare DNS
    re.compile(r"de:ad:be:ef", re.IGNORECASE),  # well-known dummy MAC
    re.compile(r"00:00:00:00:00:00"),  # null MAC (down adapters)
    # Well-known org social profiles (not personal PII)
    re.compile(r"linkedin\.com/(?:in|pub|posts)/(?:company|anthropic|openai)\b", re.IGNORECASE),
    # x.com/twitter.com glob patterns and common non-profile paths
    re.compile(r"x\.com/[.*]", re.IGNORECASE),  # glob patterns like x.com/.*
    re.compile(r"(?:x|twitter)\.com/(?:forums|search|home|explore|settings|i/)\b", re.IGNORECASE),
    # Python decorator false positives for email pattern
    re.compile(r"@triton\."),
    re.compile(r"@dataclasses\."),
    re.compile(r"@functools\."),
    re.compile(r"@contextlib\."),
    re.compile(r"@torch\."),
    re.compile(r"@CustomOp\."),
]


def _shannon_entropy(s: str) -> float:
    """Higher values indicate more random-looking strings."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _has_mixed_char_types(s: str) -> bool:
    """Check if string has a mix of uppercase, lowercase, and digits."""
    has_upper = any(c.isupper() for c in s)
    has_lower = any(c.islower() for c in s)
    has_digit = any(c.isdigit() for c in s)
    return has_upper and has_lower and has_digit


def _looks_like_identifier(s: str) -> bool:
    """Return True if the string looks like a code identifier, not a secret.

    Catches: camelCase, PascalCase, snake_case, hyphenated model names,
    already-redacted path hashes (user_abcd1234), tool use IDs (toolu_01...),
    GPU kernel names, and C++ mangled symbols.
    """
    # camelCase or PascalCase: starts with letter, has transitions like aB or Ab
    if re.match(r'^[a-zA-Z]', s) and re.search(r'[a-z][A-Z]', s):
        # Extract "word segments" — runs of lowercase (optionally preceded by uppercase)
        # Real identifiers have recognizable word parts (4+ lowercase chars),
        # while base64/tokens have short random runs.
        word_segments = re.findall(r'[A-Z]?[a-z]{4,}', s)
        if len(word_segments) >= 2:
            return True

    # Underscore-separated identifiers (2+ underscores): covers snake_case, GPU kernels,
    # C++ mangled names (MakeBsGridDescriptor_BK0_N_BK1), config names
    if s.count('_') >= 2:
        parts = s.split('_')
        # If most parts are short alphanumeric tokens that look like abbreviations
        # or words (not random base64), it's an identifier
        identifier_like = sum(1 for p in parts if p and (
            re.match(r'^[A-Z]+[a-z]*$', p) or  # PascalCase/UPPER part
            re.match(r'^[a-z]+\d*$', p) or      # lowercase part with optional digits
            re.match(r'^[A-Z]+\d+$', p) or       # UPPER+digits (MT128, BK0, v4r1)
            len(p) <= 3                           # short abbreviation
        ))
        if identifier_like >= len(parts) * 0.6:
            return True

    # Hyphenated model/project names: Word-Word-Version patterns
    if '-' in s:
        parts = s.split('-')
        # If most parts start with uppercase or are version-like numbers, it's a name
        name_like = sum(1 for p in parts if re.match(r'^[A-Z][a-z]', p) or re.match(r'^\d+', p) or len(p) <= 2)
        if name_like >= len(parts) * 0.5 and len(parts) >= 3:
            return True

    # Already-redacted username paths: Users-user_XXXX-ProjectName
    if re.search(r'user_[a-f0-9]{6,}', s):
        return True

    # Anthropic tool-use IDs
    if s.startswith('toolu_'):
        return True

    # C++ mangled symbols (start with _Z or _GLOBAL)
    if s.startswith(('_ZN', '_ZL', '_GLOBAL')):
        return True

    return False


def _is_time_range(s: str) -> bool:
    """Check if a MAC-address-like string is actually a time range HH:MM:SS-HH:MM:SS."""
    # Time ranges like "20:52:31-20:54:13" have mixed : and - separators
    if '-' in s and ':' in s:
        parts = re.split(r'[-:]', s)
        if len(parts) == 6:
            try:
                vals = [int(p) for p in parts]
                # Check if it looks like two HH:MM:SS times
                if (vals[0] < 24 and vals[1] < 60 and vals[2] < 60 and
                        vals[3] < 24 and vals[4] < 60 and vals[5] < 60):
                    return True
            except ValueError:
                pass
    return False


def _normalize_for_scan(text: str) -> str:
    """Collapse newlines that may break multi-segment token matching.

    Terminal line-wrapping can split JWTs and other tokens across lines,
    causing the regex to miss them. We rejoin lines that look like they
    continue a base64/JWT segment.
    """
    # Rejoin lines where a base64url segment was split by a newline
    # (e.g. "[REDACTED].[REDACTED]\npayload.signature" or "eyJ...\n...sig")
    # Include ] to handle [REDACTED] at line boundaries
    return re.sub(r"([A-Za-z0-9_/+=.\]\[-])\n([A-Za-z0-9_/+=.\[\]-])", r"\1\2", text)


def scan_text(text: str) -> list[dict]:
    if not text:
        return []

    text = _normalize_unicode(text)
    return _scan_raw(text)


def redact_text(text: str) -> tuple[str, int]:
    if not text:
        return text, 0

    # Normalize Unicode before scanning to defeat homoglyph/zero-width evasion
    text = _normalize_unicode(text)

    # First pass: scan and redact original text
    result, count = _apply_redactions(text, _scan_raw(text))

    # Second pass on the already-redacted result:
    # 1. Catch orphaned JWT signatures left after partial redaction
    # 2. Normalize newlines to catch tokens split by terminal line-wrapping
    for _ in range(3):  # at most 3 extra passes
        extra_findings = _scan_raw(result)
        if not extra_findings:
            # Also try with normalized newlines
            normalized = _normalize_for_scan(result)
            if normalized != result:
                extra_findings = _scan_raw(normalized)
                if extra_findings:
                    result, extra = _apply_redactions(normalized, extra_findings)
                    count += extra
                    continue
            break
        result, extra = _apply_redactions(result, extra_findings)
        count += extra

    return result, count


def _scan_raw(text: str) -> list[dict]:
    """Scan text without normalization — used internally for second-pass."""
    if not text:
        return []
    findings = []
    for name, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            matched_text = match.group(0)
            if any(allow_pat.search(matched_text) for allow_pat in ALLOWLIST):
                continue
            if name == "mac_address":
                if _is_time_range(matched_text):
                    continue
            if name == "env_secret":
                if "[REDACTED]" in matched_text:
                    continue
            if name == "high_entropy":
                inner = matched_text[1:-1]
                if not _has_mixed_char_types(inner):
                    continue
                if _shannon_entropy(inner) < 3.5:
                    continue
                if inner.count(".") > 2:
                    continue
            if name == "high_entropy_unquoted":
                if not _has_mixed_char_types(matched_text):
                    continue
                if _shannon_entropy(matched_text) < 4.0:
                    continue
                if _looks_like_identifier(matched_text):
                    continue
            findings.append({
                "type": name,
                "start": match.start(),
                "end": match.end(),
                "match": matched_text,
            })
    return findings


def _apply_redactions(text: str, findings: list[dict]) -> tuple[str, int]:
    """Apply a list of findings as redactions to text."""
    if not findings:
        return text, 0

    # Sort by position (descending start) to replace without shifting indices
    findings.sort(key=lambda f: f["start"], reverse=True)

    # Deduplicate overlapping findings (keep the later-starting match on overlap)
    deduped = []
    for f in findings:
        if not deduped or f["end"] <= deduped[-1]["start"]:
            deduped.append(f)

    # Replace from end-to-start (deduped is already in descending start order)
    result = text
    for f in deduped:
        result = result[:f["start"]] + REDACTED + result[f["end"]:]

    return result, len(deduped)


def redact_custom_strings(text: str, strings: list[str]) -> tuple[str, int]:
    if not text or not strings:
        return text, 0

    count = 0
    for target in strings:
        if not target or len(target) < 3:
            continue
        escaped = re.escape(target)
        if len(target) >= 4:
            # Pass 1: word-boundary match (standard behavior)
            text, replacements = re.subn(rf"\b{escaped}\b", REDACTED, text)
            count += replacements
            # Pass 2: boundaryless case-insensitive match (catches inside
            # filenames, URLs, hashtags like ADNOC_Report.md or #teamrwe)
            text, replacements = re.subn(escaped, REDACTED, text, flags=re.IGNORECASE)
            count += replacements
        else:
            text, replacements = re.subn(escaped, REDACTED, text)
            count += replacements

    return text, count


def redact_session(session: dict, custom_strings: list[str] | None = None) -> tuple[dict, int]:
    """Redact all secrets in a session dict. Returns (redacted_session, total_redactions)."""
    total = 0

    for msg in session.get("messages", []):
        for field in ("content", "thinking"):
            if msg.get(field):
                msg[field], count = redact_text(msg[field])
                total += count
                if custom_strings:
                    msg[field], count = redact_custom_strings(msg[field], custom_strings)
                    total += count
        for tool_use in msg.get("tool_uses", []):
            for field in ("input", "output"):
                if tool_use.get(field):
                    tool_use[field], count = redact_text(tool_use[field])
                    total += count
                    if custom_strings:
                        tool_use[field], count = redact_custom_strings(tool_use[field], custom_strings)
                        total += count

    return session, total
