# Safety-DataClaw

This project sanitizes you claude code trajectories. We are planning on dveloping a feature that allows you to donate your trajecotires for research.
Supporting: Claude Code, Codex, Gemini CLI, and OpenCode.

Here's the pitch:
Don't put your AI trajectories on HF. Donate them for AI safety.
We need better AI safety not more capable open source models.
I believe Claude Code trajectories are very valuable for alignment research and want to make it easy to contribute to this research.

![Safety-DataClaw](safety-dataclaw-meme.png)

**Core principle:** Safety-conscious users should never have to send unsanitized data off their machine. The CLI sanitizes locally; only clean data is uploaded.

## Give this to your coding agent

Paste this into Claude Code, Codex, or any coding agent:

```
Help me export my Claude Code, Codex, Gemini CLI, and OpenCode conversation history to TRACED using safety-dataclaw.
Install it, set up the skill, then walk me through the process.

STEP 1 — INSTALL
  pip install safety-dataclaw
  If that fails: git clone https://github.com/JoachimSchaeffer/safety-dataclaw.git /tmp/safety-dataclaw && pip install /tmp/safety-dataclaw
  If that also fails, ask the user where the source is.

STEP 2 — INSTALL SKILL
  safety-dataclaw update-skill claude

STEP 3 — AUTHENTICATE
  Get an API key at https://traced.run/settings
  safety-dataclaw auth <API_KEY>

STEP 4 — START
  safety-dataclaw prep
  Every safety-dataclaw command outputs next_steps in its JSON — follow them through the entire flow.

STEP 4A — CHOOSE SOURCE SCOPE (REQUIRED BEFORE EXPORT)
  Ask the user explicitly: Claude Code, Codex, Gemini CLI, OpenCode, or all?
  safety-dataclaw config --source "claude|codex|gemini|opencode|all"
  Do not export until source scope is explicitly confirmed.

STEP 4B — PRESENT ALL FOLDERS (REQUIRED BEFORE EXPORT)
  safety-dataclaw list --source "claude|codex|gemini|opencode|all"
  Send the FULL project/folder list to the user in a message (name, source, sessions, size, excluded).
  Ask which projects to exclude.
  safety-dataclaw config --exclude "project1,project2" OR safety-dataclaw config --confirm-projects
  Do not export until folder selection is explicitly confirmed.

STEP 4C — CHOOSE TOOL OUTPUT INCLUSION (REQUIRED BEFORE EXPORT)
  Ask the user: should tool outputs (file contents, bash stdout, grep results) be included?
  Including them provides richer trajectory data but increases export size significantly.
  Secrets are still redacted either way.
  safety-dataclaw config --include-tool-outputs OR safety-dataclaw config --no-tool-outputs

STEP 5 — REVIEW + CONFIRM (REQUIRED BEFORE UPLOAD)
  safety-dataclaw export --no-push --output /tmp/safety_dataclaw_export.jsonl
  Review PII findings and apply excludes/redactions as needed.
  Full name is requested for an exact-name privacy scan against the export.
  If the user declines sharing full name, use --skip-full-name-scan and attest the skip reason.
  safety-dataclaw confirm --full-name "THEIR FULL NAME" --attest-full-name "..." --attest-sensitive "..." --attest-manual-scan "..."

STEP 6 — UPLOAD (ONLY AFTER EXPLICIT USER APPROVAL)
  safety-dataclaw upload
  After upload, visit https://traced.run to publish individual trajectories.

IF ANY COMMAND FAILS DUE TO A SKIPPED STEP:
  Restate the checklist above and resume from the blocked step (do not skip ahead).

IMPORTANT: Always export with --no-push first and review for PII before uploading.
```

<details>
<summary><b>Manual usage (without an agent)</b></summary>

### Quick start

```bash
pip install safety-dataclaw

# Authenticate
safety-dataclaw auth <API_KEY>  # Get key at https://traced.run/settings

# See your projects
safety-dataclaw prep
safety-dataclaw config --source all  # REQUIRED: choose claude, codex, gemini, opencode, or all
safety-dataclaw list --source all    # Present full list and confirm folder scope before export

# Configure
safety-dataclaw config --exclude "personal-stuff,scratch"
safety-dataclaw config --redact-usernames "my_github_handle,my_discord_name"
safety-dataclaw config --redact "my-domain.com,my-secret-project"

# Export locally first
safety-dataclaw export --no-push

# Review and confirm
safety-dataclaw confirm \
  --full-name "YOUR FULL NAME" \
  --attest-full-name "Asked for full name and scanned export for YOUR FULL NAME." \
  --attest-sensitive "Asked about company/client/internal names and private URLs; none found or redactions updated." \
  --attest-manual-scan "Manually scanned 20 sessions across beginning/middle/end and reviewed findings."

# Optional if user declines sharing full name
safety-dataclaw confirm \
  --skip-full-name-scan \
  --attest-full-name "User declined to share full name; skipped exact-name scan." \
  --attest-sensitive "Asked about company/client/internal names and private URLs; none found or redactions updated." \
  --attest-manual-scan "Manually scanned 20 sessions across beginning/middle/end and reviewed findings."

# Upload
safety-dataclaw upload
```

### Commands

| Command | Description |
|---------|-------------|
| `safety-dataclaw status` | Show current stage and next steps (JSON) |
| `safety-dataclaw auth <KEY>` | Authenticate with TRACED API key |
| `safety-dataclaw prep` | Discover projects, check auth, output JSON |
| `safety-dataclaw prep --source all` | Prep with all sources explicitly selected |
| `safety-dataclaw prep --source claude` | Prep using only Claude Code sessions |
| `safety-dataclaw prep --source codex` | Prep using only Codex sessions |
| `safety-dataclaw prep --source gemini` | Prep using only Gemini CLI sessions |
| `safety-dataclaw prep --source opencode` | Prep using only OpenCode sessions |
| `safety-dataclaw list` | List all projects with exclusion status |
| `safety-dataclaw list --source all` | List all sources |
| `safety-dataclaw list --source codex` | List only Codex projects |
| `safety-dataclaw config` | Show current config |
| `safety-dataclaw config --source all` | REQUIRED source scope selection (`claude`, `codex`, `gemini`, `opencode`, or `all`) |
| `safety-dataclaw config --exclude "a,b"` | Add excluded projects (appends) |
| `safety-dataclaw config --redact "str1,str2"` | Add strings to always redact (appends) |
| `safety-dataclaw config --redact-usernames "u1,u2"` | Add usernames to anonymize (appends) |
| `safety-dataclaw config --confirm-projects` | Mark project selection as confirmed |
| `safety-dataclaw export --no-push` | Export locally only (always do this first) |
| `safety-dataclaw export --source all --no-push` | Export all sources locally |
| `safety-dataclaw export --all-projects` | Include everything (ignore exclusions) |
| `safety-dataclaw export --no-thinking` | Exclude extended thinking blocks |
| `safety-dataclaw export --include-tool-outputs` | Include tool results (file contents, bash stdout, etc.) |
| `safety-dataclaw confirm --full-name "NAME" ...` | Scan for PII, run exact-name privacy check, verify review attestations, unlock uploading |
| `safety-dataclaw upload` | Upload sanitized data to TRACED as private datasets |
| `safety-dataclaw update-skill claude` | Install/update the safety-dataclaw skill for Claude Code |

</details>

<details>
<summary><b>What gets exported</b></summary>

| Data | Included | Notes |
|------|----------|-------|
| User messages | Yes | Full text (including voice transcripts) |
| Assistant responses | Yes | Full text output |
| Extended thinking | Yes | Claude's reasoning (opt out with `--no-thinking`) |
| Tool calls | Yes | Tool name + summarized input |
| Tool results | Optional | Opt in with `--include-tool-outputs` (secrets redacted) |
| Token usage | Yes | Input/output tokens per session |
| Model & metadata | Yes | Model name, git branch, timestamps |

### Privacy & Redaction

Safety-DataClaw applies multiple layers of protection:

1. **Path anonymization** — File paths stripped to project-relative
2. **Username hashing** — Your macOS username + any configured usernames replaced with stable hashes
3. **Secret detection** — Regex patterns catch JWT tokens, API keys (Anthropic, OpenAI, HF, GitHub, AWS, etc.), database passwords, private keys, Discord webhooks, and more
4. **Entropy analysis** — Long high-entropy strings in quotes are flagged as potential secrets
5. **Email redaction** — Personal email addresses removed
6. **Custom redaction** — You can configure additional strings and usernames to redact
7. **Tool input pre-redaction** — Secrets in tool inputs are redacted BEFORE truncation to prevent partial leaks

**This is NOT foolproof.** Always review your exported data before uploading.
Automated redaction cannot catch everything — especially service-specific
identifiers, third-party PII, or secrets in unusual formats.

To help improve redaction, report issues: https://github.com/JoachimSchaeffer/safety-dataclaw/issues

</details>

<details>
<summary><b>Data schema</b></summary>

Each line in the JSONL export is one session:

```json
{
  "session_id": "abc-123",
  "project": "my-project",
  "model": "claude-opus-4-6",
  "git_branch": "main",
  "start_time": "2025-06-15T10:00:00+00:00",
  "end_time": "2025-06-15T10:30:00+00:00",
  "messages": [
    {"role": "user", "content": "Fix the login bug", "timestamp": "..."},
    {
      "role": "assistant",
      "content": "I'll investigate the login flow.",
      "thinking": "The user wants me to look at...",
      "tool_uses": [{"tool": "Read", "input": "src/auth.py", "output": "(only with --include-tool-outputs)"}],
      "timestamp": "..."
    }
  ],
  "stats": {
    "user_messages": 5, "assistant_messages": 8,
    "tool_uses": 20, "input_tokens": 50000, "output_tokens": 3000
  }
}
```

</details>

## License

MIT — forked from [dataclaw](https://github.com/peteromallet/dataclaw) by Banodoco.
