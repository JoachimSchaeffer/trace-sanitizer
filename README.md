# Trace-Sanitizer

Sanitize your AI agent trajectories and publish misaligned or funny trajectories on [traced.run](https://traced.run).

Supports Claude Code, Codex, Gemini CLI, and OpenCode.

![Trace-Sanitizer](trace-sanitizer-meme.png)

## Install

```bash
pip install trace-sanitizer
```

## 1. Single trajectory

Export one trajectory interactively — no configuration needed.

```bash
trace-sanitizer export
```

This auto-detects all sources, lets you pick a project and session, asks about tool output inclusion, and exports a sanitized JSONL file. Review it for PII, then publish it on [traced.run](https://traced.run).

### Agent prompt

Paste this into Claude Code or any coding agent:

```
Help me export a conversation using trace-sanitizer.

1. pip install trace-sanitizer
2. trace-sanitizer update-skill claude
3. trace-sanitizer export
   (Interactive menu — pick a project and session.)
4. Review the exported JSONL for PII.
5. Tell the user how to publish it at https://traced.run
```

## 2. BETA: Donate multiple trajectories

**This is beta.**

Real world coding trajectories are important for early detection of AI misalignment, failures, and scheming in the wild. Your trajectoreis might contain relevant examples that can make a real difference for research. Trace-sanitizer is maintained by Dr. Joachim Schaeffer. I am currenlty a MATS 9.0 Fellow. I am talking to AI safety research institutes about formal data contribution pipelines. A more structured process will follow.

But if you want to get active now already, bulk donation works like this:

```bash
# Configure
trace-sanitizer config --source all
trace-sanitizer list --source all
trace-sanitizer config --confirm-projects
trace-sanitizer config --include-tool-outputs    # or --no-tool-outputs

# Export everything
trace-sanitizer export --all -o export.jsonl

# Review
trace-sanitizer confirm \
  --full-name "YOUR NAME" \
  --attest-full-name "Scanned for full name." \
  --attest-sensitive "Checked for company names and private URLs." \
  --attest-manual-scan "Sampled 20 sessions manually."
```

Then put the JSONL in a Google Drive folder and email the link to **donate@traced.run**.

<details>
<summary><b>All commands</b></summary>

| Command | Description |
|---------|-------------|
| `trace-sanitizer export` | Interactive: pick a project and session |
| `trace-sanitizer export --all` | Export all sessions (requires config) |
| `trace-sanitizer export --source claude` | Filter by source |
| `trace-sanitizer export --include-tool-outputs` | Include tool results |
| `trace-sanitizer export --no-thinking` | Exclude extended thinking |
| `trace-sanitizer prep` | Discover projects (JSON) |
| `trace-sanitizer list` | List projects with exclusion status |
| `trace-sanitizer config --source all` | Set source scope |
| `trace-sanitizer config --exclude "a,b"` | Exclude projects |
| `trace-sanitizer config --redact "str"` | Add custom redaction strings |
| `trace-sanitizer config --redact-usernames "u"` | Anonymize usernames |
| `trace-sanitizer config --confirm-projects` | Confirm project selection |
| `trace-sanitizer confirm ...` | PII scan + review attestations |
| `trace-sanitizer status` | Show current stage (JSON) |
| `trace-sanitizer update-skill claude` | Install skill for Claude Code |

</details>

<details>
<summary><b>What gets redacted</b></summary>

1. **Paths** — stripped to project-relative
2. **Usernames** — macOS username + configured handles replaced with hashes
3. **Secrets** — JWT tokens, API keys (Anthropic, OpenAI, HF, GitHub, AWS, etc.), private keys, webhooks
4. **Entropy** — high-entropy strings flagged as potential secrets
5. **Emails** — personal addresses removed
6. **Custom** — your configured strings and usernames

**Not foolproof.** Always review before sharing.

</details>

<details>
<summary><b>Data schema</b></summary>

Each JSONL line is one session:

```json
{
  "session_id": "abc-123",
  "project": "my-project",
  "model": "claude-opus-4-6",
  "start_time": "2025-06-15T10:00:00+00:00",
  "messages": [
    {"role": "user", "content": "Fix the login bug"},
    {"role": "assistant", "content": "I'll investigate...", "tool_uses": [{"tool": "Read", "input": "src/auth.py"}]}
  ],
  "stats": {"user_messages": 5, "assistant_messages": 8, "tool_uses": 20}
}
```

</details>

## License

MIT — forked from [dataclaw](https://github.com/peteromallet/dataclaw) by Banodoco.
