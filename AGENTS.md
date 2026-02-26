# Safety-DataClaw

Export Claude Code, Codex, Gemini CLI, and OpenCode conversation history to TRACED.

## THE RULE

**Every `safety-dataclaw` command outputs `next_steps`. FOLLOW THEM.**

Do not memorize the flow. Do not skip steps. Do not improvise.
Run the command → read the output → follow `next_steps`. That's it.

The CLI tracks your stage (1-4: auth → configure → review → done).
`safety-dataclaw upload` is **gated** — you must run `safety-dataclaw confirm` first or it will refuse.

## Getting Started

Run `safety-dataclaw status` (or `safety-dataclaw prep` for full details) and follow the `next_steps`.

## Output Format

- `safety-dataclaw prep`, `safety-dataclaw config`, `safety-dataclaw status`, and `safety-dataclaw confirm` output pure JSON
- `safety-dataclaw export` outputs human-readable text followed by `---SAFETY_DATACLAW_JSON---` and a JSON block
- Always parse the JSON and act on `next_steps`

Key fields:
- `stage` / `stage_number` / `total_stages` — where you are
- `next_steps` — follow these in order
- `next_command` — the single most important command to run next (null if user input needed first)

## PII Audit (Stage 3)

After `safety-dataclaw export --no-push`, follow the `next_steps` in the JSON output. The flow is:

1. **Ask the user their full name** — then grep the export for it
2. **Run the pii_commands** from the JSON output and review results with the user
3. **Ask the user what else to look for** — company names, client names, private URLs, other people's names, custom domains
4. **Deep manual scan** — sample ~20 sessions (beginning, middle, end) and look for anything sensitive the regex missed
5. **Fix and re-export** if anything found: `safety-dataclaw config --redact "string"` then `safety-dataclaw export --no-push`
6. **Run `safety-dataclaw confirm` with text attestations** — pass `--full-name`, `--attest-full-name`, `--attest-sensitive`, and `--attest-manual-scan`. It runs PII scan, verifies attestations, shows project breakdown, and unlocks uploading.
7. **Upload only after explicit user confirmation**: `safety-dataclaw upload`
   After upload, visit https://traced.run/datasets to publish individual trajectories.

## Commands Reference

```bash
safety-dataclaw status                            # Show current stage and next steps (JSON)
safety-dataclaw auth <API_KEY>                    # Authenticate with TRACED API key
safety-dataclaw prep                              # Discover projects, check auth (JSON)
safety-dataclaw prep --source all                 # All sources (Claude + Codex + Gemini + OpenCode)
safety-dataclaw prep --source claude              # Only Claude Code sessions
safety-dataclaw prep --source codex               # Only Codex sessions
safety-dataclaw prep --source gemini              # Only Gemini CLI sessions
safety-dataclaw prep --source opencode            # Only OpenCode sessions
safety-dataclaw confirm --full-name "NAME" --attest-full-name "..." --attest-sensitive "..." --attest-manual-scan "..." # Scan PII, verify attestations, unlock uploading (JSON)
safety-dataclaw confirm --file /path/to/file.jsonl --full-name "NAME" --attest-full-name "..." --attest-sensitive "..." --attest-manual-scan "..." # Confirm a specific export file
safety-dataclaw list                              # List all projects with exclusion status
safety-dataclaw list --source all                 # List all sources
safety-dataclaw list --source codex               # List only Codex projects
safety-dataclaw config                            # Show current config
safety-dataclaw config --source all               # REQUIRED source scope: claude|codex|gemini|opencode|all
safety-dataclaw config --exclude "a,b"            # Add excluded projects (appends)
safety-dataclaw config --redact "str1,str2"       # Add strings to redact (appends)
safety-dataclaw config --redact-usernames "u1,u2" # Add usernames to anonymize (appends)
safety-dataclaw config --confirm-projects         # Mark project selection as confirmed
safety-dataclaw upload                            # Upload to TRACED (requires safety-dataclaw confirm first)
safety-dataclaw export --no-push                  # Export locally only
safety-dataclaw export --source all --no-push     # Export all sources locally
safety-dataclaw export --source codex --no-push   # Export only Codex sessions
safety-dataclaw export --source claude --no-push  # Export only Claude Code sessions
safety-dataclaw export --source gemini --no-push  # Export only Gemini CLI sessions
safety-dataclaw export --source opencode --no-push # Export only OpenCode sessions
safety-dataclaw export --all-projects             # Include everything (ignore exclusions)
safety-dataclaw export --no-thinking              # Exclude extended thinking blocks
safety-dataclaw export -o /path/to/file.jsonl     # Custom output path
safety-dataclaw update-skill claude               # Install/update the safety-dataclaw skill for Claude Code
```

## Gotchas

- **`--exclude`, `--redact`, `--redact-usernames` APPEND** — they never overwrite. Safe to call repeatedly.
- **Source selection is REQUIRED before export** — explicitly set `safety-dataclaw config --source claude|codex|gemini|opencode|all` (or pass `--source ...` on export).
- **`safety-dataclaw prep` outputs pure JSON** — parse it directly.
- **Always export with `--no-push` first** — review before uploading.
- **`safety-dataclaw upload` requires `safety-dataclaw confirm` first** — it will refuse otherwise. Re-exporting with `--no-push` resets this.
- **PII audit is critical** — automated redaction is not foolproof.
- **Large exports take time** — 500+ sessions may take 1-3 minutes. Use a generous timeout.

## Install

```bash
pip install safety-dataclaw
```
