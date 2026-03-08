"""Interactive menus for trace-sanitizer — project and session selection."""

import sys
from typing import Any


def _format_size(size_bytes: int) -> str:
    if size_bytes >= 1_000_000:
        return f"{size_bytes / 1_000_000:.1f} MB"
    if size_bytes >= 1_000:
        return f"{size_bytes / 1_000:.1f} KB"
    return f"{size_bytes} B"


def _format_time(ts: str | None) -> str:
    if not ts:
        return "unknown date"
    # Handle ISO format timestamps — show just date + time
    return ts[:16].replace("T", " ")


def pick_project(projects: list[dict]) -> dict:
    """Show numbered project list, return selected project dict. Exits on cancel."""
    print("\nSelect a project:\n")
    for i, p in enumerate(projects, 1):
        source = p.get("source", "claude")
        sessions = p["session_count"]
        size = _format_size(p["total_size_bytes"])
        print(f"  {i:>3})  {p['display_name']}  ({source})  —  {sessions} sessions, {size}")

    print(f"\n    0)  Cancel\n")
    return _prompt_choice(projects)


def pick_session(sessions: list[dict[str, Any]], project_name: str) -> dict[str, Any]:
    """Show numbered session list, return selected session dict. Exits on cancel."""
    print(f"\nSessions in {project_name}:\n")
    for i, s in enumerate(sessions, 1):
        time_str = _format_time(s.get("start_time"))
        model = s.get("model") or "unknown model"
        msgs = s.get("message_count", "?")
        size = _format_size(s.get("size_bytes", 0))
        print(f"  {i:>3})  {time_str}  {model}  ~{msgs} messages  ({size})")

    print(f"\n    0)  Cancel\n")
    return _prompt_choice(sessions)


def confirm_tool_outputs() -> bool:
    """Ask the user whether to include tool outputs. Returns True/False."""
    print("\nInclude tool outputs (file contents, bash stdout, grep results)?")
    print("This provides richer data but increases export size. Secrets are still redacted.\n")
    while True:
        try:
            raw = input("Include tool outputs? [Y/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        if raw in ("", "y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print("  Enter y or n.")


def _prompt_choice(items: list) -> Any:
    """Prompt until a valid choice is made. Exit on 0 or EOF."""
    n = len(items)
    while True:
        try:
            raw = input(f"Choice [1-{n}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        if not raw:
            continue
        try:
            choice = int(raw)
        except ValueError:
            print(f"  Enter a number between 0 and {n}.")
            continue
        if choice == 0:
            sys.exit(0)
        if 1 <= choice <= n:
            return items[choice - 1]
        print(f"  Enter a number between 0 and {n}.")
