#!/usr/bin/env python3
"""
VibeSecurity CLI — Automated Security Validator for AI-Generated Code
Designed for CI/CD Pipelines (GitHub Actions, GitLab CI, Jenkins) and local git hooks.
"""

import os
import sys
import argparse
import json
from pathlib import Path
import logging

# Silence background library loggers for clean terminal output
logging.disable(logging.INFO)
try:
    from loguru import logger
    logger.remove()
except Exception:
    pass

# Force UTF-8 on Windows terminal to avoid charmap UnicodeEncodeErrors
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure backend root is on sys.path
CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

try:
    from scanner.code_analyzer import analyze_api_route
except ImportError:
    # If called from repo root
    sys.path.insert(0, str(CURRENT_DIR.parent / "backend"))
    from scanner.code_analyzer import analyze_api_route

# ANSI Colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

SUPPORTED_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".py", ".mjs", ".cjs"}
IGNORE_DIRS = {
    "node_modules", ".git", ".next", "dist", "build", "venv", ".venv",
    "__pycache__", ".turbo", "coverage", ".idea", ".vscode", "scanner", "tests", "mock"
}


def scan_file(file_path: Path):
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        return []

    # Run 30+ CWE rules
    findings = analyze_api_route(content)
    # Filter out placeholder info findings
    real_findings = [f for f in findings if f.get("id") != "api_looks_ok"]
    for f in real_findings:
        f["file"] = str(file_path)
    return real_findings


def scan_directory(target_dir: Path, exclude_dirs: set = None):
    all_findings = []
    total_files = 0
    ignore_set = set(IGNORE_DIRS)
    if exclude_dirs:
        ignore_set.update(exclude_dirs)

    for root, dirs, files in os.walk(target_dir):
        # Prune ignored directories in-place
        dirs[:] = [d for d in dirs if d not in ignore_set]

        for file in files:
            p = Path(root) / file
            if p.suffix.lower() in SUPPORTED_EXTENSIONS:
                total_files += 1
                findings = scan_file(p)
                all_findings.extend(findings)

    return all_findings, total_files


def install_git_hook():
    # Find .git directory
    curr = Path.cwd()
    found_git = None
    for p in [curr, *curr.parents]:
        if (p / ".git").is_dir():
            found_git = p / ".git"
            break

    if not found_git:
        print(f"{RED}Error: .git directory not found. Please run this inside a git repository.{RESET}")
        sys.exit(1)

    hooks_dir = found_git / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    pre_push_file = hooks_dir / "pre-push"

    hook_content = (
        "#!/bin/sh\n"
        "# VibeSecurity automated pre-push security validator\n"
        "echo \"\\033[96m\\033[1m🛡️  [VibeSecurity]\\033[0m Scanning AI-generated code before git push...\"\n"
        "python backend/cli.py . --fail-on high\n"
        "STATUS=$?\n"
        "if [ $STATUS -ne 0 ]; then\n"
        "    echo \"\\033[91m\\033[1m❌ [VibeSecurity] Push aborted! Fix security vulnerabilities before pushing.\\033[0m\"\n"
        "    exit 1\n"
        "fi\n"
        "exit 0\n"
    )

    try:
        pre_push_file.write_text(hook_content, encoding="utf-8")
        import stat
        pre_push_file.chmod(pre_push_file.stat().st_mode | stat.S_IEXEC)
        print(f"\n{GREEN}{BOLD}✅ Success! VibeSecurity pre-push hook installed:{RESET} {pre_push_file}")
        print(f"{CYAN}From now on, whenever anyone runs '{BOLD}git push{RESET}{CYAN}', your terminal will:{RESET}")
        print(f"  1. Automatically scan all source files for OWASP Top 10 & CWE Top 25 AI security vulnerabilities.")
        print(f"  2. Print the exact line & suggested fix directly in your terminal.")
        print(f"  3. Abort the push if Critical or High security issues exist.\n")
    except Exception as e:
        print(f"{RED}Error writing git hook: {e}{RESET}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="VibeSecurity CI/CD — Automated Security Validator for AI-Generated Code"
    )
    parser.add_argument("path", nargs="?", default=".", help="Directory or file to scan (default: .)")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], default="high",
                        help="Minimum severity level that causes CI pipeline to exit with error (default: high)")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON for CI/CD artifacts")
    parser.add_argument("--output", default=None, help="Save report to file path (e.g. security-report.json)")

    parser.add_argument("--exclude", default="",
                        help="Comma-separated folder names or paths to ignore (e.g. tests,docs)")
    parser.add_argument("--changed-only", action="store_true",
                        help="Scan only the files modified in the latest git commit")
    parser.add_argument("--install-hook", action="store_true",
                        help="Install a local git pre-push hook in the current repository to scan and block insecure code")

    args = parser.parse_args()

    if args.install_hook:
        install_git_hook()
        return

    target_path = Path(args.path).resolve()

    if not target_path.exists():
        print(f"{RED}Error: Target path '{args.path}' does not exist.{RESET}", file=sys.stderr)
        sys.exit(2)

    if not args.json:
        print(f"\n{BOLD}{CYAN}======================================================{RESET}")
        print(f"{BOLD}{CYAN}🛡️  VIBESECURITY CI/CD AI CODE VALIDATOR{RESET}")
        print(f"{CYAN}   Scanning: {target_path}{RESET}")
        print(f"{BOLD}{CYAN}======================================================{RESET}\n")

    exclude_set = {x.strip() for x in args.exclude.split(",") if x.strip()} if args.exclude else set()

    # In CI/CD git environments (e.g. GitHub Actions), scan only the files modified in this push
    changed_mode = False
    if os.getenv("GITHUB_SHA") or os.getenv("CI") or getattr(args, "changed_only", False):
        try:
            import subprocess
            out = subprocess.check_output(
                ["git", "log", "-1", "--name-only", "--pretty="],
                stderr=subprocess.DEVNULL,
                text=True
            )
            raw_files = [f.strip() for f in out.splitlines() if f.strip()]
            if raw_files:
                changed_mode = True
                findings = []
                total_files = 0
                for rf in raw_files:
                    p = Path(rf)
                    if any(part in IGNORE_DIRS for part in p.parts):
                        continue
                    if p.name.startswith("mock_") or p.name.startswith("test_"):
                        continue
                    if p.is_file() and p.suffix.lower() in SUPPORTED_EXTENSIONS:
                        total_files += 1
                        findings.extend(scan_file(p))
                    elif p.is_file():
                        total_files += 1
                if not args.json:
                    print(f"📦 Git commit changed files: {len(raw_files)} files detected in push.")
        except Exception:
            changed_mode = False

    if not changed_mode:
        if target_path.is_file():
            findings = scan_file(target_path)
            total_files = 1
        else:
            findings, total_files = scan_directory(target_path, exclude_dirs=exclude_set)

    critical_count = sum(1 for f in findings if f.get("severity") == "critical")
    high_count = sum(1 for f in findings if f.get("severity") == "high")
    medium_count = sum(1 for f in findings if f.get("severity") == "medium")
    low_count = sum(1 for f in findings if f.get("severity") == "low")

    report_data = {
        "status": "failed" if (critical_count > 0 or high_count > 0) else "passed",
        "total_files_scanned": total_files,
        "total_vulnerabilities": len(findings),
        "critical": critical_count,
        "high": high_count,
        "medium": medium_count,
        "low": low_count,
        "findings": findings
    }

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as out_f:
                json.dump(report_data, out_f, indent=2)
            if not args.json:
                print(f"📄 Report saved to: {args.output}")
        except Exception as e:
            print(f"{YELLOW}Warning: Failed to save output file: {e}{RESET}")

    if args.json:
        print(json.dumps(report_data, indent=2))
        notify_realtime_stream(critical_count, high_count, findings, total_files)
        _check_exit(critical_count, high_count, medium_count, args.fail_on)
        return

    # Terminal output
    if findings:
        print(f"{BOLD}Found {len(findings)} potential security issues in {total_files} files:{RESET}\n")
        for idx, f in enumerate(findings, 1):
            sev = f.get("severity", "medium").upper()
            color = RED if sev in ["CRITICAL", "HIGH"] else YELLOW
            file_name = f.get("file", "unknown")
            try:
                rel_file = os.path.relpath(file_name, target_path)
            except ValueError:
                rel_file = file_name

            print(f"{idx}. {color}[{sev}]{RESET} {BOLD}{f.get('name')}{RESET}")
            print(f"   📁 File:     {CYAN}{rel_file}{RESET}")
            print(f"   🏷️  Category: {f.get('category')}")
            if f.get("evidence"):
                print(f"   🔍 Evidence: {f.get('evidence').strip()}")
            if f.get("fix"):
                fix_lines = f.get("fix").strip().split("\n")
                first_line = fix_lines[0] if fix_lines else ""
                print(f"   💡 Suggested Fix: {GREEN}{first_line}{RESET}")
            print()

        print(f"------------------------------------------------------")
        print(f"Summary: {RED}{critical_count} Critical{RESET} | {YELLOW}{high_count} High{RESET} | {medium_count} Medium | {total_files} files scanned")
    else:
        print(f"{GREEN}✅ Clean Code! 0 security vulnerabilities found across {total_files} files.{RESET}")
        print(f"{GREEN}   Passed all 30+ CWE Top 25 & OWASP automated checks.{RESET}\n")

    notify_realtime_stream(critical_count, high_count, findings, total_files)
    _check_exit(critical_count, high_count, medium_count, args.fail_on)


def notify_realtime_stream(critical_count: int, high_count: int, findings: list, total_files: int):
    """
    Broadcasts CI/CD push results to VibeSecurity web Dashboard in real-time
    via Supabase Realtime WebSocket broadcast.
    """
    try:
        import subprocess
        import time

        is_safe = (critical_count == 0 and high_count == 0)
        repo = os.getenv("GITHUB_REPOSITORY", "Aryan544-byte/VibeSecurity")
        branch = os.getenv("GITHUB_REF_NAME", "main")
        committer = os.getenv("GITHUB_ACTOR", "Aryan544-byte")
        
        inc_id = f"PUSH-{int(time.time()) % 10000}" if is_safe else f"INC-{int(time.time()) % 10000}"

        if is_safe:
            threat = f"Clean code push ({total_files} files scanned) — All 30+ AST heuristics passed, zero security issues"
            cwe = None
        else:
            first_f = findings[0] if findings else {}
            cwe = first_f.get("cwe", "CWE-Security")
            threat = f"{cwe}: {first_f.get('name', 'Vulnerability detected')} in {first_f.get('file', 'code')}"

        incident_payload = {
            "id": inc_id,
            "type": "safe" if is_safe else "malicious",
            "threat": threat,
            "repo": repo,
            "branch": branch,
            "committer": committer,
            "time": "Just now",
            "cwe": cwe
        }

        # 1. Primary: Deliver via notify_realtime.js WebSocket connection
        script_path = Path(__file__).resolve().parent / "notify_realtime.js"
        if script_path.exists():
            try:
                import base64
                b64_payload = base64.b64encode(json.dumps(incident_payload).encode("utf-8")).decode("ascii")
                res = subprocess.run(
                    ["node", str(script_path), b64_payload],
                    capture_output=True,
                    text=True,
                    timeout=8
                )
                if res.returncode == 0:
                    print(f"{CYAN}📡 [Realtime Sync] WebSocket broadcast delivered to Dashboard ({inc_id}){RESET}")
                else:
                    print(f"[Realtime Sync] Node script failed: {res.stderr.strip() or res.stdout.strip()}")
            except Exception as e:
                print(f"[Realtime Sync] Process error: {e}")

        # 2. Secondary fallback: HTTP broadcast
        payload = {
            "messages": [
                {
                    "topic": "realtime:vibeguard_live_interceptions",
                    "event": "broadcast",
                    "payload": {
                        "type": "broadcast",
                        "event": "live_incident",
                        "payload": incident_payload
                    }
                }
            ]
        }
        import urllib.request
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            "https://odqoobyxovzqzxhevnaq.supabase.co/realtime/v1/api/broadcast",
            data=data,
            headers={
                "apikey": "sb_publishable_RvzfDniw_RHlWszb-Con3w_ujbl6e_M",
                "Content-Type": "application/json"
            }
        )
        urllib.request.urlopen(req, timeout=4)
        print(f"{CYAN}📡 [Realtime Sync] Broadcast sent to VibeSecurity Dashboard ({inc_id}){RESET}")
    except Exception:
        pass


def _check_exit(critical, high, medium, fail_on):
    fail = False
    if fail_on == "critical" and critical > 0:
        fail = True
    elif fail_on == "high" and (critical > 0 or high > 0):
        fail = True
    elif fail_on == "medium" and (critical > 0 or high > 0 or medium > 0):
        fail = True

    if fail:
        print(f"\n{RED}{BOLD}❌ CI/CD PIPELINE BLOCKED:{RESET} Insecure AI-generated code detected.")
        print(f"Fix the {critical + high} critical/high issues above before merging or deployment.\n")
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
