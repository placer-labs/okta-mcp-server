#!/usr/bin/env python3
"""Merge open Dependabot PRs once CI is green and every bumped release is old enough.

A PR is merged only when all of these hold:
  * every pull_request workflow run on its head commit finished successfully;
  * every updated dependency is a semver patch or minor bump;
  * every new version was published at least MIN_AGE_DAYS ago (release-age
    cooldown; applies to security updates too, which Dependabot's own
    `cooldown` setting does not cover).

Anything that cannot be verified (unknown ecosystem, missing publish date,
major bump) is left for a human. Merges made with GITHUB_TOKEN do not trigger
push workflows, so after merging the script dispatches POST_MERGE_WORKFLOW.

Env: GH_TOKEN, REPO, MERGE_METHOD (merge|squash|rebase), MIN_AGE_DAYS,
POST_MERGE_WORKFLOW (optional), DRY_RUN (optional, "true" to only report).
"""

import json
import os
import re
import subprocess  # ruff: ignore[suspicious-subprocess-import] - only runs the gh CLI with argument lists
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

REPO = os.environ["REPO"]
MERGE_METHOD = os.environ.get("MERGE_METHOD", "squash")
MIN_AGE = timedelta(days=int(os.environ.get("MIN_AGE_DAYS", "7")))
POST_MERGE_WORKFLOW = os.environ.get("POST_MERGE_WORKFLOW", "")
DRY_RUN = os.environ.get("DRY_RUN", "").lower() == "true"
NOW = datetime.now(timezone.utc)

ALLOWED_UPDATE_TYPES = {"version-update:semver-patch", "version-update:semver-minor"}
OK_CONCLUSIONS = {"success", "skipped", "neutral"}


def gh(*args: str) -> str:
    # gh is on PATH on GitHub runners; args are passed as a list, never through a shell.
    return subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]
        ["gh", *args],  # ruff: ignore[start-process-with-partial-path]
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def gh_json(*args: str):
    return json.loads(gh(*args))


def http_json(url: str):
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "dependabot-automerge"})  # ruff: ignore[suspicious-url-open-usage]
    with urllib.request.urlopen(req, timeout=30) as resp:  # ruff: ignore[suspicious-url-open-usage]
        return json.load(resp)


def parse_time(value: str) -> datetime:
    value = re.sub(r"(\.\d{6})\d+", r"\1", value.replace("Z", "+00:00"))
    return datetime.fromisoformat(value)


def parse_updated_dependencies(message: str) -> list[dict]:
    """Parse the YAML metadata block Dependabot appends to its commit message."""
    deps, current = [], None
    in_block = False
    for line in message.splitlines():
        if line.startswith("updated-dependencies:"):
            in_block = True
            continue
        if not in_block:
            continue
        if line.startswith("..."):
            break
        m = re.match(r"^(- |  )([\w-]+): ?(.*)$", line)
        if not m:
            continue
        if m.group(1) == "- ":
            current = {}
            deps.append(current)
        if current is not None:
            current[m.group(2)] = m.group(3).strip().strip("'\"")
    return deps


def go_escape(path: str) -> str:
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), path)


def published_at(ecosystem: str, name: str, version: str) -> datetime | None:
    try:
        if ecosystem == "go_modules":
            v = version if version.startswith("v") else "v" + version
            info = http_json(f"https://proxy.golang.org/{go_escape(name)}/@v/{go_escape(v)}.info")
            return parse_time(info["Time"])
        if ecosystem in ("uv", "pip"):
            data = http_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json")
            times = [parse_time(u["upload_time_iso_8601"]) for u in data.get("urls", [])]
            return min(times) if times else None
        if ecosystem == "github_actions":
            repo = "/".join(name.split("/")[:2])
            for tag in (version, "v" + version.lstrip("v")):
                try:
                    rel = gh_json("api", f"repos/{repo}/releases/tags/{tag}")
                    return parse_time(rel["published_at"])
                except subprocess.CalledProcessError:
                    pass
                try:
                    commit = gh_json("api", f"repos/{repo}/commits/{tag}")
                    return parse_time(commit["commit"]["committer"]["date"])
                except subprocess.CalledProcessError:
                    pass
    except (urllib.error.URLError, KeyError, ValueError) as exc:
        print(f"    lookup failed for {name}@{version}: {exc}")
    return None


def ci_green(sha: str) -> tuple[bool, str]:
    runs = gh_json("api", f"repos/{REPO}/actions/runs?head_sha={sha}&event=pull_request&per_page=100")["workflow_runs"]
    if not runs:
        return False, "no CI runs yet"
    # Keep only the newest run of each workflow (the API reports its latest attempt).
    latest = {}
    for run in runs:
        prev = latest.get(run["workflow_id"])
        if prev is None or run["id"] > prev["id"]:
            latest[run["workflow_id"]] = run
    pending = [r["name"] for r in latest.values() if r["status"] != "completed"]
    if pending:
        return False, f"CI still running: {', '.join(pending)}"
    failed = [r["name"] for r in latest.values() if r["conclusion"] not in OK_CONCLUSIONS]
    if failed:
        return False, f"CI failed: {', '.join(failed)}"
    return True, f"{len(latest)} workflows green"


def evaluate(pr: dict) -> tuple[bool, str]:
    if pr["isDraft"]:
        return False, "draft"
    if pr["mergeable"] == "CONFLICTING":
        return False, "has conflicts (Dependabot will rebase)"
    m = re.match(r"dependabot/([^/]+)/", pr["headRefName"])
    if not m:
        return False, "unrecognised branch name"
    ecosystem = m.group(1)

    commit = gh_json("api", f"repos/{REPO}/commits/{pr['headRefOid']}")
    deps = parse_updated_dependencies(commit["commit"]["message"])
    if not deps:
        return False, "no dependency metadata in commit message"

    for dep in deps:
        name, version = dep.get("dependency-name"), dep.get("dependency-version")
        update_type = dep.get("update-type")
        if update_type not in ALLOWED_UPDATE_TYPES:
            return False, f"{name}: update type {update_type!r} needs a human"
        if not version:
            return False, f"{name}: no target version in metadata"
        when = published_at(ecosystem, name, version)
        if when is None:
            return False, f"{name}@{version}: publish date unknown"
        age = NOW - when
        if age < MIN_AGE:
            return False, f"{name}@{version}: only {age.days}d old (< {MIN_AGE.days}d)"
        print(f"    {name}@{version}: {age.days}d old, {update_type}")

    return ci_green(pr["headRefOid"])


def main() -> int:
    prs = gh_json(
        "pr",
        "list",
        "-R",
        REPO,
        "--author",
        "app/dependabot",
        "--state",
        "open",
        "--json",
        "number,title,headRefName,headRefOid,isDraft,mergeable,reviewDecision",
    )
    merged = 0
    for pr in prs:
        print(f"#{pr['number']} {pr['title']}")
        ok, reason = evaluate(pr)
        print(f"  -> {'MERGE' if ok else 'skip'}: {reason}")
        if not ok or DRY_RUN:
            continue
        num, sha = str(pr["number"]), pr["headRefOid"]
        try:
            if pr["reviewDecision"] != "APPROVED":
                gh(
                    "pr",
                    "review",
                    num,
                    "-R",
                    REPO,
                    "--approve",
                    "--body",
                    f"Auto-approved: CI green, patch/minor bump, releases >= {MIN_AGE.days} days old.",
                )
            gh("pr", "merge", num, "-R", REPO, f"--{MERGE_METHOD}", "--match-head-commit", sha)
            merged += 1
        except subprocess.CalledProcessError as exc:
            print(f"  !! merge failed: {exc.stderr.strip()}")

    if merged and POST_MERGE_WORKFLOW:
        default_branch = gh_json("api", f"repos/{REPO}")["default_branch"]
        gh("workflow", "run", POST_MERGE_WORKFLOW, "-R", REPO, "--ref", default_branch)
        print(f"Dispatched {POST_MERGE_WORKFLOW} on {default_branch}")
    print(f"Merged {merged} PR(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
