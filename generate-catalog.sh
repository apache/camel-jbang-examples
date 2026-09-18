#!/usr/bin/env bash
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# Generates camel-jbang-example-catalog.json from metadata.json files.
#
# Usage: ./generate-catalog.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CATALOG_FILE="$SCRIPT_DIR/camel-jbang-example-catalog.json"

python3 - "$SCRIPT_DIR" "$CATALOG_FILE" << 'PYEOF'
import json
import os
import sys

repo_root = sys.argv[1]
catalog_file = sys.argv[2]

SKIP_FILES = {
    "metadata.json",
    "compose.yaml", "docker-compose.yaml",
    ".gitignore", ".DS_Store"
}
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".excalidraw", ".iml"
}

catalog = []

for dirpath, dirnames, filenames in sorted(os.walk(repo_root)):
    # skip hidden directories
    dirnames[:] = [d for d in dirnames if not d.startswith(".")]

    if "metadata.json" not in filenames:
        continue

    meta_path = os.path.join(dirpath, "metadata.json")
    with open(meta_path) as f:
        meta = json.load(f)

    if meta.get("exclude", False):
        continue

    name = os.path.relpath(dirpath, repo_root)

    SKIP_DIRS = {"test", "target", "node_modules"}

    # collect example files recursively (skip metadata/readme/images/hidden/test dirs)
    files = []
    for sub_dirpath, sub_dirnames, sub_filenames in os.walk(dirpath):
        sub_dirnames[:] = [
            d for d in sub_dirnames
            if not d.startswith(".") and d not in SKIP_DIRS
        ]
        # skip subdirs that have their own metadata.json (they are separate examples)
        sub_dirnames[:] = [
            d for d in sub_dirnames
            if not os.path.exists(os.path.join(sub_dirpath, d, "metadata.json"))
        ]
        for f in sub_filenames:
            if (f not in SKIP_FILES
                    and not f.startswith(".")
                    and os.path.splitext(f)[1].lower() not in SKIP_EXTENSIONS):
                rel = os.path.relpath(os.path.join(sub_dirpath, f), dirpath)
                files.append(rel)
    files.sort()

    requires_docker = ("compose.yaml" in filenames or "docker-compose.yaml" in filenames
                       or len(meta.get("infraServices", [])) > 0)

    # detect Citrus integration tests (also in sub-directories without own metadata)
    has_citrus_tests = False
    for sub_dirpath2, sub_dirnames2, sub_filenames2 in os.walk(dirpath):
        sub_dirnames2[:] = [
            d for d in sub_dirnames2
            if not d.startswith(".") and d not in {"target", "node_modules"}
            and not os.path.exists(os.path.join(sub_dirpath2, d, "metadata.json"))
        ]
        if os.path.basename(sub_dirpath2) == "test":
            if any(f.endswith(".citrus.it.yaml") or f.endswith(".citrus.it.xml")
                   for f in sub_filenames2):
                has_citrus_tests = True
                break

    entry = {
        "name": name,
        "title": meta["title"],
        "description": meta["description"],
        "level": meta.get("level", "intermediate"),
        "teaches": meta.get("teaches", {}),
        "tags": meta.get("tags", []),
        "bundled": meta.get("bundled", False),
        "requiresDocker": requires_docker,
        "hasCitrusTests": has_citrus_tests,
        "files": files,
    }
    if "infraServices" in meta:
        entry["infraServices"] = meta["infraServices"]
    if meta.get("ciSkip", False):
        entry["ciSkip"] = True
    if "order" in meta:
        entry["order"] = meta["order"]
    catalog.append(entry)

with open(catalog_file, "w") as f:
    json.dump(catalog, f, indent=4)
    f.write("\n")

print(f"Generated {catalog_file} with {len(catalog)} examples")

# render the example tables of README.md, between the markers, one table per group in ladder order
GROUPS = [
    ("quick-start", "Quick start", "The first ten minutes: generic examples with no story and no service, each running in seconds."),
    ("run", "Run", "Running Camel: timers and cron schedules, a bean in a route, properties and profiles."),
    ("transform", "Transform and map", "JSON, XML and CSV in and out, field-by-field mapping, Groovy and XSLT."),
    ("route", "Route", "The routing patterns: content-based router, splitter, aggregator, filter and multicast."),
    ("fail-well", "Fail well", "Retries, a dead letter channel, and a circuit breaker in front of a flaky service."),
    ("connect", "Connect without a service", "Files, an HTTP client and a REST server; everything runs inside the example."),
    ("connect-service", "Connect to one service", "SQL, JMS, MQTT, Kafka and FTP against a service the Camel CLI starts for you with `camel infra run`."),
    ("contracts", "Contracts and security", "An OpenAPI contract served and called, and an API protected by Keycloak."),
    ("ai", "AI", "A local model writing text, routes exposed as MCP tools, RAG over documents, PII redaction."),
    ("cloud", "Cloud", "A cloud service, run locally through LocalStack and switched to the real thing by properties."),
    ("showcase", "Showcase", "Tooling demos outside the ladder: the TUI, a memory leak, message sizes, log analysis."),
]
by_level = {}
for e in catalog:
    by_level.setdefault(e["level"], []).append(e)

def by_order(e):
    return (e.get("order", 999), e["name"])

def table(entries, link_prefix):
    rows = ["| Example | What you will see | Needs |", "|---|---|---|"]
    for e in entries:
        short = e["name"].split("/", 1)[1] if "/" in e["name"] else e["name"]
        link = link_prefix + e["name"] + "/" if link_prefix is not None else short + "/"
        rows.append(f"| [{e['title']}]({link}) | {e['description']} | {needs(e)} |")
    return rows

def needs(e):
    parts = []
    if e.get("infraServices"):
        parts.append("`camel infra run " + " ".join(e["infraServices"]) + "`")
    if e.get("ciSkip"):
        parts.append("a local model")
    return ", ".join(parts) if parts else "nothing"

lines = []
for level, title, intro in GROUPS:
    entries = sorted(by_level.get(level, []), key=by_order)
    if not entries:
        continue
    lines.append(f"### [{title}]({level}/)")
    lines.append("")
    lines.append(intro)
    lines.append("")
    lines.extend(table(entries, ""))
    lines.append("")

    # the group's own README: title, intro and its examples in reading order, between markers so
    # prose outside them survives; created when missing
    group_readme = os.path.join(repo_root, level, "README.md")
    gstart, gend = "<!-- group:start -->", "<!-- group:end -->"
    body = [intro, ""]
    body.extend(table(entries, None))
    body.append("")
    first = entries[0]
    first_short = first["name"].split("/", 1)[1]
    if len(entries) == 1:
        body.append(f"Start with [{first['title']}]({first_short}/).")
    elif level in ("quick-start", "showcase"):
        body.append(f"Start with [{first['title']}]({first_short}/); the others stand on their own, in any order.")
    else:
        body.append(f"Start with [{first['title']}]({first_short}/); the examples read best in the order above, "
                    f"each one building on what the one before it set up.")
    body.append("")
    body.append("Every example has a README that says what you will see, how it works, how to build it step by step, "
                "what to try changing, and how to run its test with `camel test run`.")
    if os.path.exists(group_readme):
        g = open(group_readme).read()
        if gstart in g and gend in g:
            a2 = g.index(gstart) + len(gstart)
            b2 = g.index(gend)
            g = g[:a2] + "\n" + "\n".join(body) + "\n" + g[b2:]
        else:
            g = g.rstrip("\n") + "\n\n" + gstart + "\n" + "\n".join(body) + "\n" + gend + "\n"
    else:
        g = f"# {title}\n\n{gstart}\n" + "\n".join(body) + f"\n{gend}\n"
    open(group_readme, "w").write(g)
readme_path = os.path.join(repo_root, "README.md")
readme = open(readme_path).read()
start, end = "<!-- examples:start -->", "<!-- examples:end -->"
if start in readme and end in readme:
    a = readme.index(start) + len(start)
    b = readme.index(end)
    readme = readme[:a] + "\n" + "\n".join(lines) + readme[b:]
    open(readme_path, "w").write(readme)
    print(f"Updated the example tables in {readme_path}")
PYEOF
