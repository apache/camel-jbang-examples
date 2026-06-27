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
        "tags": meta.get("tags", []),
        "bundled": meta.get("bundled", False),
        "requiresDocker": requires_docker,
        "hasCitrusTests": has_citrus_tests,
        "files": files,
    }
    if "infraServices" in meta:
        entry["infraServices"] = meta["infraServices"]
    catalog.append(entry)

with open(catalog_file, "w") as f:
    json.dump(catalog, f, indent=4)
    f.write("\n")

print(f"Generated {catalog_file} with {len(catalog)} examples")
PYEOF
