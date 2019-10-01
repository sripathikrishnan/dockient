#!/bin/sh
files=$(git diff --cached --name-only --diff-filter=ACMR | grep -Ei "\.py$")

if [ ! -z "${files}" ]; then
    echo "Formatting modified python files using black before committing them ..."
    black --exclude venv $files
    git add $(echo "$files" | paste -s -d " " -)
fi
