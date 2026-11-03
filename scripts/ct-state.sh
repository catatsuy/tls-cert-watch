#!/usr/bin/env bash
set -euo pipefail
mode=${1:?load or save}
state=${CT_STATE_FILE:?}
case "$mode" in
  load)
    # Distinguish a missing branch from authentication/network failures.
    git ls-remote --heads origin refs/heads/ct-state > "$RUNNER_TEMP/ct-remote"
    if [[ -s "$RUNNER_TEMP/ct-remote" ]]; then
      git fetch --no-tags origin refs/heads/ct-state
      git rev-parse FETCH_HEAD > "$RUNNER_TEMP/ct-parent"
      # A missing/corrupt state on an existing branch is always an error.
      git show FETCH_HEAD:ct-state.json > "$state"
    else
      [[ "${CT_INITIALIZE:-false}" == true ]] || { echo 'ct-state branch missing; explicit initialization required' >&2; exit 1; }
      : > "$RUNNER_TEMP/ct-parent"
    fi
    ;;
  save)
    parent=$(cat "$RUNNER_TEMP/ct-parent")
    blob=$(git hash-object -w "$state")
    if [[ -n "$parent" ]] && [[ "$blob" == "$(git rev-parse "$parent:ct-state.json")" ]]; then
      echo 'No cursor changes; no commit'
      exit 0
    fi
    export GIT_INDEX_FILE="$RUNNER_TEMP/ct-index"
    rm -f "$GIT_INDEX_FILE"
    if [[ -n "$parent" ]]; then git read-tree "$parent"; else git read-tree --empty; fi
    git update-index --add --cacheinfo "100644,$blob,ct-state.json"
    tree=$(git write-tree)
    export GIT_AUTHOR_NAME='github-actions[bot]' GIT_COMMITTER_NAME='github-actions[bot]'
    export GIT_AUTHOR_EMAIL='41898282+github-actions[bot]@users.noreply.github.com' GIT_COMMITTER_EMAIL='41898282+github-actions[bot]@users.noreply.github.com'
    if [[ -n "$parent" ]]; then
      commit=$(git commit-tree "$tree" -p "$parent" -m 'Update CT cursors or acquisition checkpoint')
    else
      commit=$(git commit-tree "$tree" -m 'Create CT acquisition state')
    fi
    # Normal fast-forward push: never overwrite concurrent/out-of-band updates.
    git push origin "$commit:refs/heads/ct-state"
    ;;
  *) exit 2 ;;
esac
