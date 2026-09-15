# CLAUDE.md

Guidance for coding agents (Claude Code and similar) working in this repository.

## What this is

A DNS/TLS/WHOIS/blocklist watchdog written in Go, published as a GitHub Action
(`daigotanaka0714/dns-watchdog@v1`). It is in production use, so treat changes
to the checkers and the notifier as changes to something people rely on.

## Language

This is a public repository. Write code, comments, commit messages, PR text and
documentation in English.

The Japanese strings in `labels.go` are the `ja` locale of the notification
labels. They are a feature, not a leftover - do not "clean them up".

## Before you start

Run `./bin/agent-check`. It is plain bash and needs only Go and, optionally,
golangci-lint - no editor or agent tooling. `.github/workflows/ci.yml` runs the
same checks in the same order, so a local PASS predicts a green CI run.

Versions have exactly one source of truth: `go.mod` for Go (the workflows read
it via `go-version-file`) and `.config/agent-check.env` for the golangci-lint
version (the gate and CI both read it). Do not write a version anywhere else.

<!-- daigo-lab-ops:completion-criteria:start -->
<!-- 自動生成。daigo-lab-ops/docs/completion-criteria.md が唯一の出どころ。
     ここを手で編集しない。`lab sync` で作り直す。 -->

## エージェントの完了条件

### Definition of done

1. This repository's `bin/agent-check` returns `STATUS: PASS`
2. The change stays within what was asked for
3. The PR is opened from a branch other than main / master

### Do not

- **Never push directly to the default branch.** Always branch and open a PR.
- **Never merge.** `git merge` and `gh pr merge` are a human's job.
- **Never edit the gate to make it pass.** If the gate needs to be relaxed,
  propose that as its own PR and explain why.
- **Never silence a lint rule to get green.** Fix what it reports.

### When opening a PR

- Do not put a Claude session URL (`claude.ai/code/session_...`) or a
  `Claude-Session:` line in the PR body or in any commit message
- **Always name the repository and include the URL when referring to a PR.**
  `#24` alone does not identify anything when several repositories are in play
- Stacked PRs: before merging the base PR, re-target the one stacked on top of
  it to the default branch first (`gh pr edit <n> --base main`). Merging the
  base deletes its branch, and that takes the stacked PR with it. Most of these
  repositories delete the branch on merge automatically, so this is a step you
  have to take, not an option you can decline

<!-- daigo-lab-ops:completion-criteria:end -->
