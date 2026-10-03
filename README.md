# AccessLens

AccessLens is a read-only Linux privilege and permission risk analyzer for a
fourth-year BSc IT (Hons) Cybersecurity project. It collects local system
facts, identifies risky settings, scores the findings, and generates terminal,
JSON, and self-contained HTML reports.

## Current status

Phases 1-10 are implemented:

- Collectors for users, groups, shadow, sudoers, filesystem metadata, SSH keys,
  and cron jobs.
- Checks for account, sudo, file, SUID/SGID, SSH, and cron risks.
- Capped risk scoring from 0-100 with A-F grades.
- Terminal, JSON, and offline HTML reports.
- Before/after JSON comparison.
- Explicitly confirmed demonstration lab with exact-manifest cleanup.
- Architecture and presentation documentation in [`docs/`](docs/).

## Requirements

- Linux
- Python 3.10 or newer
- No third-party packages to run AccessLens
- `pytest` is used for development tests

## Run a scan

From the directory containing `accesslens/`:

```bash
python3 -m accesslens.main --help
python3 -m accesslens.main scan --quick --format terminal,html,json
sudo python3 -m accesslens.main scan --format terminal,html,json
```

Reports are saved to `./reports` by default. Use `--output-dir DIR` to select
another location. `--fail-on high` returns exit code 1 when HIGH or CRITICAL
findings exist, which is useful in an automation gate.

## Compare scans

```bash
python3 -m accesslens.main compare reports/before.json reports/after.json
```

Finding identity is `(check_id, target)`. The comparison shows NEW, RESOLVED,
and UNCHANGED findings plus the score delta.

## Demonstration lab

The lab intentionally creates weak settings on the local system, so it must
only be used on a machine you control. It requires root and the exact typed
confirmation `yes-this-is-my-system`. It records every created object in
`/var/lib/accesslens/lab-manifest`.

```bash
cd lab
sudo ./setup_lab.sh
cd ..
sudo python3 -m accesslens.main scan --quick --format terminal,html,json
cd lab
sudo ./cleanup_lab.sh
```

Cleanup requires `yes-clean-accesslens-lab` and refuses to run without the
manifest. Never remove the manifest manually before cleanup. Read
[`lab/README_LAB.txt`](lab/README_LAB.txt) and
[`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md) first.

## Tests

```bash
python3 -m pytest tests/ -v
```

Tests use fixtures and temporary directories; they do not run the host lab.

## Safety and limitations

AccessLens does not execute fix commands, change permissions, create users, or
make network requests during a scan. The filesystem collector does not follow
symbolic links, avoids crossing filesystem boundaries, and skips virtual
filesystem trees.

This is a focused educational auditor, not a replacement for Lynis,
OpenSCAP, or a complete enterprise compliance platform. It does not currently
evaluate ACLs, Linux capabilities, SELinux/AppArmor policy, or remote hosts.
