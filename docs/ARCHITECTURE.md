# AccessLens architecture

AccessLens is organized as a pipeline:

```text
CLI
  -> collectors
  -> ScanContext
  -> checks
  -> Finding objects
  -> scoring
  -> terminal / JSON / HTML reporters
  -> compare (for two JSON reports)
```

## Helicopter view of each layer

- `main.py`: command-line interface and scan orchestration.
- `config.py`: policy constants, baselines, paths, and severity weights.
- `models.py`: dataclasses shared by every layer.
- `collectors/`: read-only extraction of users, sudo rules, files, SSH data,
  and cron jobs.
- `checks/`: independent security rules. Each returns `Finding` objects and
  never changes the system.
- `scoring.py`: converts findings into a capped 0-100 score and grade.
- `reporters/`: produces human-readable terminal, machine-readable JSON, and
  offline HTML output.
- `compare.py`: compares finding identities `(check_id, target)` between two
  JSON reports.
- `lab/`: explicitly confirmed demonstration setup and exact-manifest cleanup.
- `tests/`: fixture and temporary-tree tests that do not require the lab.

## Safety boundaries

The scanner uses `lstat`, does not follow symbolic links, avoids network
mounts, skips virtual filesystem trees, and never executes fix commands.
The lab is separate from the scanner and is the only component intended to
modify system state.
