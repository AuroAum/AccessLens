# AccessLens presentation demo

This script is written for a fourth-year BSc IT (Hons) Cybersecurity
presentation. Perform the lab only on the controlled local system and keep the
manifest until cleanup is complete.

## 1. Baseline

```bash
cd accesslens
python3 -m accesslens.main scan --quick --format terminal,html,json
```

Explain that the baseline JSON is the “before” evidence.

## 2. Create controlled weaknesses

```bash
cd lab
sudo ./setup_lab.sh
```

Type `yes-this-is-my-system` only after confirming the machine can tolerate the
temporary changes.

## 3. Scan again

```bash
cd ..
sudo python3 -m accesslens.main scan --quick --format terminal,html,json --fail-on high
```

Demonstrate three findings:

1. `SUD-001`: passwordless sudo.
2. `FIL-001`: world-writable file.
3. `SID-001`: dangerous SUID copy of `find`.

Open the HTML report offline and show filtering, expanded explanations, and
the copy button. The scanner displays commands but never runs them.

## 4. Compare

```bash
python3 -m accesslens.main compare reports/before.json reports/after.json
```

Explain NEW, RESOLVED, UNCHANGED, and score delta.

## 5. Cleanup and prove restoration

```bash
cd lab
sudo ./cleanup_lab.sh
cd ..
sudo python3 -m accesslens.main scan --quick --format terminal,html,json
```

Keep the final scan and cleanup output as evidence that the demonstration
objects were removed.
