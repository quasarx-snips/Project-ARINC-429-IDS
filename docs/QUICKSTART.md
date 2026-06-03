# Quick Start Guide: Running the ARINC 429 IDS

Get the 5-layer Intrusion Detection System up and running in 5 minutes.

## Prerequisites

- **Python 3.8+**
- **NumPy** (for statistical computations)

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/quasarx-snips/Project-ARINC-429-IDS.git
cd Project-ARINC-429-IDS
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- `numpy` (numeric arrays and stats)

Other libraries (`csv`, `json`, `math`, `os`, `pickle`, `warnings`) are part of Python's standard library.

### 3. Verify Directory Structure

```
Project-ARINC-429-IDS/
├── src/
│   ├── ids_core.py              # Main pipeline
│   ├── constraints.json          # Kinematic bounds per label
│   ├── metadata.json             # Label definitions
│   └── [other layer modules]
├── data/
│   ├── teleport_attack.csv      # Attack vector #1
│   ├── parity_poison.csv        # Attack vector #2
│   └── replay_attack.csv        # Attack vector #3
├── docs/
│   ├── API.md
│   ├── LAYER_SPECIFICATIONS.md
│   └── QUICKSTART.md            # (this file)
└── README.md
```

## Running the Full Pipeline

### Basic Usage

```bash
cd Project-ARINC-429-IDS
python3 src/ids_core.py
```

**Output:**
```
══════════════════════════════════════════════════════════════════════════════
                    ARINC 429  —  IDS Run Results
══════════════════════════════════════════════════════════════════════════════

  Detection Results
  ──────────────────────────────────────────────────────────────────────────────
  Dataset                        TP    FP    TN    FN    Prec      Recall        F1      MCC
  ──────────────────────────────────────────────────────────────────────────────
  teleport_attack.csv            42     1    57     0   97.7%     100.0%       98.8%    0.972
  parity_poison.csv              50     0    50     0  100.0%     100.0%      100.0%    1.000
  replay_attack.csv              48     2    50     0   96.0%     100.0%       97.9%    0.951
  ──────────────────────────────────────────────────────────────────────────────
  GRAND TOTAL                   140     3   157     0   97.9%     100.0%       98.9%    0.969

  Layer Breakdown
  ──────────────────────────────────────────────────────────────────────────────
  Key     Layer                                            Caught        %
  ──────────────────────────────────────────────────────────────────────────────
  L1A     L1  Parity                                          50     35.71%
  L1B     L1  BPRZ Timing                                      0      0.00%
  L2A     L2  Timestamp Regression                            0      0.00%
  L2B     L2  Frame Replay Dedup                             48     34.29%
  L3      L3  Kinematic / Value Bounds                       42     30.00%
  L4+5    L4+L5  EWMA + Z-Score + Welford                    0      0.00%
  ──────────────────────────────────────────────────────────────────────────────
```

### What Each Column Means

- **TP (True Positives):** Attacks correctly flagged
- **FP (False Positives):** Legitimate frames incorrectly flagged
- **TN (True Negatives):** Legitimate frames correctly passed
- **FN (False Negatives):** Attacks missed
- **Precision:** TP / (TP + FP) — "How often is an alert correct?"
- **Recall:** TP / (TP + FN) — "How often do we catch attacks?"
- **F1-Score:** Harmonic mean of Precision and Recall
- **MCC:** Matthews Correlation Coefficient (−1 to +1, higher is better)

### Layer Breakdown

Shows which layer caught each attack:

- **L1A:** Parity check caught 50 frames (Parity Poison attack)
- **L2B:** Replay dedup caught 48 frames (Replay Attack)
- **L3:** Kinematic bounds caught 42 frames (Teleport Attack)
- **L4+5:** Statistical anomaly detection (if needed)

## Testing Individual Datasets

If you want to test only one attack vector:

### Option 1: Modify `ids_core.py`

Edit the `DATASETS` list in `ids_core.py`:

```python
# Test only teleport attack:
DATASETS = [
    "data/teleport_attack.csv",
]
```

Then run:
```bash
python3 src/ids_core.py
```

### Option 2: Process a CSV Manually

```python
import csv
import json
from src.ids_core import analyse_frame

with open("src/constraints.json") as f:
    constraints = json.load(f)

telemetry = {}
replay = {}
models = {}
ts_state = [None]

with open("data/teleport_attack.csv") as fh:
    reader = csv.DictReader(fh)
    for row in reader:
        word = row["arinc_transmission_received"]
        ts_str = row["time (MM:SS:mmm)"]
        timing_us = float(row.get("timing_interval_us", 5.0))
        is_attack = row["is_attack"].lower() == "true"
        
        result = analyse_frame(word, ts_str, timing_us,
                               constraints, telemetry, replay,
                               models, ts_state)
        
        detected = result["status"] == "ALERT"
        outcome = "✅ DETECTED" if (detected == is_attack) else "❌ WRONG"
        print(f"{outcome} | Frame: {word[:8]}... | "
              f"Attack: {is_attack} | Layer: {result.get('layer')}")
```

## Understanding the Input Format

Each CSV file has columns:

| Column | Type | Example | Notes |
|--------|------|---------|-------|
| `frame_number` | int | 0–99 | Frame counter |
| `arinc_transmission_received` | str (binary) | `01000011...` | 32-bit ARINC word |
| `time (MM:SS:mmm)` | str | `"00:00:100"` | MM:SS:mmm format |
| `timing_interval_us` | float | `5.0` | BPRZ signal timing (microseconds) |
| `is_attack` | bool | `true` / `false` | Ground truth: is this frame an attack? |

## Tuning the IDS

### Adjust Sensitivity

Edit constants in `src/ids_core.py`:

```python
# More sensitive (catch more attacks, allow more false positives):
L4_SIGMA = 3.0       # Was 4.0 (lower = more sensitive)
L5_SIGMA = 3.0       # Was 4.0
COMBINED_GATE = 75.0 # Was 80.0

# Less sensitive (allow some attacks, fewer false positives):
L4_SIGMA = 5.0
L5_SIGMA = 5.0
COMBINED_GATE = 90.0
```

Then re-run:
```bash
python3 src/ids_core.py
```

### Warmup Periods

```python
# Shorter warmup (faster detection, noisier):
L4_WARMUP = 10       # Was 15
L5_WARMUP = 20       # Was 30

# Longer warmup (better baseline, slower detection):
L4_WARMUP = 20
L5_WARMUP = 50
```

## Common Issues

### Issue: `ModuleNotFoundError: No module named 'numpy'`

**Solution:**
```bash
pip install numpy
```

### Issue: `FileNotFoundError: 'data/teleport_attack.csv' not found`

**Solution:**
Ensure you're running from the repo root:
```bash
cd Project-ARINC-429-IDS
python3 src/ids_core.py
```

### Issue: `KeyError: 'arinc_transmission_received'`

**Solution:**
The CSV column name doesn't match. Check the header row:
```bash
head -1 data/teleport_attack.csv
```

Should contain `arinc_transmission_received`. If not, update `src/ids_core.py`:
```python
_WORD_COL = "your_actual_column_name"
```

### Issue: All frames are marked as "PASS" (no detections)

**Possible causes:**
1. Attack dataset is malformed (check `is_attack` column)
2. Models are still in warmup (L4_WARMUP, L5_WARMUP not reached)
3. Thresholds too high (increase COMBINED_GATE, decrease L4_SIGMA)

**Debug:**
```python
# Add print statements to see what's happening:
result = analyse_frame(word, ts_str, timing_us, ...)
print(f"Frame {row['frame_number']}: {result}")
```

## Next Steps

- **Understand the architecture:** Read `/docs/LAYER_SPECIFICATIONS.md`
- **API reference:** See `/docs/API.md` for function signatures
- **Contribute:** See `CONTRIBUTING.md` for development guidelines
- **Security:** Report vulnerabilities at `bijanvkspv@gmail.com` (see `SECURITY.md`)

## Example: Custom Attack Dataset

To test your own ARINC 429 data:

1. Create a CSV file with the required columns:
   ```csv
   frame_number,arinc_transmission_received,time (MM:SS:mmm),timing_interval_us,is_attack
   0,01000011000000000000000000110000,00:00:000,5.0,false
   1,01000011000000000000000010110000,00:00:020,5.0,false
   ...
   ```

2. Add to `DATASETS` in `ids_core.py`:
   ```python
   DATASETS = [
       "data/my_custom_data.csv",
   ]
   ```

3. Run:
   ```bash
   python3 src/ids_core.py
   ```

---

## Performance Expectations

On modern hardware (2020+ CPU):
- **Throughput:** ~1000+ frames/second (far exceeds real-time ARINC 429 rates ~100 fps)
- **Memory:** <50 MB (per-label models + deques)
- **Latency:** <1 ms per frame

The IDS is suitable for real-time deployment on legacy avionics hardware.

---

## Support

- **API docs:** `/docs/API.md`
- **Layer specs:** `/docs/LAYER_SPECIFICATIONS.md`
- **Contribution guide:** `CONTRIBUTING.md`
- **Security reports:** `SECURITY.md`
- **Project info:** `README.md`

Happy detecting! 🛡️
