# ARINC 429 IDS – API Reference

This document describes the function signatures, parameters, and return values for each layer in the 5-layer detection pipeline.

## Quick Links

- [L1: Parity & BPRZ Timing](#l1-parity--bprz-timing)
- [L2: Replay & Temporal Integrity](#l2-replay--temporal-integrity)
- [L3: Physics Constraints](#l3-physics-constraints)
- [L4: Adaptive Anomaly Scoring](#l4-adaptive-anomaly-scoring)
- [L5: Welford Feature Anomaly](#l5-welford-feature-anomaly)
- [Main Orchestration](#main-orchestration)
- [Usage Example](#usage-example)

---

## L1: Parity & BPRZ Timing

**Purpose:** Validates bit-level protocol integrity and signal timing.

### `L1(word: str, timing_us: float, ts_ms, ts_state: list) -> dict | None`

**Parameters:**
- `word` (str): 32-bit binary string (e.g., `"01000000000000000000000000110000"`)
- `timing_us` (float): Signal timing in microseconds (should be 4.75–5.25 µs for BPRZ)
- `ts_ms` (int | None): Timestamp in milliseconds (used for state tracking)
- `ts_state` (list): Mutable list `[last_timestamp_ms]` to track monotonicity across frames

**Returns:**
- `None` if the frame passes L1
- `{"layer": "L1A", "msg": "Parity violation"}` if odd parity check fails
- `{"layer": "L1B", "msg": "BPRZ timing violation"}` if timing is outside [4.75, 5.25]

**Example:**
```python
word = "01000000000000000000000000110000"
timing_us = 5.0
ts_ms = 1000
ts_state = [None]

result = L1(word, timing_us, ts_ms, ts_state)
if result is None:
    print("✅ Parity and timing OK")
else:
    print(f"🛑 {result['layer']}: {result['msg']}")
```

---

## L2: Replay & Temporal Integrity

**Purpose:** Detects timestamp regression and frame replay attacks.

### `L2(word: str, ts_ms, ts_state: list, label: str, label_name: str, replay: dict, telemetry: dict, models: dict) -> dict | None`

**Parameters:**
- `word` (str): 32-bit binary string
- `ts_ms` (int | None): Frame timestamp in milliseconds
- `ts_state` (list): Mutable list `[last_timestamp_ms]` (shared with L1)
- `label` (str): 3-digit octal label (e.g., `"203"` for Barometric Altitude)
- `label_name` (str): Human-readable label name
- `replay` (dict): Per-label replay window tracking (mutable)
- `telemetry` (dict): Per-label telemetry history (mutable)
- `models` (dict): Per-label LabelModel instances (mutable)

**Returns:**
- `None` if the frame passes L2
- `{"layer": "L2A", "msg": "Timestamp regression"}` if `ts_ms < last_timestamp_ms` (clears telemetry/models on hit)
- `{"layer": "L2B", "msg": "Replay"}` if `(word, ts_ms)` tuple seen before in last 20 frames

**Side Effects:**
- Updates `ts_state[0]` with current timestamp
- Appends `(word, ts_ms)` to `replay[label]` (deque, maxlen=20)
- On L2A hit, clears `telemetry` and resets all `models`

**Example:**
```python
replay = {}
telemetry = {}
models = {}
ts_state = [None]

result = L2(word, ts_ms, ts_state, "203", "Barometric Altitude",
            replay, telemetry, models)
if result:
    print(f"🛑 {result['layer']}: {result['msg']}")
```

---

## L3: Physics Constraints

**Purpose:** Validates value bounds and kinematic continuity (detects teleportation).

### `L3(word: str, label: str, label_name: str, rules: dict, constraints: dict, telemetry: dict, models: dict) -> tuple`

**Parameters:**
- `word` (str): 32-bit binary string
- `label` (str): Octal label
- `label_name` (str): Human-readable name
- `rules` (dict): Constraints for this label from `constraints.json` (keys: `"min_val"`, `"max_val"`, `"max_delta"`)
- `constraints` (dict): Full constraints lookup
- `telemetry` (dict): Per-label last-known values (mutable)
- `models` (dict): Per-label LabelModel instances (mutable)

**Returns:**
- Tuple: `(alert_dict | None, delta_abs: float, decoded_value: float)`
  - `alert_dict` = `None` if passes, or `{"layer": "L3", "msg": "..."}` if fails
  - `delta_abs` = absolute change from last known value (0.0 if first occurrence)
  - `decoded_value` = the decoded BNR value

**Alert Reasons:**
- Out of bounds: `"Out of bounds"` (value < min or > max)
- Teleportation: `"Teleportation"` (delta exceeds `max_delta`)

**Special Handling:**
- Longitude labels (`"111"`, `"311"`): Wraps delta at ±180° (accounts for +/− 179.5 = valid 1° move)

**Example:**
```python
rules = constraints.get("203", {})
alert, delta, value = L3(word, "203", "Barometric Altitude",
                          rules, constraints, telemetry, models)
if alert:
    print(f"🛑 {alert['msg']} (delta={delta:.2f})")
else:
    print(f"✅ Value={value:.1f}, Delta={delta:.2f}")
```

---

## L4: Adaptive Anomaly Scoring

**Purpose:** Detects sustained or statistical anomalies using EWMA and rolling z-scores.

### `L4(delta_abs: float, model: LabelModel) -> dict`

**Parameters:**
- `delta_abs` (float): Absolute kinematic change from L3
- `model` (LabelModel): Per-label adaptive model with learned baseline

**Returns:**
```python
{
    "ewma_hard": bool,      # True if delta exceeds adaptive EWMA threshold
    "ewma_score": float,    # 0–100, severity of EWMA anomaly
    "zs_score": float       # 0–100, z-score severity across rolling buffer
}
```

**Algorithm Details:**

1. **EWMA Hard Flag:**
   - After `L4_WARMUP=15` clean frames, compute adaptive threshold:
     - `threshold = ewma_mean + L4_SIGMA * ewma_std`
   - If `delta_abs > threshold`, set `ewma_hard=True` and score the anomaly

2. **Z-Score:**
   - Maintain rolling window (40 frames) of past deltas
   - Compute mean and std dev
   - If std dev > threshold, compute z-score: `z = (delta_abs - mean) / std`
   - Scale to 0–100 range

**Example:**
```python
from src.L4 import L4
from src.ids_core import LabelModel

model = LabelModel(max_delta=25.0)
# ... feed clean data to model.update() ...

l4_result = L4(delta_abs=15.5, model=model)
print(f"EWMA Hard Flag: {l4_result['ewma_hard']}")
print(f"EWMA Score: {l4_result['ewma_score']}")
print(f"Z-Score: {l4_result['zs_score']}")
```

---

## L5: Welford Feature Anomaly

**Purpose:** Detects distributional shifts using online Welford algorithm and multi-feature z-scores.

### `L5(delta_abs: float, word: str, timing_us: float, model: LabelModel) -> dict`

**Parameters:**
- `delta_abs` (float): Absolute kinematic change
- `word` (str): 32-bit binary string
- `timing_us` (float): Signal timing in microseconds
- `model` (LabelModel): Per-label model with learned feature distribution

**Returns:**
```python
{
    "nn_score": float   # 0–100, severity of feature-space anomaly
}
```

**Features Extracted (5D):**
1. `delta_ratio` = min(delta_abs / max_delta, 1.0) → [0, 1]
2. `bit_balance` = ones_count / 32.0 → [0, 1]
3. `transition_freq` = transitions / 31.0 → [0, 1]
4. `entropy` = Shannon entropy of bits → [0, 1]
5. `timing_norm` = (timing_us - 5.0) / 0.25, clamped to [−1, 1]

**Algorithm:**
- After `L5_WARMUP=30` frames, compute feature means and standard deviations (using Welford online algorithm, no batch buffer needed)
- Extract feature vector `x` from current frame
- Compute z-scores per feature: `z[i] = |x[i] - mean[i]| / std[i]`
- Take max z-score and scale: `nn_score = min(100.0, (max_z / L5_SIGMA) * 100.0)`

**Example:**
```python
l5_result = L5(delta_abs=15.5, word=word_32bit, timing_us=5.0, model=model)
print(f"Feature Anomaly Score: {l5_result['nn_score']}")
```

---

## Main Orchestration

**Purpose:** Chains all 5 layers together and produces final alert decision.

### `analyse_frame(word, ts_str, timing_us, constraints, telemetry, replay, models, ts_state) -> dict`

**Parameters:**
- `word` (str): 32-bit binary ARINC word
- `ts_str` (str): Timestamp string (e.g., `"01:23:456"` for MM:SS:mmm)
- `timing_us` (float): Signal timing in microseconds
- `constraints` (dict): Full constraints lookup from `constraints.json`
- `telemetry` (dict): Per-label telemetry (mutable)
- `replay` (dict): Per-label replay windows (mutable)
- `models` (dict): Per-label LabelModel instances (mutable)
- `ts_state` (list): Mutable list `[last_timestamp_ms]`

**Returns:**
```python
{
    "status": "ALERT" | "PASS",
    "layer": "L1A" | "L1B" | "L2A" | "L2B" | "L3" | "L4+5" | None,
    "msg": str
}
```

**Flow:**
1. Parse timestamp → L1
2. If L1 fails → return alert
3. Extract label → L2
4. If L2 fails → return alert
5. Decode value → L3
6. If L3 fails → return alert
7. Create/fetch model → L4 + L5
8. Combine scores: `combined = 0.50 * ewma + 0.30 * zs + 0.20 * nn`
9. If `ewma_hard=True` OR `combined >= 80.0` → alert (layer: "L4+5")
10. Otherwise → update telemetry/model, return PASS

**Example:**
```python
import json
from src.ids_core import analyse_frame

with open("src/constraints.json") as f:
    constraints = json.load(f)

telemetry = {}
replay = {}
models = {}
ts_state = [None]

result = analyse_frame(
    word="01000000000000000000000000110000",
    ts_str="00:00:100",
    timing_us=5.0,
    constraints=constraints,
    telemetry=telemetry,
    replay=replay,
    models=models,
    ts_state=ts_state
)

print(f"Status: {result['status']}")
if result['status'] == "ALERT":
    print(f"Layer: {result['layer']}, Message: {result['msg']}")
```

---

## Usage Example

### Full Integration Example

```python
import csv
import json
from src.ids_core import analyse_frame

# Load configuration
with open("src/constraints.json") as f:
    constraints = json.load(f)

# Initialize state
telemetry = {}
replay = {}
models = {}
ts_state = [None]

# Process CSV file
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
        print(f"Frame: {word[:8]}... | Attack: {is_attack} | Detected: {detected}")
```

---

## Constants & Tuning Parameters

All constants are defined in `src/ids_core.py`:

```python
BPRZ_MIN = 4.75          # Minimum BPRZ signal timing (µs)
BPRZ_MAX = 5.25          # Maximum BPRZ signal timing (µs)

REPLAY_WINDOW = 20       # Per-label deque size (frames)

EWMA_ALPHA = 0.08        # Exponential smoothing factor
L4_WARMUP = 15           # Frames to collect before L4 alerts
L4_SIGMA = 4.0           # Z-score sigma threshold for EWMA

ZS_WINDOW = 40           # Rolling z-score buffer size
ZS_SIGMA = 3.5           # Z-score sigma for rolling buffer

L5_WARMUP = 30           # Frames to collect before L5 alerts
L5_SIGMA = 4.0           # Z-score sigma for feature anomaly

COMBINED_GATE = 80.0     # Alert threshold: combined score >= 80
```

To tune for your deployment, adjust `L4_SIGMA`, `L5_SIGMA`, and `COMBINED_GATE`.

---

## See Also

- `/docs/LAYER_SPECIFICATIONS.md` — Detailed per-layer behavior
- `/docs/QUICKSTART.md` — How to run the full pipeline
- `CONTRIBUTING.md` — Contribution guidelines
