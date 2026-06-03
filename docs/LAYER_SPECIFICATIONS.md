# Layer Specifications: ARINC 429 IDS 5-Layer Pipeline

Detailed behavioral specifications for each detection layer, including threat model, detection method, edge cases, and false-negative risks.

## Table of Contents

- [L1: Physical Layer (Parity & BPRZ Timing)](#l1-physical-layer)
- [L2: Transport Layer (Replay & Temporal Integrity)](#l2-transport-layer)
- [L3: Application Layer (Physics Constraints)](#l3-application-layer)
- [L4: Statistical Layer (Adaptive Anomaly Scoring)](#l4-statistical-layer)
- [L5: Distributional Layer (Multi-Feature Anomaly)](#l5-distributional-layer)
- [Attack Attribution Matrix](#attack-attribution-matrix)

---

## L1: Physical Layer (Parity & BPRZ Timing)

### Purpose
Validate bit-level protocol integrity and BPRZ signal timing at the physical layer.

### Threat Model
- **L1A (Parity):** Attacker attempts to inject a word with corrupted bit, hoping the receiver accepts it
- **L1B (BPRZ):** Attacker modulates the BPRZ signal outside nominal timing window (hardware-level tampering)

### Detection Method

**L1A – Odd Parity Check:**
- ARINC 429 uses odd parity (all 32 bits must XOR to 1)
- Count `ones` in the 32-bit word
- If `ones % 2 == 0`, parity is even → ALERT
- Rejected frames don't proceed to L2+

**L1B – BPRZ Timing:**
- BPRZ encoding requires signal timing in nominal range: **4.75 µs to 5.25 µs**
- If `timing_us` falls outside this range → ALERT
- Accounts for transmitter/receiver oscillator drift and cable propagation delay

### False-Negative Risk
**ZERO** (protocol-level enforcement)

Any word arriving at the IDS has already:
1. Been transmitted (bit timing validated by BPRZ receiver)
2. Been received and deserialized (parity enforced by receiver hardware or earlier software layer)

If this IDS sees the frame, it's already considered protocol-valid by legacy hardware.

### Edge Cases
- **Timing missing:** If `timing_us` is None, skip L1B (assume hardware already validated)
- **Malformed input:** 32-bit word shorter than 32 chars → indexing error (should validate input)

### Constants
```python
BPRZ_MIN = 4.75  # microseconds
BPRZ_MAX = 5.25  # microseconds
```

---

## L2: Transport Layer (Replay & Temporal Integrity)

### Purpose
Detect timestamp regression (time travel) and frame replay (duplicate injection).

### Threat Model

**L2A (Timestamp Regression):**
- Attacker sends frames with old timestamps, trying to inject stale data retroactively
- Example: Inject frame with `ts_ms=5000` after receiver has processed `ts_ms=10000`
- Intent: Corrupt temporal ordering, confuse adaptive baselines

**L2B (Frame Replay):**
- Attacker replays an exact frame `(word, ts_ms)` pair within 20-frame window
- Intent: Repeat a stale altitude/heading value to mislead FMS

### Detection Method

**L2A – Timestamp Monotonicity:**
- Maintain global `last_timestamp_ms`
- If `ts_ms < last_timestamp_ms`, ALERT: "Timestamp regression"
- On alert, clear all telemetry and reset all adaptive models (prevent cascade false-positives)

**L2B – Sliding-Window Replay Dedup:**
- Per label, maintain deque of `(word, ts_ms)` tuples, max size 20
- On new frame, check if key exists in deque
- If yes, ALERT: "Replay"
- Append new key to deque (overwrites oldest if full)

### False-Negative Risk
**LOW** (except for stealthy attackers)

- **L2A bypass:** Attacker modifies timestamp to be monotonic (e.g., injects at `ts_ms=15000` instead of `5000`). L3/L4/L5 still detect via physics/statistics.
- **L2B bypass:** Attacker modifies the word slightly (e.g., rounds altitude to nearest 0.25 ft), same timestamp. Becomes a "new" frame, bypasses dedup but L3 may catch if the change violates constraints.

### Edge Cases
- **Missing timestamp:** If `ts_str` unparseable or None, set `ts_ms=None`. L2A check skipped. L2B still works (uses None as part of key).
- **Out-of-order arrival from network:** L2A catch-all; any disorder in streaming triggers reset.

### Constants
```python
REPLAY_WINDOW = 20  # frames per label
```

---

## L3: Application Layer (Physics Constraints)

### Purpose
Enforce flight dynamics constraints: value bounds (min/max) and kinematic continuity (max_delta).

### Threat Model

**Out-of-Bounds Attack:**
- Attacker injects altitude value 200,000 ft (impossible for commercial aircraft)
- Goal: Crash the FMS or cause erratic autoflight

**Teleportation Attack:**
- Attacker injects altitude jump from 30,000 ft → 5,000 ft in one frame (20 ms)
- This violates max descent rate of ~1000 fpm (=333 ft/s)
- Over 20 ms, max_delta should be ~6.6 ft, not 25,000 ft

### Detection Method

**Bounds Check:**
- Decode BNR value from bits 11–29
- Compare against `constraints[label]["min_val"]` and `["max_val"]`
- If out of bounds, ALERT and reset model

**Kinematic Continuity (Teleportation):**
1. Look up last known value: `prev_value = telemetry[label]`
2. Compute delta: `delta_abs = abs(value - prev_value)`
3. Special case: Longitude wrap (labels 111, 311)
   - If `delta_abs > 180.0`, assume wraparound: `delta_abs = 360.0 - delta_abs`
4. Compare to `constraints[label]["max_delta"]`
5. If `delta_abs > max_delta`, ALERT and reset model

### BNR Decoding
```
Bits 11–29: 19-bit BNR data
Bit 29: Sign bit (1 = negative)
Bits 11–28: Magnitude (MSB first)
Value = (signed) × constraints[label]["resolution"]
```

### False-Negative Risk
**MEDIUM** (stealthy attackers can stay within bounds)

- **Slow moves:** Attacker injects altitude 30,005 ft (within max_delta of 25 ft), then 30,010 ft, then 30,015 ft...
  - Each frame passes L3 individually
  - But over 10 frames, the trend is impossible (sustained climb at 500 fpm in cruise)
  - **Caught by L4/L5** (sustained delta elevation)

### Edge Cases
- **First occurrence:** If label not in telemetry, `delta_abs = 0.0` (no previous value to compare)
- **Longitude wrap:** Manual 180° boundary logic for labels 111 (GPS Lon) and 311 (IRS Lon)
  - Other labels don't wrap

### Constants

From `constraints.json`:
```json
"203": {
  "name": "Barometric Altitude",
  "min_val": -131072.0,
  "max_val": 131072.0,
  "max_delta": 25.0  // feet per frame
}
```

---

## L4: Statistical Layer (Adaptive Anomaly Scoring)

### Purpose
Detect sustained or statistically anomalous deltas that L3 might miss (stealthy attacks).

### Threat Model

**Slow Injection:**
- Attacker injects altitude changes within `max_delta` but at an abnormal *rate*
- Example: Steady 100 fpm descent (should be 0 fpm in cruise)
- L3 allows ±25 ft per frame, but L4 learns normal is ±0.5 ft and flags the sustained elevation

### Detection Method

**EWMA (Exponentially-Weighted Moving Average):**
1. **Warmup:** Collect L4_WARMUP=15 clean frames (no L3 hits)
2. **Baseline:** After warmup, compute running mean and variance of delta_abs
3. **Adaptive Threshold:** `threshold = ewma_mean + L4_SIGMA × ewma_std`
4. **Hard Flag:** If `delta_abs > threshold`, set `ewma_hard=True`
5. **Scoring:** `ewma_score = min(100, (delta_abs / threshold - 1) × 50 + 50)`

**Z-Score Rolling Buffer:**
1. **Warmup:** Start buffering deltas immediately (no warmup needed)
2. **Threshold:** Once buffer has ≥10 samples, compute `mean` and `std`
3. **Z-Score:** `z = (delta_abs - mean) / std`
4. **Scoring:** `zs_score = min(100, (z / ZS_SIGMA) × 100)`

**Combined Aggregation:**
```
combined_score = 0.50 × ewma_score + 0.30 × zs_score
```
Alert if `ewma_hard=True` OR `combined_score >= 80.0`

### False-Negative Risk
**MEDIUM** (during warmup and baseline adaptation)

- **L4_WARMUP period (frames 0–15):** No EWMA threshold yet; only z-score available
- **Adaptive baseline drift:** If baseline learns on partially-injected data, threshold inflates
  - **Mitigation:** Operator must provide 10+ minutes of clean pre-flight data before arming

### Edge Cases
- **Warmup period:** `ewma_hard` always False if `n_clean < L4_WARMUP`
- **Small std dev:** If `ewma_std < 1e-9`, avoid division by zero
- **Buffer size:** Z-score check only triggers if `len(zs_buffer) >= 10`

### Constants
```python
EWMA_ALPHA = 0.08    # Smoothing factor (higher = faster adaptation)
L4_WARMUP = 15       # Frames to reach steady baseline
L4_SIGMA = 4.0       # Z-score sensitivity (higher = fewer alerts)
ZS_WINDOW = 40       # Rolling buffer size
ZS_SIGMA = 3.5       # Z-score sensitivity
COMBINED_GATE = 80.0 # Alert threshold
```

### Tuning Guidance
- **More sensitive:** Decrease L4_SIGMA and L5_SIGMA (e.g., 3.0)
- **Less sensitive:** Increase COMBINED_GATE (e.g., 90.0)
- **Faster adaptation:** Increase EWMA_ALPHA (e.g., 0.15)

---

## L5: Distributional Layer (Multi-Feature Anomaly)

### Purpose
Detect subtle distributional shifts that don't manifest as large deltas or statistical outliers.

### Threat Model

**Sophisticated Injection:**
- Attacker injects data that:
  - Stays within L3 bounds ✓
  - Follows realistic L4 deltas ✓
  - But exhibits unusual *bitwise patterns* (high entropy, unusual bit balance)
- Example: Altitude word that looks correct but has abnormal 1/0 distribution due to bit manipulation

### Detection Method

**Feature Extraction (5D):**
For each frame, extract 5 features:
1. **delta_ratio** = min(delta_abs / max_delta, 1.0)
2. **bit_balance** = ones_count / 32
3. **transition_freq** = bit_transitions / 31
4. **entropy** = Shannon entropy (bits) / 5 (normalized)
5. **timing_norm** = (timing_us − 5.0) / 0.25, clamped [−1, 1]

**Online Learning (Welford Algorithm):**
1. **Warmup:** Collect L5_WARMUP=30 frames, compute feature statistics
2. **Mean & Variance:** Use Welford to avoid storing full history
3. **Z-Scores:** Per feature: `z[i] = |x[i] − mean[i]| / std[i]`
4. **Max Z:** `max_z = max(z[0..4])`
5. **Scoring:** `nn_score = min(100, (max_z / L5_SIGMA) × 100)`

### False-Negative Risk
**LOW** (after warmup)

- **During L5_WARMUP (frames 0–30):** No feature anomaly detection; L4 covers
- **Legitimate high-activity:** Takeoff/landing have different feature distributions
  - Baseline adapts after ~2–3 minutes of operation

### Edge Cases
- **Std dev = 0:** If all frames have identical feature, std=0 → no z-score (skip L5 for that feature)
- **Div by zero:** Check `std > 1e-6` before computing z-score

### Constants
```python
L5_WARMUP = 30
L5_SIGMA = 4.0
```

---

## Attack Attribution Matrix

Which layer catches which attack vector:

| Attack Type | Exploit | L1A | L1B | L2A | L2B | L3 | L4 | L5 |
|-------------|---------|-----|-----|-----|-----|----|----|-----|
| **Teleport Attack** | 25,000 ft jump | — | — | — | — | ✅ | ✓ | ✓ |
| **Parity Poison** | Flipped bit | ✅ | — | — | — | — | — | — |
| **Replay Attack** | Duplicate (word, ts) | — | — | ✓ | ✅ | — | — | — |
| **Slow Injection** | +100 fpm sustained | — | — | — | — | — | ✅ | ✓ |
| **Bit Flip (L3 bypass)** | Single bit mutated, value still in bounds | — | — | — | — | — | ✓ | ✅ |
| **Timestamp Injection** | Old ts, stale data | — | — | ✅ | — | — | — | — |

**Legend:**
- ✅ = **Primary catch** (layer specifically designed for this)
- ✓ = **Secondary catch** (layer may flag but not guaranteed)
- — = **Does not catch**

---

## Summary: Defense-in-Depth Flow

```
INPUT → L1(parity, timing)
         ├─ FAIL → ALERT "Protocol Violation"
         └─ PASS
            ↓
        L2(replay, timestamp)
         ├─ FAIL → ALERT "Temporal Violation"
         └─ PASS
            ↓
        L3(bounds, delta)
         ├─ FAIL → ALERT "Physics Violation"
         └─ PASS
            ↓
        L4(EWMA, z-score)
         ├─ FAIL → ALERT "Statistical Anomaly"
         └─ PASS
            ↓
        L5(feature z-score)
         ├─ FAIL → ALERT "Distributional Anomaly"
         └─ PASS
            ↓
        ✅ FORWARD TO FMS
```

**Key Property:** An attacker must **simultaneously evade all 5 layers**. Evading one (e.g., physics via slow moves) triggers another (L4/L5).

---

## See Also

- `/docs/API.md` — Function signatures and usage examples
- `/docs/QUICKSTART.md` — How to run the full pipeline
- `CONTRIBUTING.md` — Contribution guidelines
- `SECURITY.md` — Vulnerability reporting and known limitations
