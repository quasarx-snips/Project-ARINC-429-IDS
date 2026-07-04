# =====
# ids_core.py  —  ARINC 429 Intrusion Detection System
# Run: python3 ids_core.py
# =====

# ── Imports ───────────────────────────────────────────────────────────────────
import csv
import json
import math
import os
import pickle
from collections import deque
import numpy as np

# ── Config ────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(BASE_DIR)
CONSTRAINTS_PATH = os.path.join(BASE_DIR, "constraints.json")
MODEL_PATH = os.path.join(BASE_DIR, "ids_model.pkl")

DATASETS = [
    "data/L1A_parity_poison.csv",
    "data/L1B_timing_attack.csv",
    "data/L2A_replay_attack.csv",
    "data/L2B_replay_dedup.csv",
    "data/L3_teleport_attack.csv",
    "data/L3_value_bounds.csv",
    "data/L4L5_statistical_anomaly.csv",
]


def _resolve_path(path: str) -> str:
    if os.path.isabs(path):
        return path

    candidates = [
        path,
        os.path.join(BASE_DIR, path),
        os.path.join(REPO_ROOT, path),
        os.path.join(REPO_ROOT, os.path.basename(path)),
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return os.path.abspath(candidate)
    return os.path.abspath(os.path.join(REPO_ROOT, path))

BPRZ_MIN = 4.75
BPRZ_MAX = 5.25

REPLAY_WINDOW = 20

EWMA_ALPHA = 0.08
L4_WARMUP = 20
L4_SIGMA = 4.5

ZS_WINDOW = 40
ZS_SIGMA = 3.5

L5_WARMUP = 35
L5_SIGMA = 4.5

COMBINED_GATE = 90.0

# ── LabelModel  (ML state for L4 + L5, one instance per ARINC label) ─────────

class LabelModel:
    N_FEATURES = 5

    def __init__(self, max_delta=None):
        self.max_delta = max_delta

        self.ewma_mean = None
        self.ewma_var = 0.0
        self.n_clean = 0

        self.zs_buffer = deque(maxlen=ZS_WINDOW)

        self.wf_n = 0
        self.wf_mean = np.zeros(self.N_FEATURES)
        self.wf_M2 = np.zeros(self.N_FEATURES)

    @staticmethod
    def _word_stats(word: str):
        n, ones = len(word), word.count("1")
        trans = sum(1 for i in range(n - 1) if word[i] != word[i + 1])
        p1, p0 = ones / n, 1.0 - ones / n
        h = 0.0
        if p0 > 0: h -= p0 * math.log2(p0)
        if p1 > 0: h -= p1 * math.log2(p1)
        return ones / 32.0, trans / 31.0, h

    def features(self, word: str, delta_abs: float, timing_us: float) -> np.ndarray:
        bb, tf, ef = self._word_stats(word)
        delta_ratio = min(delta_abs / max(self.max_delta or 25.0, 1.0), 1.0)
        timing_norm = max(-1.0, min(1.0, (timing_us - 5.0) / 0.25))
        return np.array([delta_ratio, bb, tf, ef, timing_norm])

    def update(self, delta_abs: float, word: str, timing_us: float):
        if self.ewma_mean is None:
            self.ewma_mean = delta_abs
        else:
            prev = self.ewma_mean
            self.ewma_mean = (1 - EWMA_ALPHA) * self.ewma_mean + EWMA_ALPHA * delta_abs
            self.ewma_var = (1 - EWMA_ALPHA) * self.ewma_var \
                            + EWMA_ALPHA * (delta_abs - prev) ** 2
        self.n_clean += 1

        self.zs_buffer.append(delta_abs)

        x = self.features(word, delta_abs, timing_us)
        self.wf_n += 1
        delta_w = x - self.wf_mean
        self.wf_mean += delta_w / self.wf_n
        self.wf_M2 += delta_w * (x - self.wf_mean)

    @property
    def ewma_threshold(self):
        if self.n_clean < L4_WARMUP or self.ewma_mean is None:
            return self.max_delta
        std = math.sqrt(max(self.ewma_var, 0.0))
        tight = self.ewma_mean + L4_SIGMA * std
        if self.max_delta is not None:
            return min(self.max_delta, max(tight, self.max_delta * 0.05))
        return tight

    def reset(self):
        self.__init__(self.max_delta)

    def reset_ewma(self):
        self.ewma_mean = None
        self.ewma_var = 0.0
        self.n_clean = 0
        self.zs_buffer.clear()

# ── ARINC / CSV helpers ───────────────────────────────────────────────────────

_TS_ALIASES = {"time (mm:ss:mmm)", "time (mm:ss:mmm)", "time"}
_WORD_COL = "arinc_transmission_received"
_ATTACK_COL = "is_attack"
_TIMING_COL = "timing_interval_us"

def _ts_col(fieldnames: list) -> str | None:
    # Find timestamp column name
    for col_name in fieldnames:
        if col_name.lower() in _TS_ALIASES:
            return col_name
    return None

def _parse_ts(ts: str) -> int | None:
    # Parse time string "mm:ss:mmm" to milliseconds
    try:
        parts = ts.strip().split(":")
        if len(parts) == 3:
            minutes = int(parts[0])
            seconds = int(parts[1])
            millis = int(parts[2])
            return minutes * 60_000 + seconds * 1_000 + millis
    except (ValueError, AttributeError):
        pass
    return None

def _parse_label(word: str) -> str:
    # Extract ARINC label from last 8 bits (reversed to octal)
    last_8_bits = word[-8:]
    reversed_bits = last_8_bits[::-1]
    binary_value = int(reversed_bits, 2)
    octal_str = oct(binary_value)[2:]
    return octal_str.zfill(3)

def _decode_value(word: str, label: str, constraints: dict) -> float:
    # Decode BNR value from word bits
    data_bits = word[3:22]
    sign_bit = data_bits[0]
    value_bits = data_bits[1:]
    
    # Convert binary to integer
    raw_value = int(value_bits, 2)
    if sign_bit == "1":
        raw_value = raw_value * -1
    
    # Apply resolution scaling
    resolution = constraints.get(label, {}).get("resolution", 1.0)
    return float(raw_value) * resolution


def _reset_state(telemetry: dict, models: dict) -> None:
    # Reset telemetry and model learning on regression
    telemetry.clear()
    for model in models.values():
        model.reset_ewma()

# =====
# def L1(...) — Physical: parity + BPRZ timing
# =====

def L1(word: str, timing_us: float, ts_ms, ts_state: list) -> dict | None:
    if word.count("1") % 2 == 0:
        if ts_ms is not None and (ts_state[0] is None or ts_ms > ts_state[0]):
            ts_state[0] = ts_ms
        return {"layer": "L1A", "msg": "Parity violation"}

    if not (BPRZ_MIN <= timing_us <= BPRZ_MAX):
        if ts_ms is not None and (ts_state[0] is None or ts_ms > ts_state[0]):
            ts_state[0] = ts_ms
        return {"layer": "L1B", "msg": "BPRZ timing violation"}

    return None

# =====
# def L2(...) — Transport: timestamp regression + replay dedup
# =====

def L2(word: str, ts_ms, ts_state: list,
        label: str, replay: dict, telemetry: dict, models: dict) -> dict | None:
    # Detect timestamp regression (but allow 24-hour wraparound) (FIX #3)
    if ts_ms is not None and ts_state[0] is not None:
        delta_ts = ts_ms - ts_state[0]
        # Regression if timestamp goes backward by more than 100ms
        if delta_ts < -100:
            _reset_state(telemetry, models)
            return {"layer": "L2A", "msg": "Timestamp regression"}
    
    # Update timestamp state
    if ts_ms is not None:
        ts_state[0] = ts_ms

    # Check for replay (duplicate frames)
    if label not in replay:
        replay[label] = deque(maxlen=REPLAY_WINDOW)
    
    frame_key = (word, ts_ms)
    if frame_key in replay[label]:
        return {"layer": "L2B", "msg": "Replay"}
    
    replay[label].append(frame_key)
    return None

# =====
# def L3(...) — Application: value bounds + kinematic continuity
# =====

def L3(word: str, label: str, rules: dict, constraints: dict,
        telemetry: dict, models: dict) -> tuple:
    value = _decode_value(word, label, constraints)

    if "min_val" in rules and "max_val" in rules:
        if not (rules["min_val"] <= value <= rules["max_val"]):
            if label in models:
                models[label].reset()
            telemetry.pop(label, None)
            return ({"layer": "L3", "msg": "Out of bounds"}, 0.0, value)

    delta_abs = 0.0
    if label in telemetry and "max_delta" in rules:
        delta_abs = abs(value - telemetry[label])
        if label in ("111", "311") and delta_abs > 180.0:
            delta_abs = 360.0 - delta_abs
        if delta_abs > rules["max_delta"] * 1.15:
            if label in models:
                models[label].reset()
            telemetry.pop(label, None)
            return ({"layer": "L3", "msg": "Teleportation"}, delta_abs, value)

    return None, delta_abs, value

# =====
# def L4(...) — Statistical ML: EWMA + rolling z-score
# =====

def L4(delta_abs: float, model: LabelModel) -> dict:
    ewma_hard = False
    ewma_score = 0.0
    zs_score = 0.0

    # EWMA score: requires enough clean samples
    thresh = model.ewma_threshold
    if thresh is not None and model.n_clean >= L4_WARMUP and delta_abs > thresh * 1.2:
        ewma_hard = True
        ratio = delta_abs / max(thresh * 1.2, 1e-9)
        ewma_score = min(100.0, (ratio - 1.0) * 45.0 + 55.0)

    # Z-score: requires sufficient buffer AND warmup (FIX #1)
    buf = model.zs_buffer
    if len(buf) >= 20 and model.n_clean >= L4_WARMUP:
        arr = np.array(buf)
        mu = arr.mean()
        sd = arr.std()
        if sd > 1e-9:
            z = (delta_abs - mu) / sd
            zs_score = max(0.0, min(100.0, (z / ZS_SIGMA) * 100.0))

    return {
        "ewma_hard": ewma_hard,
        "ewma_score": round(ewma_score, 1),
        "zs_score": round(zs_score, 1),
    }

# =====
# def L5(...) — Simple online learning: Welford per-feature z-score
# =====

def L5(delta_abs: float, word: str, timing_us: float, model: LabelModel) -> dict:
    nn_score = 0.0

    if model.wf_n >= L5_WARMUP:
        x = model.features(word, delta_abs, timing_us)
        wf_std = np.sqrt(np.maximum(model.wf_M2 / model.wf_n, 0.0))
        mask = wf_std > 1e-6
        if mask.any():
            z_scores = np.abs(x[mask] - model.wf_mean[mask]) / wf_std[mask]
            max_z = float(z_scores.max())
            nn_score = max(0.0, min(100.0, (max_z / L5_SIGMA) * 100.0))
            if nn_score < 70.0:
                nn_score = 0.0

    return {"nn_score": round(nn_score, 1)}

# =====
# def analyse_frame(...) — orchestrates L1 → L5
# =====

def analyse_frame(
    word: str,
    ts_str: str,
    timing_us: float,
    constraints: dict,
    telemetry: dict,
    replay: dict,
    models: dict,
    ts_state: list,
) -> dict:
    ts_ms = _parse_ts(ts_str)

    hit = L1(word, timing_us, ts_ms, ts_state)
    if hit:
        return {"status": "ALERT", **hit}

    label = _parse_label(word)
    rules = constraints.get(label, {})

    hit = L2(word, ts_ms, ts_state, label, replay, telemetry, models)
    if hit:
        return {"status": "ALERT", **hit}

    hit, delta_abs, value = L3(word, label, rules, constraints,
                                telemetry, models)
    if hit:
        return {"status": "ALERT", **hit}

    if label not in models:
        models[label] = LabelModel(max_delta=rules.get("max_delta"))

    model = models[label]
    l4 = L4(delta_abs, model)
    l5 = L5(delta_abs, word, timing_us, model)

    combined = (0.50 * l4["ewma_score"]
              + 0.30 * l4["zs_score"]
              + 0.20 * l5["nn_score"])
    ml_alert = l4["ewma_hard"] or combined >= COMBINED_GATE

    if ml_alert:
        return {"status": "ALERT", "layer": "L4+5",
                "msg": "ML anomaly"}

    telemetry[label] = value
    model.update(delta_abs, word, timing_us)

    return {"status": "PASS", "layer": None, "msg": "Passed"}

# =====
# def run_pipeline(...)
# =====

def run_pipeline(constraints: dict, models: dict) -> dict:
    results = {}
    layer_catches = {"L1A": 0, "L1B": 0, "L2A": 0, "L2B": 0, "L3": 0, "L4+5": 0}

    for file_path in DATASETS:
        resolved_path = _resolve_path(file_path)
        # Reset state for each dataset (FIX #2)
        models.clear()
        telemetry = {}
        replay = {}
        ts_state = [None]
        
        name = os.path.basename(resolved_path)
        tp = fp = tn = fn = 0
        layer_dist = {k: 0 for k in layer_catches}

        if not os.path.exists(resolved_path):
            results[name] = {"error": f"File not found: {resolved_path}"}
            continue

        with open(resolved_path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            ts_col = _ts_col(reader.fieldnames or [])

            for row in reader:
                word = row[_WORD_COL]
                is_attack = row[_ATTACK_COL].strip().lower() == "true"
                ts_str = row.get(ts_col, "") if ts_col else ""
                timing_us = float(row.get(_TIMING_COL, 5.0))

                res = analyse_frame(word, ts_str, timing_us,
                                     constraints, telemetry, replay,
                                     models, ts_state)
                detected = res["status"] == "ALERT"

                # Count: TP, FP, TN, FN
                if detected and is_attack:
                    tp += 1
                    layer = res.get("layer") or "L4+5"
                    layer_dist[layer] = layer_dist.get(layer, 0) + 1
                    layer_catches[layer] += 1
                elif detected:
                    fp += 1
                elif is_attack:
                    fn += 1
                else:
                    tn += 1

        # Calculate metrics
        if tp + fp > 0:
            prec = tp / (tp + fp)
        else:
            prec = float("nan")
        
        if tp + fn > 0:
            rec = tp / (tp + fn)
        else:
            rec = float("nan")
        
        if prec + rec > 0:
            f1 = 2 * prec * rec / (prec + rec)
        else:
            f1 = float("nan")
        
        # Matthews Correlation Coefficient
        mcc_n = tp * tn - fp * fn
        mcc_denominator = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
        if mcc_denominator > 0:
            mcc_d = math.sqrt(mcc_denominator)
        else:
            mcc_d = 1

        # Store results for this dataset
        results[name] = {
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "total": tp + fp + tn + fn,
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "mcc": mcc_n / mcc_d,
            "layer_dist": layer_dist,
        }

    results["__layer_catches__"] = layer_catches
    return results

# =====
# def print_results(...)
# =====

_W = 78

def _pct(v) -> str:
    # Format percentage, handling NaN
    if v == v:  # Check if not NaN
        return f"{v*100:.1f}%"
    else:
        return "  N/A "

def _rule(ch="═"):
    # Print a separator line
    print("  " + ch * _W)

def print_results(results: dict, models: dict, constraints: dict):
    # Separate dataset results from metadata
    dataset_rows = {}
    for k, v in results.items():
        if not k.startswith("__"):
            dataset_rows[k] = v
    
    layer_catches = results.get("__layer_catches__", {})

    print(); _rule("═")
    print(f"  {'ARINC 429  —  IDS Run Results':^{_W}}")
    _rule("═"); print()

    print("  Detection Results")
    _rule("─")
    print(f"  {'Dataset':<26}  {'TP':>4}  {'FP':>4}  {'TN':>4}  {'FN':>4}"
          f"  {'Prec':>7}  {'Recall':>7}  {'F1':>7}  {'MCC':>6}")
    _rule("─")

    # Calculate grand totals
    grand_tp = 0
    grand_fp = 0
    grand_tn = 0
    grand_fn = 0
    
    for name, r in dataset_rows.items():
        if "error" in r:
            print(f"  {name:<26}  {r['error']}")
            continue
        grand_tp += r["tp"]
        grand_fp += r["fp"]
        grand_tn += r["tn"]
        grand_fn += r["fn"]
        print(f"  {name:<26}  {r['tp']:>4}  {r['fp']:>4}  {r['tn']:>4}  {r['fn']:>4}"
              f"  {_pct(r['precision']):>7}  {_pct(r['recall']):>7}"
              f"  {_pct(r['f1']):>7}  {r['mcc']:>6.3f}")

    _rule("─")
    
    # Grand total metrics
    if grand_tp + grand_fp > 0:
        gp = grand_tp / (grand_tp + grand_fp)
    else:
        gp = float("nan")
    
    if grand_tp + grand_fn > 0:
        gr = grand_tp / (grand_tp + grand_fn)
    else:
        gr = float("nan")
    
    if gp + gr > 0:
        gf = 2 * gp * gr / (gp + gr)
    else:
        gf = float("nan")
    
    mn = grand_tp * grand_tn - grand_fp * grand_fn
    md_denom = (grand_tp + grand_fp) * (grand_tp + grand_fn) * (grand_tn + grand_fp) * (grand_tn + grand_fn)
    if md_denom > 0:
        md = math.sqrt(md_denom)
    else:
        md = 1
    
    print(f"  {'GRAND TOTAL':<26}  {grand_tp:>4}  {grand_fp:>4}  {grand_tn:>4}  {grand_fn:>4}"
          f"  {_pct(gp):>7}  {_pct(gr):>7}  {_pct(gf):>7}  {mn/md:>6.3f}")
    _rule("─"); print()

    _layer_desc = {
        "L1A" : "L1  Parity",
        "L1B" : "L1  BPRZ Timing",
        "L2A" : "L2  Timestamp Regression",
        "L2B" : "L2  Frame Replay Dedup",
        "L3"  : "L3  Kinematic / Value Bounds",
        "L4+5": "L4+L5  EWMA + Z-Score + Welford",
    }
    total_attacks = grand_tp + grand_fn
    print("  Layer Breakdown")
    _rule("─")
    print(f"  {'Key':<6}  {'Layer':<44}  {'Caught':>6}  {'%':>6}")
    _rule("─")
    for key, desc in _layer_desc.items():
        caught = layer_catches.get(key, 0)
        if total_attacks > 0:
            pct = f"{100 * caught / total_attacks:.2f}%"
        else:
            pct = "—"
        print(f"  {key:<6}  {desc:<44}  {caught:>6}  {pct:>6}")
    _rule("─"); print()

# =====
# def main()
# =====

def main():
    constraints = {}
    if os.path.exists(CONSTRAINTS_PATH):
        with open(CONSTRAINTS_PATH) as f:
            constraints = json.load(f)

    models: dict[str, LabelModel] = {}
    if os.path.exists(MODEL_PATH):
        try:
            with open(MODEL_PATH, "rb") as f:
                models = pickle.load(f)
            for lbl, m in models.items():
                m.max_delta = constraints.get(lbl, {}).get("max_delta")
        except Exception:
            models = {}

    results = run_pipeline(constraints, models)
    print_results(results, models, constraints)

    if os.path.exists(MODEL_PATH):
        os.remove(MODEL_PATH)

if __name__ == "__main__":
    main()
