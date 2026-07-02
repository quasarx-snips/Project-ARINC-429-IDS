# =============================================================================
# ids_core.py  —  ARINC 429 Intrusion Detection System
# Run: python3 ids_core.py
# =============================================================================

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
    for c in fieldnames:
        if c.lower() in _TS_ALIASES:
            return c
    return None

def _parse_ts(ts: str) -> int | None:
    try:
        p = ts.strip().split(":")
        if len(p) == 3:
            return int(p[0]) * 60_000 + int(p[1]) * 1_000 + int(p[2])
    except (ValueError, AttributeError):
        pass
    return None

def _parse_label(word: str) -> str:
    return oct(int(word[-8:][::-1], 2))[2:].zfill(3)

def _decode_value(word: str, label: str, constraints: dict) -> float:
    data = word[3:22]
    raw = int(data[1:], 2) * (-1 if data[0] == "1" else 1)
    return float(raw) * constraints.get(label, {}).get("resolution", 1.0)


def _reset_state(telemetry: dict, models: dict) -> None:
    telemetry.clear()
    for model in models.values():
        model.reset_ewma()

# =============================================================================
# def L1(...) — Physical: parity + BPRZ timing
# =============================================================================

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

# =============================================================================
# def L2(...) — Transport: timestamp regression + replay dedup
# =============================================================================

def L2(word: str, ts_ms, ts_state: list,
        label: str, replay: dict, telemetry: dict, models: dict) -> dict | None:
    if ts_ms is not None and ts_state[0] is not None and ts_ms < ts_state[0]:
        _reset_state(telemetry, models)
        return {"layer": "L2A", "msg": "Timestamp regression"}

    if ts_ms is not None:
        ts_state[0] = ts_ms

    if label not in replay:
        replay[label] = deque(maxlen=REPLAY_WINDOW)
    key = (word, ts_ms)
    if key in replay[label]:
        return {"layer": "L2B", "msg": "Replay"}
    replay[label].append(key)

    return None

# =============================================================================
# def L3(...) — Application: value bounds + kinematic continuity
# =============================================================================

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

# =============================================================================
# def L4(...) — Statistical ML: EWMA + rolling z-score
# =============================================================================

def L4(delta_abs: float, model: LabelModel) -> dict:
    ewma_hard = False
    ewma_score = 0.0
    zs_score = 0.0

    thresh = model.ewma_threshold
    if thresh is not None and model.n_clean >= L4_WARMUP and delta_abs > thresh * 1.2:
        ewma_hard = True
        ratio = delta_abs / max(thresh * 1.2, 1e-9)
        ewma_score = min(100.0, (ratio - 1.0) * 45.0 + 55.0)

    buf = model.zs_buffer
    if len(buf) >= 10:
        arr = np.array(buf)
        mu, sd = arr.mean(), arr.std()
        if sd > 1e-9:
            z = (delta_abs - mu) / sd
            zs_score = max(0.0, min(100.0, (z / ZS_SIGMA) * 100.0))

    return {
        "ewma_hard" : ewma_hard,
        "ewma_score": round(ewma_score, 1),
        "zs_score"  : round(zs_score, 1),
    }

# =============================================================================
# def L5(...) — Simple online learning: Welford per-feature z-score
# =============================================================================

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

# =============================================================================
# def analyse_frame(...) — orchestrates L1 → L5
# =============================================================================

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

# =============================================================================
# def run_pipeline(...)
# =============================================================================

def run_pipeline(constraints: dict, models: dict) -> dict:
    results = {}
    layer_catches = {"L1A": 0, "L1B": 0, "L2A": 0, "L2B": 0, "L3": 0, "L4+5": 0}

    telemetry: dict = {}
    replay: dict = {}
    ts_state: list = [None]

    for file_path in DATASETS:
        resolved_path = _resolve_path(file_path)
        telemetry.clear()
        replay.clear()
        ts_state[0] = None
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

                if detected and is_attack:
                    tp += 1
                    lyr = res.get("layer") or "L4+5"
                    layer_dist[lyr] = layer_dist.get(lyr, 0) + 1
                    layer_catches[lyr] += 1
                elif detected:
                    fp += 1
                elif is_attack:
                    fn += 1
                else:
                    tn += 1

        prec = tp / (tp + fp) if (tp + fp) else float("nan")
        rec = tp / (tp + fn) if (tp + fn) else float("nan")
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else float("nan")
        mcc_n = tp * tn - fp * fn
        mcc_d = math.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn)) \
                if (tp+fp)*(tp+fn)*(tn+fp)*(tn+fn) > 0 else 1

        results[name] = {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "total": tp + fp + tn + fn,
            "precision": prec, "recall": rec, "f1": f1,
            "mcc": mcc_n / mcc_d,
            "layer_dist": layer_dist,
        }

    results["__layer_catches__"] = layer_catches
    return results

# =============================================================================
# def print_results(...)
# =============================================================================

_W = 78

def _pct(v) -> str:
    return f"{v*100:.1f}%" if v == v else "  N/A "

def _rule(ch="═"):
    print("  " + ch * _W)

def print_results(results: dict, models: dict, constraints: dict):
    dataset_rows = {k: v for k, v in results.items() if not k.startswith("__")}
    layer_catches = results.get("__layer_catches__", {})

    print(); _rule("═")
    print(f"  {'ARINC 429  —  IDS Run Results':^{_W}}")
    _rule("═"); print()

    print("  Detection Results")
    _rule("─")
    print(f"  {'Dataset':<26}  {'TP':>4}  {'FP':>4}  {'TN':>4}  {'FN':>4}"
          f"  {'Prec':>7}  {'Recall':>7}  {'F1':>7}  {'MCC':>6}")
    _rule("─")

    grand = dict(tp=0, fp=0, tn=0, fn=0)
    for name, r in dataset_rows.items():
        if "error" in r:
            print(f"  {name:<26}  {r['error']}"); continue
        for k in grand: grand[k] += r[k]
        print(f"  {name:<26}  {r['tp']:>4}  {r['fp']:>4}  {r['tn']:>4}  {r['fn']:>4}"
              f"  {_pct(r['precision']):>7}  {_pct(r['recall']):>7}"
              f"  {_pct(r['f1']):>7}  {r['mcc']:>6.3f}")

    _rule("─")
    tp, fp, tn, fn = grand["tp"], grand["fp"], grand["tn"], grand["fn"]
    gp = tp / (tp+fp) if (tp+fp) else float("nan")
    gr = tp / (tp+fn) if (tp+fn) else float("nan")
    gf = 2*gp*gr / (gp+gr) if (gp+gr) else float("nan")
    mn = tp*tn - fp*fn
    md = math.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn)) \
         if (tp+fp)*(tp+fn)*(tn+fp)*(tn+fn) > 0 else 1
    print(f"  {'GRAND TOTAL':<26}  {tp:>4}  {fp:>4}  {tn:>4}  {fn:>4}"
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
    total_attacks = tp + fn
    print("  Layer Breakdown")
    _rule("─")
    print(f"  {'Key':<6}  {'Layer':<44}  {'Caught':>6}  {'%':>6}")
    _rule("─")
    for key, desc in _layer_desc.items():
        n = layer_catches.get(key, 0)
        pct = f"{100*n/total_attacks:.2f}%" if total_attacks else "—"
        print(f"  {key:<6}  {desc:<44}  {n:>6}  {pct:>6}")
    _rule("─"); print()

# =============================================================================
# def main()
# =============================================================================

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
