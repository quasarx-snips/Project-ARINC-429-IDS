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
