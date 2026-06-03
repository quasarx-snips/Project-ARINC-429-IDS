def L2(word: str, ts_ms, ts_state: list,
        label: str, label_name: str,
        replay: dict, telemetry: dict, models: dict) -> dict | None:
    if ts_ms is not None and ts_state[0] is not None and ts_ms < ts_state[0]:
        telemetry.clear()
        for m in models.values():
            m.reset_ewma()
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
