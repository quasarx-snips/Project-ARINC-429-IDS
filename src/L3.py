def L3(word: str, label: str, label_name: str,
        rules: dict, constraints: dict,
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
        if delta_abs > rules["max_delta"]:
            if label in models:
                models[label].reset()
            telemetry.pop(label, None)
            return ({"layer": "L3", "msg": "Teleportation"}, delta_abs, value)

    return None, delta_abs, value
