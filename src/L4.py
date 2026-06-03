def L4(delta_abs: float, model: LabelModel) -> dict:
    ewma_hard = False
    ewma_score = 0.0
    zs_score = 0.0

    thresh = model.ewma_threshold
    if thresh is not None and model.n_clean >= L4_WARMUP and delta_abs > thresh:
        ewma_hard = True
        ratio = delta_abs / max(thresh, 1e-9)
        ewma_score = min(100.0, (ratio - 1.0) * 50.0 + 50.0)

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
