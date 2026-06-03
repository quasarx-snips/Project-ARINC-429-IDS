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

    return {"nn_score": round(nn_score, 1)}
