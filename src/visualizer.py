import pandas as pd
import matplotlib.pyplot as plt
import os

# ── 1. Helper: Robust Parsing ──────────────────────────────────────────────────
def parse_arinc_bits(binary_val):
    word = str(binary_val)
    word = word.zfill(32)
    label_bin = word[-8:][::-1]
    label = int(label_bin, 2)
    payload_bin = word[3:22]
    payload = int(payload_bin, 2)

    return label, payload

# ── 2. Helper: Time conversion ────────────────────────────────────────────────
def convert_to_seconds(t_str):
    try:
        parts = str(t_str).split(':')
        return int(parts[0]) * 60 + int(parts[1]) + (int(parts[2]) / 1000 if len(parts) > 2 else 0)
    except:
        return 0.0

# ── 3. Processing Engine ──────────────────────────────────────────────────────
def process_file(file_path):
    print(f"... Processing {file_path}...")

    if not os.path.exists(file_path):
        print(f"    [!] File not found: {file_path}")
        return

    df = pd.read_csv(file_path)

    parsed = df['arinc_transmission_received'].apply(parse_arinc_bits)
    df['lbl'] = [x[0] for x in parsed]
    df['val'] = [x[1] for x in parsed]

    time_col = 'time' if 'time' in df.columns else 'time (MM:SS:mmm)'
    df['s'] = df[time_col].apply(convert_to_seconds)

    df['is_attack'] = df['is_attack'].astype(bool)

    # ── 4. Plotting ───────────────────────────────────────────────────────────
    unique_labels = df['lbl'].unique()
    fig, axes = plt.subplots(len(unique_labels), 1, figsize=(12, 4 * len(unique_labels)), sharex=True)
    if len(unique_labels) == 1: axes = [axes]

    for ax, label in zip(axes, unique_labels):
        subset = df[df['lbl'] == label]

        # Plot Normal (Blue)
        normal = subset[~subset['is_attack']]
        ax.scatter(normal['s'], normal['val'], s=10, c='blue', label='Normal', alpha=0.5)

        # Plot Attacks (Red X)
        attacks = subset[subset['is_attack']]
        ax.scatter(attacks['s'], attacks['val'], s=60, c='red', marker='x', label='Attack')

        ax.set_title(f"Label: {oct(label)[2:]} (Octal ID)")
        ax.legend()
        ax.grid(True, linestyle='--')

    plt.tight_layout()
    os.makedirs('plots', exist_ok=True)
    save_path = f"plots/visual_{os.path.basename(file_path).replace('.csv', '.png')}"
    plt.savefig(save_path)
    plt.close()
    print(f" Saved: {save_path}")

# ── 5. Main Execution ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    files = [
        "L1A_parity_poison.csv", 
        "L1B_timing_attack.csv", 
        "L2A_replay_attack.csv",
        "L2B_replay_dedup.csv", 
        "L3_teleport_attack.csv", 
        "L3_value_bounds.csv",
        "L4L5_statistical_anomaly.csv"
    ]

    for f in files:
        process_file(f)
    print("\nAll files processed successfully.")
