import csv
import os
import random
from datetime import datetime, timedelta

def generate_teleport_attack_csv(filename="data/teleport_attack.csv"):
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    LABEL_ALTITUDE = "203"
    BASE_ALT_FT = 30000.0
    ATTACK_FRAME_INDEX = 50
    SPOOFED_ALT_FT = 5000.0

    headers = ["frame_index", "timestamp", "label", "type", "value", "unit", "is_attack"]

    current_altitude = BASE_ALT_FT
    base_time = datetime.utcnow()

    print(f"Generating {filename}...")

    with open(filename, mode="w", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=headers)
        writer.writeheader()

        for i in range(100):
            timestamp = (base_time + timedelta(milliseconds=i * 20)).isoformat() + "Z"

            if i < ATTACK_FRAME_INDEX:
                current_altitude += random.uniform(-2.0, 2.0)
                is_attack = 0
            elif i == ATTACK_FRAME_INDEX:
                current_altitude = SPOOFED_ALT_FT
                is_attack = 1
                print(f"Injected teleport attack at frame {i}: {SPOOFED_ALT_FT} ft")
            else:
                current_altitude = SPOOFED_ALT_FT + random.uniform(-1.0, 1.0)
                is_attack = 0

            writer.writerow({
                "frame_index": i,
                "timestamp": timestamp,
                "label": LABEL_ALTITUDE,
                "type": "BNR",
                "value": round(current_altitude, 2),
                "unit": "feet",
                "is_attack": is_attack
            })

    print(f"Success. Teleport attack stream written to {filename}")

if __name__ == "__main__":
    generate_teleport_attack_csv()
