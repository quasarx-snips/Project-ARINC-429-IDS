import csv
import os
import random

def calculate_odd_parity(bit_string):
    return '1' if bit_string.count('1') % 2 == 0 else '0'

def generate_replay_attack_csv(filename="data/replay_attack.csv"):
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    current_altitude = 30000.0
    capture_buffer = []

    with open(filename, mode="w", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=["frame_number", "arinc_transmission_received", "time", "is_attack"])
        writer.writeheader()

        for i in range(100):
            current_altitude += random.uniform(-2.0, 2.0)

            bits_31_to_1 = "00" + format(int(max(0, current_altitude)), '019b') + "0011000001"
            word_32_to_1 = calculate_odd_parity(bits_31_to_1) + bits_31_to_1
            timestamp = f"{(i * 20) // 60000:02d}:{((i * 20) // 1000) % 60:02d}:{(i * 20) % 1000:03d}"

            if 20 <= i < 30:
                capture_buffer.append((word_32_to_1, timestamp))

            is_replay = 70 <= i < 80

            writer.writerow({
                "frame_number": i,
                "arinc_transmission_received": capture_buffer[i - 70][0] if is_replay else word_32_to_1,
                "time": capture_buffer[i - 70][1] if is_replay else timestamp,
                "is_attack": is_replay
            })

generate_replay_attack_csv()
