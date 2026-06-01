import csv
import os
import random

def calculate_odd_parity(bit_string):
    return '1' if bit_string.count('1') % 2 == 0 else '0'

def generate_parity_poison_csv(filename="data/parity_poison.csv"):
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    LABEL_203_WIRE_BIN = "11000001"
    SDI_BIN = "00"
    SSM_BIN = "00"
    ATTACK_FRAME_INDEX = random.randint(10, 90)

    current_altitude = 30000.0

    with open(filename, mode="w", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=["frame_number", "arinc_transmission_received", "time", "is_attack"])
        writer.writeheader()

        for i in range(100):
            current_altitude += random.uniform(-2.0, 2.0)

            bits_31_to_1 = SSM_BIN + format(int(max(0, current_altitude)), '019b') + SDI_BIN + LABEL_203_WIRE_BIN
            correct_parity = calculate_odd_parity(bits_31_to_1)

            writer.writerow({
                "frame_number": i,
                "arinc_transmission_received": (('0' if correct_parity == '1' else '1') if i == ATTACK_FRAME_INDEX else correct_parity) + bits_31_to_1,
                "time": f"{(i * 20) // 60000:02d}:{((i * 20) // 1000) % 60:02d}:{(i * 20) % 1000:03d}",
                "is_attack": i == ATTACK_FRAME_INDEX
            })

generate_parity_poison_csv()
