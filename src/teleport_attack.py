import csv
import os
import random
from datetime import timedelta

def calculate_odd_parity(bit_string):
    return '1' if bit_string.count('1') % 2 == 0 else '0'

def generate_teleport_attack_csv(filename="data/teleport_attack.csv"):
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    LABEL_203_WIRE_BIN = "11000001"
    SDI_BIN = "00"
    SSM_BIN = "00"
    BASE_ALT_FT = 30000.0
    ATTACK_FRAME_INDEX = random.randint(10,90)
    SPOOFED_ALT_FT = 5000.0

    headers = ["frame_number", "arinc_transmission_received", "time (MM:SS:mmm)", "is_attack"]
    current_altitude = BASE_ALT_FT

    with open(filename, mode="w", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=headers)
        writer.writeheader()

        for i in range(100):
            
            elapsed_time = timedelta(milliseconds=i * 20)
            minutes = int(elapsed_time.total_seconds()) // 60
            seconds = total_seconds % 60
            milliseconds = int(elapsed_time.microseconds / 1000)
            # Format as MM:SS:mmm (e.g., 01:23:450)
            timestamp = f"{minutes:02d}:{seconds:02d}:{milliseconds:03d}"

            if i < ATTACK_FRAME_INDEX:
                current_altitude += random.uniform(-2.0, 2.0)
                is_attack = False
            elif i == ATTACK_FRAME_INDEX:
                current_altitude = SPOOFED_ALT_FT
                is_attack = True
            else:
                current_altitude = SPOOFED_ALT_FT + random.uniform(-1.0, 1.0)
                is_attack = False

            data_bin = format(int(max(0, current_altitude)), '019b')

            bits_31_to_1 = SSM_BIN + data_bin + SDI_BIN + LABEL_203_WIRE_BIN
            arinc_word_32_to_1 = calculate_odd_parity(bits_31_to_1) + bits_31_to_1

            writer.writerow({
                "frame_number": i,
                "arinc_transmission_received": arinc_word_32_to_1,
                "time (MM:SS:mmm)": timestamp,
                "is_attack": is_attack
            })

generate_teleport_attack_csv()
