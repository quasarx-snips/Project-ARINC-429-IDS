import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE_DIR, "metadata.json"), "r") as md:
   metadata = json.load(md)

#sample = "10000000000000000000000000110000"
def decode(sample):
  label_bits = sample[-8:][::-1]
  label_octal = oct(int(label_bits, 2))[2:].zfill(3)

  sdi_bits = sample[-10:-8]
  data_bits = sample[-29:-10]
  ssm_bits = sample[-31:-29]
  parity_bit = sample[-32]

  result = {
      "label": label_octal,
      "name": metadata["labels"][label_octal]["name"],
      "sdi": {
          "code": sdi_bits,
          "description": metadata["sdi"][sdi_bits]
      },
      "data": int(data_bits, 2),
      "ssm": {
          "code": ssm_bits,
          "description": metadata["ssm_bnr"][ssm_bits]
      },
      "parity": parity_bit
  }

  return result

def layer_2_parity_check(word_32bit: str) -> dict:
    """
    Validates odd parity across a 32-bit ARINC 429 word.
    """
    # 1. Handle None or non-string inputs
    if not word_32bit or not isinstance(word_32bit, str):
        return {"status": "ALERT", "reason": "Input is None or not a string"}

    # 2. Clean and validate length
    word = word_32bit.strip()
    if len(word) != 32:
        return {"status": "ALERT", "reason": f"Invalid frame length: {len(word)}"}

    # 3. Calculate parity
    ones_count = word.count('1')

    # 4. Odd parity check
    if ones_count % 2 != 0:
        return {"status": "PASS"}
    else:
        return {"status": "ALERT", "reason": "Parity failure: Even number of 1s detected"}
