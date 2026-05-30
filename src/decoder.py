import json
with open("metadata.json", "r") as md:
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

