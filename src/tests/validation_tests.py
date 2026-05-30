import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


from decoder import decode
print(decode("10000000000000000000000000110000"))
