def check_layer1(timing_interval_us):
  L1_MIN = 4.75
  L1_MAX = 5.25

  if L1_MIN <= timing_interval_us <= L1_MAX:
      return True
  else:
      return False
