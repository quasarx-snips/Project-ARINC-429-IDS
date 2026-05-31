import math 
def shannon_entropy(data):
  def p(x):
     return float(data.count(x)) / len(data)
  return -sum(p(x) * math.log(p(x), 2) for x in set(data))
def normalized_shannon_entropy(data):
    h = shannon_entropy(data) 
    max_h = math.log2(len(data))
    return (h / max_h)*100 # Normalized to 0-100 scale
