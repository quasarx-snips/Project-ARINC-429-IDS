def parity_check(word):
    one_count = 0
    
    for character in word:
        if character == "1":
            one_count = one_count + 1
    if one_count % 2 != 0:
        return True
    else:
        return False
