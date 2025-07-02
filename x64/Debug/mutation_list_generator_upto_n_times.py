from itertools import product

chars = ['l', 'u', 'r', 'c', 't', 'd', 's', 'n', '3']
max_len = 6
start_writing = False

with open("rule_combinations_no_lu_from_l_up_to_3.txt", "w", encoding="utf-8") as f:
    first = True
    for length in range(1, max_len + 1):
        for combo in product(chars, repeat=length):
            combo_str = ''.join(combo)
            # Skip combos containing both 'l' and 'u'
            if 'l' in combo_str and 'u' in combo_str:
                continue
            # Start writing once we reach the combo "l"
            if not start_writing:
                if combo_str == 'l':
                    start_writing = True
                else:
                    continue
            # Write combos separated by comma+space
            if not first:
                f.write(", ")
            f.write(combo_str)
            first = False


print("Done")
