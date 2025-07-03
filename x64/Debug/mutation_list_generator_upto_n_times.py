from itertools import product

chars = ['l', 'u', 'r', 'c', 't', 'd', 's', 'n', '1', '2', '3', '4', '5', 'p']
max_len = 3
start_writing = False

with open("mutation_list.txt", "w", encoding="utf-8") as f:
    first = True
    
    f.write("# If mutator rules list is empty, mutation are disabled.\n")
    f.write("# However, if it is enabled, it will attempt to mutate\n")
    f.write("# each word depending on the rule.\n")
    f.write("\n")
    f.write("# normal = plain password without mutation.\n")
    f.write("# l = lowercase\n")
    f.write("# u = uppercase\n")
    f.write("# r = reverse\n")
    f.write("# c = capitalize first letter\n")
    f.write("# t = toggle case\n")
    f.write("# d = duplicate\n")
    f.write("# s = substitute sXY\n")
    f.write("# n = append numbers\n")
    f.write("# 1 = prepends !\n")
    f.write("# 2 = postpends !\n")
    f.write("# 3 = prepends @\n")
    f.write("# 4 = postpends @\n")
    f.write("# 5 = replaces @ with 4\n")
    f.write("# p = l33tsp3@k\n")
    f.write("\n")
    f.write("MUTATION_RULES=")
    f.write("normal, ")
    
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
