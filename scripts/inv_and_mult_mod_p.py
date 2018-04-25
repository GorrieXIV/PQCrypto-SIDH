a = []
b = []
comp = []
bit = []

# p stores the working modulus
p = 'C968549F878A8EEB59B1A13F7CC76E3EE9867D6EBE876DA92B5045CB257480842909F97BADC6685606FE5D541F71C0E1'
p = int(p, 16)

i = 0
with open("abcomp_output") as file:
	for line in file:
		if (i == 0):
			line = line.strip("a: ")
			a.append(int(line,16))
		elif (i == 1):
			line = line.strip("b: ")
			b.append(int(line,16))
		elif (i == 2):
			line = line.strip("comp: ")				
			comp.append(int(line,16))
		elif (i == 3):
			line = line.strip("bit: ")
			bit.append(int(line))
		i = (i + 1) % 4

for q in range(0, len(a)):
    if (bit[q] == 1):
        ainv = pow (a[q], p-2, p)
        rcomp = (ainv * b[q]) % p
        print(str(comp[q] == rcomp))
    else:
        binv = pow(b[q], p-2, p)
        rcomp = (binv * a[q]) % p
        print(str(comp[q] == rcomp))
