signA = []
verifyA = []
verifyIndexes = []

i = 0
with open("A_output") as file:
  for line in file:
    if (line[:1] == 'S'):
      line = line[12:]
      line = line.strip()
      signA.append(int(line))
    elif (line[:1] == 'V'):
      line = line[9:]
      verifyIndexes.append(int(line.rsplit(']', 1)[0]))
      line = line[5:]
      line = line.strip()
      verifyA.append(int(line))

for q in range(0, len(verifyIndexes)):
  print(signA[(verifyIndexes[q])] == verifyA[q])
