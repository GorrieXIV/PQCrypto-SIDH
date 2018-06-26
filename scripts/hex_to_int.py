i = 0
with open("psiS_test_5") as input:
  for line in file:
    if (i == 0):
      line = line.strip("Sign A: [")
      a.append(int(line,16))
    elif (i == 1):
      line = line.strip("b: ")
      b.append(int(line,16))
    elif (i == 2):
      line = line.strip("comp: ")
      comp.append(int(line,16))
    elif (i == 3):
      line = line.strip("bit: ")
    elif (i == 4):  
  i = (i + 1) % 4
  
  
print('A: [{:d},'.format(A1) + '{:d}]'.format(A2))
print('psi(S).x: [{:d},'.format(psiSx1) + '{:d}]'.format(psiSx2))
print('psi(S).y: [{:d},'.format(psiSy1) + '{:d}]'.format(psiSy2))
print('R1.x: [{:d},'.format(R1x1) + '{:d}]'.format(R1x2))
print('R1.y: [{:d},'.format(R1y1) + '{:d}]'.format(R1y2))
print('R2.x: [{:d},'.format(R2x1) + '{:d}]'.format(R2x2))
print('R2.y: [{:d},'.format(R2y1) + '{:d}]'.format(R2x2))
print('a: {:d}'.format(a))
print('b: {:d}'.format(b))
