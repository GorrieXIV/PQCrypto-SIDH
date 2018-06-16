'''
this script is used to run the TestPsiS.mag magma script
first, sig_test.c is run and the output is funnelled into psi_test_values
then the values are serially fed into TestPsiS.mag at the right locations
then TestPsiS is run, checking the validity of PsiS

From sig_test.c we need:
- the A value of every iteration
- psi(S) of every iteration
- R1 of every iteration
- R2 of every iteration
- a of every iteration
- b of every iteration
- bit of every iteration
'''

Alist = []
psiS_x_list = []
psiS_y_list = []
R1_x_list = []
R1_y_list = []
R2_x_list = []
R2_y_list = []
alist = []
blist = []
bits = []

i = 0
with open("psiS_test_values") as file:
  for line in file:
    if (i == 0):
      line = line.strip("Sign A.1: ")
      Alist.append(int(line))
    elif (i == 1):
      line = line.strip("Sign psi(S).x: ")
      psiS_x_list.append(int(line))
    elif (i == 2):
      line = line.strip("Sign psi(S).y: ")
      psiS_y_list.append(int(line))
    elif (i == 3):  
      line = line.strip("Sign R1.x: ")
      R1_x_list.append(int(line))
    elif (i == 4):
      line = line.strip("Sign R1.y: ")
      R1_x_list.append(int(line))
    elif (i == 5):
      line = line.strip("Sign R2.x: ")
      R2_x_list.append(int(line))
    elif (i == 6):
      line = line.strip("Sign R2.y: ")
      R2_y_list.append(int(line))
    elif (i == 7):
      line = line.strip("Sign a: ")
      alist.append(int(line))
    elif (i == 8):
      line = line.strip("Sign b: ")
      blist.append(int(line))
    elif (i == 9):
      line = line.strip("Sign bit: ")
      bits.append(int(line))
    i = (i + 1) % 10

print (alist[0])
print (blist[5])
print (Alist[1])
print (bits[7])
