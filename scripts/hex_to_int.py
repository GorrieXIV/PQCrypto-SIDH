TEST_CASE_NUMBER = 0

inputs = []
#i = TEST_CASE_NUMBER * 9
i = 0
with open("psiS_test_values") as input:
  for line in input:
    if (i == 0):
      inputs.append(line)
    elif (i == 1):
      inputs.append(line)
    elif (i == 2):
      inputs.append(line)
    elif (i == 3):
      inputs.append(line)
    elif (i == 4):
      inputs.append(line)
    elif (i == 5):
      inputs.append(line)
    elif (i == 6):
      inputs.append(line)
    elif (i == 7):
      inputs.append(line)
    elif (i == 8):
      inputs.append(line)
    ++i
    if (i > 8): 
      break

def replace_line(file_name, line_num, data):
  line_num = line_num - 1
  lines = open(file_name, 'r').readlines()
  lines[line_num] = data
  out = open(file_name, 'w')
  out.writelines(lines)
  out.close()

replace_line('TestPsiS.mag', 31, inputs[0])
replace_line('TestPsiS.mag', 42, inputs[1])
replace_line('TestPsiS.mag', 44, inputs[2])
replace_line('TestPsiS.mag', 51, inputs[3])
replace_line('TestPsiS.mag', 53, inputs[4])
replace_line('TestPsiS.mag', 58, inputs[5])
replace_line('TestPsiS.mag', 60, inputs[6])
replace_line('TestPsiS.mag', 65, inputs[7])
replace_line('TestPsiS.mag', 68, inputs[8])
