'''
Benchmarking script
'''

import sys, os, math
from matplotlib import pyplot


def plot_and_save(sign_points, verify_points, title, file_name):
  x = list(range(len(sign_points)))
  pyplot.scatter(x, sign_points, label='Sign Cycles', c='blue')
  pyplot.scatter(x, verify_points, label='Verify Cycles', c='red')
  pyplot.title(title)
  pyplot.ylabel('Cycles')
  pyplot.xlabel('Iteration #')
  pyplot.legend(loc='upper left')
  pyplot.savefig(file_name)
  pyplot.clf()


sig_runs = 0 
batched_runs = 0
compressed_runs = 5
CB_runs = 5

# run signature test
exec_call = ".././sig_test " + str(sig_runs) + " " + str(batched_runs) + " " + str(compressed_runs) + " " + str(CB_runs) + " > signature_benchmarks"
print("running \"" + exec_call + "\":")
print("...please wait... \n")
os.system(exec_call)


vanilla_sign_avg = 0
vanilla_verify_avg = 0
vanilla_sign_stddev_list = []
vanilla_verify_stddev_list = []

batched_sign_avg = 0
batched_verify_avg = 0
batched_sign_stddev_list = []
batched_verify_stddev_list = []

compressed_sign_avg = 0
compressed_verify_avg = 0
compressed_sign_stddev_list = []
compressed_verify_stddev_list = []

CB_sign_avg = 0
CB_verify_avg = 0
CB_sign_stddev_list = []
CB_verify_stddev_list = []

i = 0
j = 0 

print("-------------------------------------------------------------")
with open("signature_benchmarks") as file:
  for line in file:
    if (j == 2):
      j = 0
      i += 1

    if (i < sig_runs):
      if (j == 0):
        print("cycle time for signature " + str(i+1) + " sign: " + str(line)[:-1])
        vanilla_sign_avg += int(line)
        vanilla_sign_stddev_list.append(int(line))
      elif(j == 1):
        print("cycle time for signature " + str(i+1) + " verify: " + str(line)[:-1])
        vanilla_verify_avg += int(line)
        vanilla_verify_stddev_list.append(int(line))

    elif (i < sig_runs + batched_runs):
      if (j == 0):
        print("cycle time for batched signature " + str(i+1-sig_runs) + " sign: " + str(line)[:-1])
        batched_sign_avg += int(line)
        batched_sign_stddev_list.append(int(line))
      elif(j == 1):
        print("cycle time for batched signature " + str(i+1-sig_runs) + " verify: " + str(line)[:-1])
        batched_verify_avg += int(line)
        batched_verify_stddev_list.append(int(line))

    elif (i < sig_runs + batched_runs + compressed_runs):
      if (j == 0):
        print("cycle time for compressed signature " + str(i+1-sig_runs-batched_runs) + " sign: " + str(line)[:-1])
        compressed_sign_avg += int(line)
        compressed_sign_stddev_list.append(int(line))
      elif(j == 1):
        print("cycle time for compressed signature " + str(i+1-sig_runs-batched_runs) + " verify: " + str(line)[:-1])
        compressed_verify_avg += int(line)
        compressed_verify_stddev_list.append(int(line))
    else:
      if (j == 0):
        print("cycle time for CB signature " + str(i+1-sig_runs-batched_runs-compressed_runs) + " sign: " + str(line)[:-1])
        CB_sign_avg += int(line)
        CB_sign_stddev_list.append(int(line))
      elif(j == 1):
        print("cycle time for CB signature " + str(i+1-sig_runs-batched_runs-compressed_runs) + " verify: " + str(line)[:-1])
        CB_verify_avg += int(line)
        CB_verify_stddev_list.append(int(line))

    j += 1
print("-------------------------------------------------------------")

vanilla_sign_stddev = 0
vanilla_verify_stddev = 0

batched_sign_stddev = 0
batched_verify_stddev = 0

compressed_sign_stddev = 0
compressed_verify_stddev = 0

CB_sign_stddev = 0
CB_verify_stddev = 0

# compute and display vanilla signature average runtime and standard deviation
if (sig_runs != 0):
  plot_and_save(vanilla_sign_stddev_list, vanilla_verify_stddev_list, 'Performance Measurements - Unmodified Scheme', 'vanilla_cycles.pdf')
  vanilla_sign_avg = vanilla_sign_avg / sig_runs
  vanilla_verify_avg = vanilla_verify_avg / sig_runs
  print("vanilla signature sign average: " + str(vanilla_sign_avg))
  print("vanilla signature verify average: " + str(vanilla_verify_avg))
  for q in range (0, sig_runs-1):
    vanilla_sign_stddev_list[q] = (vanilla_sign_stddev_list[q] - vanilla_sign_avg)**(2)
    vanilla_verify_stddev_list[q] = (vanilla_verify_stddev_list[q] - vanilla_verify_avg)**(2)
    vanilla_sign_stddev += vanilla_sign_stddev_list[q]
    vanilla_verify_stddev += vanilla_verify_stddev_list[q]
  vanilla_sign_stddev = math.sqrt(vanilla_sign_stddev / sig_runs)
  vanilla_verify_stddev = math.sqrt(vanilla_verify_stddev / sig_runs)
  print("vanilla signature sign standard deviation: " + str(vanilla_sign_stddev))
  print("vanilla signature verify standard deviation: " + str(vanilla_verify_stddev))
 
# compute and display batched signature average runtime and standard deviation
if (batched_runs != 0):
  plot_and_save(batched_sign_stddev_list, batched_verify_stddev_list, 'Performance Measurements - With Batching', 'batched-cycles.pdf')
  batched_sign_avg = batched_sign_avg / batched_runs
  batched_verify_avg = batched_verify_avg / batched_runs
  print("batched signature sign average: " + str(batched_sign_avg))
  print("batched signature verify average: " + str(batched_verify_avg))
  for q in range (0, batched_runs-1): 
    batched_sign_stddev_list[q] = (batched_sign_stddev_list[q] - batched_sign_avg)**(2)
    batched_verify_stddev_list[q] = (batched_verify_stddev_list[q] - batched_verify_avg)**(2)
    batched_sign_stddev += batched_sign_stddev_list[q]
    batched_verify_stddev += batched_verify_stddev_list[q]
  batched_sign_stddev = math.sqrt(batched_sign_stddev / batched_runs)
  batched_verify_stddev = math.sqrt(batched_verify_stddev / batched_runs)
  print("batched signature sign standard deviation: " + str(batched_sign_stddev))
  print("batched signature verify standard deviation: " + str(batched_verify_stddev))

# compute and display compressed signature average runtime and standard deviation
if (compressed_runs != 0): 
  plot_and_save(compressed_sign_stddev_list, compressed_verify_stddev_list, 'Performance Measurements - Compressed Signatures', 'compressed-cycles.pdf')
  compressed_sign_avg = compressed_sign_avg / compressed_runs
  compressed_verify_avg = compressed_verify_avg / compressed_runs
  print("compressed signature sign average: " + str(compressed_sign_avg))
  print("compressed signature verify average: " + str(compressed_verify_avg))
  for q in range (0, compressed_runs-1):
    compressed_sign_stddev_list[q] = (compressed_sign_stddev_list[q] - compressed_sign_avg)**(2)
    compressed_verify_stddev_list[q] = (compressed_verify_stddev_list[q] - compressed_verify_avg)**(2)
    compressed_sign_stddev += compressed_sign_stddev_list[q]
    compressed_verify_stddev += compressed_verify_stddev_list[q]
  compressed_sign_stddev = math.sqrt(compressed_sign_stddev / compressed_runs)
  compressed_verify_stddev = math.sqrt(compressed_verify_stddev / compressed_runs)
  print("compressed signature sign standard deviation: " + str(compressed_sign_stddev))
  print("compressed signature verify standard deviation: " + str(compressed_verify_stddev))


# compute and display C+B signature average runtime and standard deviation
if (CB_runs != 0): 
  plot_and_save(CB_sign_stddev_list, CB_verify_stddev_list, 'Performance Measurements - Compressed Signatures with Batching', 'CB-cycles.pdf')
  CB_sign_avg = CB_sign_avg / CB_runs
  CB_verify_avg = CB_verify_avg / CB_runs
  print("C + B signature sign average: " + str(CB_sign_avg))
  print("C + B signature verify average: " + str(CB_verify_avg))
  for q in range (0, CB_runs-1):
    CB_sign_stddev_list[q] = (CB_sign_stddev_list[q] - CB_sign_avg)**(2)
    CB_verify_stddev_list[q] = (CB_verify_stddev_list[q] - CB_verify_avg)**(2)
    CB_sign_stddev += CB_sign_stddev_list[q]
    CB_verify_stddev += CB_verify_stddev_list[q]
  CB_sign_stddev = math.sqrt(CB_sign_stddev / CB_runs)
  CB_verify_stddev = math.sqrt(CB_verify_stddev / CB_runs)
  print("C + B signature sign standard deviation: " + str(CB_sign_stddev))
  print("C + B signature verify standard deviation: " + str(CB_verify_stddev))

