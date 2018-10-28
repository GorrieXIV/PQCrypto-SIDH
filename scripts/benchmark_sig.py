'''
Benchmarking script
'''

import sys, os, math
from matplotlib import pyplot

sig_runs = 0
batched_runs = 20
compressed_runs = 0

# run signature test
exec_call = ".././sig_test " + str(sig_runs) + " " + str(batched_runs) + " " + str(compressed_runs) + " > signature_benchmarks"
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

    else:
      if (j == 0):
        print("cycle time for compressed signature " + str(i+1-sig_runs-batched_runs) + " sign: " + str(line)[:-1])
        compressed_sign_avg += int(line)
        compressed_sign_stddev_list.append(int(line))
      elif(j == 1):
        print("cycle time for compressed signature " + str(i+1-sig_runs-batched_runs) + " sign: " + str(line)[:-1])
        compressed_verify_avg += int(line)
        compresseD_verify_stddev_list.append(int(line))

    j += 1
print("-------------------------------------------------------------")


vanilla_sign_stddev = 0
vanilla_verify_stddev = 0

batched_sign_stddev = 0
batched_verify_stddev = 0

compressed_sign_stddev = 0
compressed_verify_stddev = 0

# compute and display vanilla signature average runtime and standard deviation
if (sig_runs != 0):
  vanilla_sign_avg = vanilla_sign_avg / sig_runs
  vanilla_verify_avg = vanilla_verify_avg / sig_runs
  print("signature sign average: " + str(vanilla_sign_avg))
  print("signature verify average: " + str(vanilla_verify_avg))
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

