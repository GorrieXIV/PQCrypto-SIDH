'''
Benchmarking script
'''

import sys, os

sig_runs = 0
batched_runs = 0
compressed_runs = 3

# run signature test
exec_call = ".././sig_test " + str(sig_runs) + " " + str(batched_runs) + " " + str(compressed_runs) + " > signature_benchmarks"
os.system(exec_call)

# vanilla_avg, vanilla_stddev, batched_avg, batched_stddev, compressed_avg, compressed_stddev

# process output
vanilla_keygen_avg = 0
vanilla_sign_avg = 0
vanilla_verify_avg =0
batched_keygen_avg = 0
batched_sign_avg = 0
batched_verify_avg = 0
compressed_keygen_avg = 0
compressed_sign_avg = 0
compressed_verify_avg = 0
i = 1
j = 0 
with open("signature_benchmarks") as file:
  for line in file:
    if (i <= sig_runs):
      if (j == 3):
        j = 0
        i += 1
        continue
      if (j == 0):
        vanilla_keygen_avg += int(line)
      elif(j == 1):
        vanilla_sign_avg += int(line)
      elif(j == 2):
        vanilla_verify_avg += int(line)
    elif (i <= sig_runs + batched_runs):
      if (j == 0):
        batched_keygen_avg += int(line)
      elif(j == 1):
        batched_sign_avg += int(line)
      elif(j == 2):
        batched_verify_avg += int(line)
    else:
      if (j == 0):
        compressed_keygen_avg += int(line)
      elif(j == 1):
        compressed_sign_avg += int(line)
      elif(j == 2):
        compressed_verify_avg += int(line)
    j += 1

if (sig_runs != 0):
  vanilla_keygen_avg = vanilla_keygen_avg / sig_runs
  vanilla_sign_avg = vanilla_sign_avg / sig_runs
  vanilla_verify_avg = vanilla_verify_avg / sig_runs
  print(vanilla_keygen_avg)
  print(vanilla_sign_avg)
  print(vanilla_verify_avg)
 
if (batched_runs != 0):
  batched_keygen_avg = batched_keygen_avg / batched_runs
  batched_sign_avg = batched_sign_avg / batched_runs
  batched_verify_avg = batched_verify_avg / batched_runs
  print(batched_keygen_avg)
  print(batched_sign_avg)
  print(batched_verify_avg)

if (compressed_runs != 0):
  compressed_keygen_avg = compressed_keygen_avg / compressed_runs
  compressed_sign_avg = compressed_sign_avg / compressed_runs
  compressed_verify_avg = compressed_verify_avg / compressed_runs
  print(compressed_keygen_avg)
  print(compressed_sign_avg)
  print(compressed_verify_avg)
