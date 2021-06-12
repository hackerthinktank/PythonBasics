#!/usr/bin/env python3.9
import subprocess 
import sys
import os

#Example python code for executing commands and returning clean stdout

#Take input and stuff in command input
command_input=input("Command to run\n")


"""
  command_input.split()
    -will break apart the command_input into a list for subprocess.run() using spaces as delimiters
  subprocess.run('ls','-l', '/', capture_output=True) -
    -would list the root directory and return the output
"""

process=(str(subprocess.run(command_input.split(), capture_output=True)))

"""
  left="stdout=b\'"
    -this is the left boundary of stdout output from subprocess.run()
  right="\', stderr=b" 
    -this is the right boundary of stdout output from subprocess.run()
  pre_return=(str(process[process.index(left)+len(left):process.index(right)])) 
    -this extracts the stdout from using the limits left and right
  clean_return=pre_return.replace('\\n','\n').replace('\\t','\t') 
    -this fixes the newline characters from our output
  print(clean_return)
    -prints the clean return
"""

left="stdout=b\'"
right="\', stderr=b"
pre_return=(str(process[process.index(left)+len(left):process.index(right)]))
clean_return=pre_return.replace('\\n','\n').replace('\\t','\t')
print(clean_return)

#Thats it -- pretty basic


