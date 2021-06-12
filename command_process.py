#!/usr/bin/env python3.9
import subprocess 
import sys
import os
import re
import copy

left="stdout=b\'"
right="\', stderr=b"
command_input=input("Command to run\n")
process=(str(subprocess.run(command_input.split(), capture_output=True)))
pre_return=(str(process[process.index(left)+len(left):process.index(right)]))
clean_return=pre_return.replace('\\n','\n').replace('\\t','\t')
print(clean_return)




