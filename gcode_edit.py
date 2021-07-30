#!/usr/bin/env python3
import fileinput
import re
import sys

"Usage gcode_edit.py gcodeprogram.gcode axis offset -- gcode_edit.py program.gcode X -25"
with fileinput.FileInput(sys.argv[1], inplace=True, backup='.bak') as file:
    for line in file:
        elements = re.split(' ', line)
        for i in range(len(elements)):
            if (elements[i].find(str(sys.argv[2])) != -1):
                axis_integer=round(float((elements[i])[1:])-float(sys.argv[3])),4)
                "This assumes that your orgin is the lower left of the table. If it is the center of the table comment out these two lines."
                if (axis_integer < 0):
                    axis_integer=0
                elements[i]=(str(sys.argv[2])+str(axis_integer))
        fixed_line = ' '.join(elements)
        print(fixed_line, end='')
