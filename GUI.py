#!/usr/bin/python

from Tkinter import *
import tkMessageBox
from ScrolledText import ScrolledText
import tkFont
import multiprocessing
import time
import ip
import firewall


class Application(Frame):

	def __init__(self, master):
		"""Creating GUI instance"""
		Frame.__init__(self, master)
		self.output = multiprocessing.Queue() # Queue used to hold output from processes called
		self.stopped = False # False unless a threat is found (used for if/else cases in displaying to GUI)
		self.threat = False # False until threat is found
		self.create_widgets() 

	def create_widgets(self):
		"""Create all widgets in GUI"""
		self.pack(fill=BOTH, expand=1)

		self.columnconfigure(1, weight=1)
		self.columnconfigure(3, pad=7)
		self.rowconfigure(3, weight=1)
		self.rowconfigure(5, pad=7)

		helv = tkFont.Font(family='Cambria', size=10)

		self.instr = Label(self, text="Choose option:")
		self.instr['font'] = helv
		self.instr.grid(sticky=W, pady=4, padx=5)

		# Create textbox
		self.results = ScrolledText(self, undo=True)
		self.results['font'] = helv
		self.results.grid(row=1, column=1, columnspan=2, rowspan=4, padx=5, sticky=E+W+S+N)

		#Create firewall log button
		self.firewall_log = Button(self, text='Firewall Log', command=lambda: self.scan_log(self.results))
		self.firewall_log.grid(row=1, column=0)
		self.firewall_log['font'] = helv

		#create checkbox
		cvar = IntVar()
		self.cont = Checkbutton(self, text='Continuous?', variable=cvar)
		self.cont['font'] = helv
		self.cont.grid(row=5, column=0, padx=5)

		#create run scan button
		self.run = Button(self, text='Run Scan', command=lambda: self.start(cvar, self.results))
		self.run.grid(row=2, column=0)
		self.run['font'] = helv

		#Create stop/exit button
		self.exit = Button(self, text='Exit', command=self.stop)
		self.exit.grid(row=5, column=2, pady=4, padx=4)
		self.exit['font'] = helv


	def start(self, var, textbox):
		"""Begins monitoring of a computer's connections, either one
		time or continuously"""
		self.exit['text'] = 'Stop'
		self.p = multiprocessing.Process(None, lambda: ip.display_info(self.output, var.get(), self))
		self.p.start()
		self.after(500, lambda: self.check_proc(textbox))

	def stop(self):
		"""Stops the program from running"""
		if self.exit['text'] == 'Exit': # Quits when no processes are running
			self.destroy()
			self.quit()
		else: # Stops a process and then quits
			self.p.terminate()
			self.p.join()
			self.destroy()
			self.quit()

	def check_proc(self, textbox):
		"""Continually checks if processes are still alive
		and calls display_box when all are not alive"""
		if not self.p.is_alive(): # If no processes are alive
			out = self.output.get() 
			if out == True: # first item will be True if continuous mode running and a threat is found
				threats = self.output.get()
				self.p.terminate()
				self.p.join()
				self.exit['text'] = 'Exit'
				self.threat_alert(threats) # create threat alert
			else:
				self.p.terminate()
				self.p.join()
				self.exit['text'] = 'Exit'
			if self.stopped == False: # When no processes are alive, display output to GUI
				self.display_box(textbox, out)
		else:
			self.after(500, lambda: self.check_proc(textbox)) #continusously check if process is alive

	def scan_log(self, textbox):
		"""Scans firewall log, calls function in  firewall.py"""
		IPs = firewall.read_log('log.txt') 
		ip.display_firewall(self.output, IPs, self)
		self.display_box(textbox, self.output.get())

	def display_box(self, textbox, results):
		"""Displays output to textbox on GUI"""
		textbox.insert(END, results)
			
	
	def threat_alert(self, val):
		"""Creates an alert if an IP is found in the Alienvault database"""
		self.stopped = True
		tkMessageBox.showwarning("Alert", "The address " + val[0] + " has been identified as malicious\nType: " + str(val[1]) + "\nReliability: " + str(val[2]) + "\nRisk: " + str(val[3]))


def main():
	window = Tk()
	window.title('IP Utility')
	window.geometry('350x300+300+300')
	app = Application(window)
	window.mainloop()

if __name__ == '__main__':
	main()


