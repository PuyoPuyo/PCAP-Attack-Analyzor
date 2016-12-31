
import sys
from PyQt4 import QtGui, QtCore

class Window(QtGui.QMainWindow):
	
	def __init__(self):
		super(Window, self).__init__()
		self.setGeometry(100, 100, 500, 500)
		self.setWindowTitle("PCAP-Attack-Analyzor")
		self.setWindowIcon(QtGui.QIcon('Audit.png'))
		self.ExecButton()
		self.show()
	def ExecButton(self):
		btn = QtGui.QPushButton("Execute", self)
		btn.resize(btn.sizeHint())
		btn.move(200,100)
	def MenuBar(self):
		


def run():
	app = QtGui.QApplication(sys.argv)
	GUI = Window()
	sys.exit(app.exec_())

run()
