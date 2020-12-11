import sys
import os
import time
import subprocess

import chart
import nmap

from PyQt5 import QtGui, QtCore
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *

from templates.main import Ui_Form as ui_main
from templates.scan import Ui_Form as ui_scan
from templates.report import Ui_Form as ui_report


class Worker(QRunnable):
    '''
    Worker thread
    '''
    def __init__(self, fn, *args, **kwargs):
        super(Worker, self).__init__()
        # Store constructor arguments (re-used for processing)
        self.fn = fn
        self.args = args
        self.kwargs = kwargs

    @pyqtSlot()
    def run(self):
        self.fn(*self.args, **self.kwargs)
        

class MyApp(QMainWindow):
    def __init__(self, parent=None):
        super(MyApp, self).__init__()
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        self.threadpool = QThreadPool()

        self.start_time = 0

        self.main = ui_main()
        self.main.setupUi(self)

        self.scan = ui_scan()
        self.scan.setupUi(self)

        self.report = ui_report()
        self.report.setupUi(self)

        self.initialUI()

    def initialUI(self):
        self.openMainUI()

        self.main.listWidget.addItem('Common Vulnerabillity')

        self.main.scanButton.clicked.connect(self.openScanUI)

        self.scan.statusEdit.setEnabled(False)
        self.scan.reportBtn.clicked.connect(self.openReportUI)

        self.main.startBtn.clicked.connect(self.openMainUI)
        self.scan.startBtn.clicked.connect(self.openMainUI)
        self.report.startBtn.clicked.connect(self.openMainUI)

        self.main.shutdownBtn.clicked.connect(self.shutdown)
        self.scan.shutdownBtn.clicked.connect(self.shutdown)
        self.report.shutdownBtn.clicked.connect(self.shutdown)

        self.main.restartBtn.clicked.connect(self.restart)
        self.scan.restartBtn.clicked.connect(self.restart)
        self.report.restartBtn.clicked.connect(self.restart)
    
    def openMainUI(self):
        self.main.widget.show()
        self.scan.widget.hide()
        self.report.widget.hide()
    
    def shutdown(self):
        command = "/usr/bin/sudo /sbin/shutdown now"
        process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
        output = process.communicate()[0]
        print(output)

    def restart(self):
        command = "/usr/bin/sudo /sbin/shutdown -r now"
        process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
        output = process.communicate()[0]
        print(output)

    def openScanUI(self):
        indexSelected = self.main.listWidget.currentRow()
        selectMode = self.main.listWidget.item(indexSelected).text()
        if selectMode == 'Common Vulnerabillity':
            self.scan.widget.show()
            self.main.widget.hide()
            worker = Worker(self.startScan)
            self.threadpool.start(worker)
    
    def openReportUI(self):
        self.report.widget.show()
        self.scan.widget.hide()

        low, medium, high = nmap.getSeverity(7)
        chart.createPieChart(low, medium, high)

        pixmap = QPixmap('./plot.png')
        self.report.imgLabel.setPixmap(pixmap)

    def startScan(self):
        self.scan.reportBtn.setEnabled(False)
        self.scan.statusEdit.setText('Scanning...')
        text = nmap.getOutput()

        self.scan.statusEdit.setText('Prepare CVE Detail')
        data = nmap.readCVEData(text)

        self.scan.statusEdit.setText('Uploading to database')
        scanData = nmap.insertScan()

        nmap.insertNmap(data, scanData)
        self.scan.statusEdit.setText('Finish')

        self.scan.reportBtn.setEnabled(True)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    myapp = MyApp()
    myapp.show()
    sys.exit(app.exec_())