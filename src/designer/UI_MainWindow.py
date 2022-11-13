# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'UI_MainWindow.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(800, 600)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.Details = QtWidgets.QTextEdit(self.centralwidget)
        self.Details.setGeometry(QtCore.QRect(40, 360, 491, 191))
        self.Details.setObjectName("Details")
        self.Summary = QtWidgets.QTextEdit(self.centralwidget)
        self.Summary.setGeometry(QtCore.QRect(550, 360, 241, 191))
        self.Summary.setObjectName("Summary")
        self.Type = QtWidgets.QComboBox(self.centralwidget)
        self.Type.setGeometry(QtCore.QRect(40, 30, 69, 22))
        self.Type.setObjectName("Type")
        self.Packages = QtWidgets.QTextEdit(self.centralwidget)
        self.Packages.setGeometry(QtCore.QRect(40, 90, 741, 241))
        self.Packages.setObjectName("Packages")
        self.Filter = QtWidgets.QTextEdit(self.centralwidget)
        self.Filter.setGeometry(QtCore.QRect(120, 30, 301, 21))
        self.Filter.setObjectName("Filter")
        self.Start = QtWidgets.QPushButton(self.centralwidget)
        self.Start.setGeometry(QtCore.QRect(470, 30, 75, 31))
        self.Start.setObjectName("Start")
        self.Pause = QtWidgets.QPushButton(self.centralwidget)
        self.Pause.setGeometry(QtCore.QRect(580, 30, 75, 31))
        self.Pause.setObjectName("Pause")
        self.Stop = QtWidgets.QPushButton(self.centralwidget)
        self.Stop.setGeometry(QtCore.QRect(680, 30, 75, 31))
        self.Stop.setObjectName("Stop")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 23))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.Start.setText(_translate("MainWindow", "启动"))
        self.Pause.setText(_translate("MainWindow", "暂停"))
        self.Stop.setText(_translate("MainWindow", "终止"))