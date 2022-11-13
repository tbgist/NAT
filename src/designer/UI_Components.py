from src.designer.UI_MainWindow import Ui_MainWindow
from PyQt5.QtWidgets import QMainWindow


# UI_Components继承qt designer实现的Ui_MainWindow类
class UI_Components(Ui_MainWindow):
    def __init__(self):
        super(UI_Components, self).__init__()
        # QMainWindow对象
        self.mainwindow = QMainWindow()
        self.setupUi(self.mainwindow)
        # 点击开始按钮开始抓包
        # self.Start.clicked.connect(self.start)
        # # 点击暂停按钮暂停抓包
        # self.pause()
        # # 点击终止按钮结束抓包
        # self.pause()

    def start(self):
        pass

    def pause(self):
        pass

    def show(self):
        self.mainwindow.show()
