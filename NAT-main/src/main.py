# Coded by TangBin
from src.designer.MainWindow import MainWindow
import sys
from PyQt5.QtWidgets import QApplication

if __name__ == '__main__':
    # application 对象
    app = QApplication(sys.argv)
    mainwindow = MainWindow()
    # 显示
    mainwindow.show()
    sys.exit(app.exec_())
