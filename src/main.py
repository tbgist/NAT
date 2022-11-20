# Coded by TangBin
from src.designer.UI_Components import UI_Components
import sys
from PyQt5.QtWidgets import QApplication

if __name__ == '__main__':
    # application 对象
    app = QApplication(sys.argv)
    ui_components = UI_Components()
    # 显示
    ui_components.show()
    sys.exit(app.exec_())
