import sys
from src.packetcapture.Packet_capture import Packet_capture
from src.designer.UI_MainWindow import Ui_MainWindow
from PyQt5.QtWidgets import QMainWindow, QFileDialog, QHeaderView
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from scapy.all import *
from scapy.layers.inet import Ether, TCP, UDP, ICMP


# MainWindow继承qt designer生成的Ui_MainWindow类
class MainWindow(Ui_MainWindow, Packet_capture):
    def __init__(self):
        super(MainWindow, self).__init__()
        # QMainWindow对象
        self.mainwindow = QMainWindow()
        self.setupUi(self.mainwindow)
        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels(["type", "src", "dst"])
        self.PackageList.setModel(self.model)
        self.PackageList.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        # 设置默认文件路径
        self.save_path = "../../packages/"
        self.is_start = False
        # 打开文件
        self.actionopen.triggered.connect(self.open)
        # 查看报文信息
        self.PackageList.clicked.connect(self.display)
        # 保存文件
        self.pkt = None
        self.actionsave.triggered.connect(self.save)
        # 另存为
        self.actionsave_as.triggered.connect(self.save_as)
        # 点击开始按钮开始/暂停抓包
        self.Start.clicked.connect(self.start)

    def start(self):
        if self.Start.text() == "开始":
            self.Start.setText("暂停")
            # 开始抓包
            self.is_start = True
            self.start_sniff()
        else:
            self.Start.setText("开始")
            self.is_start = False
            self.pause_sniff()

    def read(self):
        while self.is_start:
            pass  # 读取临时文件

    def show(self):
        self.mainwindow.show()

    def display(self, index):
        ind = index.row()
        p = self.pkt[ind]
        saved_stdout = sys.stdout
        with open('temp.txt', 'w+', encoding="utf8") as file:
            sys.stdout = file
            p.show()
        sys.stdout = saved_stdout
        with open('temp.txt', 'r', encoding="utf8") as file:
            details = file.read()
        self.Details.setText(details)
        info = ""
        while p.name != "NoPayload":
            info = info + p.name + ": " + p.mysummary() + "\n"
            p = p.payload
        self.Summary.setText(info)

    def save(self):
        return self.save_as()

    def save_as(self):
        path = QFileDialog.getSaveFileName(self.mainwindow, '保存文件', '', 'Pcap Files (*.pcap)')
        wrpcap(path[0], self.pkt)

    def open(self):
        path, _ = QFileDialog.getOpenFileNames(self.mainwindow, "打开文件", self.save_path, "Pcap Files (*.pcap)")
        if len(path):
            self.pkt = rdpcap(path[0])
        else:
            return
        arp = (0x0806,)
        ip = (0x0080, 0x0800, 0x86DD, 0xDD68)
        for p in self.pkt:
            if p.type in arp:
                self.model.appendRow([
                    QStandardItem("ARP"),
                    QStandardItem(p.psrc),
                    QStandardItem(p.pdst)
                ])
            elif p.type in ip:
                self.model.appendRow([
                    QStandardItem("IPv{}".format(p.payload.version)),
                    QStandardItem(p.payload.src),
                    QStandardItem(p.payload.dst),
                ])
            else:
                self.model.appendRow([
                    QStandardItem("Ethernet"),
                    QStandardItem(p.src),
                    QStandardItem(p.dst),
                ])
