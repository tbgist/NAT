# coded by 唐斌
import os.path
import sys
from src.packagecapture.package_capture import Packet_capture
from src.designer.UI_MainWindow import Ui_MainWindow
from scapy.arch import get_windows_if_list
from PyQt5.QtWidgets import QMainWindow, QFileDialog, QHeaderView
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from scapy.all import *
from src.analysis.analysis import pcap


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
        # 获得所有网卡
        cards = get_windows_if_list()
        self.card_names = []
        for card in cards:
            if card['ips'] and card['name'][:8] != 'Loopback':
                self.card_names.append(card['name'])
        self.Type.addItems(self.card_names)
        self.netcard = self.card_names[self.Type.currentIndex()]
        self.Type.currentIndexChanged.connect(self.change_card)
        # 设置过滤器
        self.Filter.textChanged.connect(self.change_filter)
        # 设置默认文件路径
        self.save_path = "../../packages/"
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
        self.is_start = False
        self.count = 1
        self.Start.clicked.connect(self.start)
        self.read_thread = threading.Thread(target=self.read)
        # 显示统计数据
        self.Plot.setEnabled(True)
        self.Plot.clicked.connect(self.plot)

    def start(self):
        if self.Start.text() == "启动":
            self.is_start = True
            self.read_thread = threading.Thread(target=self.read)
            self.read_thread.start()
            self.Start.setText("暂停")
            self.start_sniff()
        else:
            self.is_start = False
            self.Start.setText("启动")
            self.pause_sniff()

    def read(self):
        while self.is_start:
            path = './test' + str(self.count) + '.pcap'
            print(os.path.abspath(path))
            print(path)
            if os.path.exists(path):
                temp_pkt = rdpcap(path)
                if self.pkt is None:
                    self.pkt = temp_pkt
                else:
                    self.pkt = self.pkt + temp_pkt
                self.show_pkt(temp_pkt)
                self.count = self.count + 1

    def show(self):
        self.mainwindow.show()

    def change_card(self, index):
        self.netcard = self.card_names[self.Type.currentIndex()]

    def change_filter(self):
        self.filter_ = self.Filter.toPlainText()

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

    def plot(self):
        p = pcap()
        if self.pkt is not None:
            p.sum()
            p.pic()
        else:
            path, _ = QFileDialog.getOpenFileNames(self.mainwindow, "打开文件", self.save_path, "Pcap Files (*.pcap)")
            p.sum(path[0])
            p.pic()

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
        self.show_pkt(self.pkt)

    def show_pkt(self, pkt):
        arp = (0x0806,)
        ip = (0x0080, 0x0800, 0x86DD, 0xDD68)
        for p in pkt:
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
