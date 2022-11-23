from scapy.all import *
from concurrent.futures import ThreadPoolExecutor
import time
import psutil
import threading
import os
import copy


class Packet_capture:
    def __init__(self):
        self.run_time_start = None
        self.packets = []  # 临时存放抓包文件的列表
        self.t = 10  # 一次抓包的时长
        self.filter_ = None  # 过滤器
        self.netcard = 'Intel(R) Wi-Fi 6 AX201 160MHz'  # 网卡
        self.pid = os.getpid()  # 进程的pid
        self.p = psutil.Process(self.pid)  # 进程
        self.pnum = 0  # 保存的文件序号
        self.count = psutil.cpu_count()  # 计算机的cpu数，用于计算cpu使用率
        self.pool = ThreadPoolExecutor(20)  # 用于保存文件的线程池
        self.start_button = False  # 按键状态
        self.run_time = 0  # 起始时间、结束时间和运行时间
        self.start_time = 0
        self.end_time = 0
        self.run_time_start = 0  # 方便计算
        self.run_time_end = 0
        self.run_time = 0
        self.button = False
        self.path = "./"
        self.number = 1

    def savep(self):  # 保存文件函数
        self.pnum += 1
        pname = "%stest%d.pcap" % (self.path, self.pnum)
        # 生成文件名

        packets_ = copy.copy(self.packets)
        # 复制临时文件用于保存，同时清空原来的列表用于存放新的文件
        self.pool.submit(lambda pro: wrpcap(*pro), (pname, packets_))
        # 选择线程池中的一个空闲线程，将列表里的临时文件保存到硬盘

        with open(self.p.name() + ' PID_' + str(self.pid) + "(" + str(self.number) + ")" + ".csv", "a+") as f:
            current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
            cpu_percent = self.p.cpu_percent() / self.count
            mem_percent = self.p.memory_percent()
            line = current_time + ',' + str(cpu_percent) + ',' + str(mem_percent)
            f.write(line + "\n")
        # 记录cpu和内存使用情况

    def getp(self, x):  # 将抓包文件临时保存到列表
        self.packets.append(x)

    def start_sniff_(self):
        while self.button:
            self.packets.clear()
            sniff(prn=self.getp, timeout=self.t, filter=self.filter_, iface=self.netcard,
                  stop_filter=lambda x: not self.button)
            self.savep()  # 抓包、保存并判断什么时候结束

    def start_sniff(self):  # 开始抓包
        with open(self.p.name() + ' PID_' + str(self.pid) + "(" + str(self.number) + ")" + ".csv", "a+") as f:
            f.write("时间,cpu占用率,内存占用率\n")
        self.number += 1
        self.button = True
        self.run_time_start = time.time()
        self.start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.run_time_start))
        # 记录时间
        t1 = threading.Thread(target=self.start_sniff_)
        t1.start()

    def pause_sniff(self):  # 停止抓包
        self.button = False
        self.run_time_end = time.time()
        self.end_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.run_time_end))
        self.run_time = self.run_time_end - self.run_time_start
        # 记录时间
