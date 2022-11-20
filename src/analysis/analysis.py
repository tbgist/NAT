import struct
import gc
from scapy.all import *
import scapy.all as scapy
import matplotlib.ticker as ticker
import matplotlib.pyplot as plt

default = 'D/Network'       # 默认抓包文件的保存处
defaultp = 'D/'             # 默认统计图片的保存处

# 生成统计图片
class info(object):
    def table(self):
        pass

    def bar(self):
        pass

    def pie(self):
        pass

    def line(self):
        pass
# 统计包各个报文数量，实现统计图片方法
class pcap(info):
    def __init__(self):     # 初始化
        self.ipv4 = 0
        self.ipv6 = 0
        self.arp = 0
        self.tcp = 0
        self.udp = 0
        self.dns = 0
        self.others = 0
        self.start = 0
        self.end = 0
        self.ratio=[]
        self.stamp=[]

    def stat(self,pkt):     # 统计包各报文数据
        ipv4 = (0x0080, 0x0800)
        ipv6 = (0x86DD,0xDD68)
        arp = (0x0806,)
        tcp = 6
        udp = 17                    # 各个协议的特征字段
        num = -1
        self.start = pkt[0].time
        while True:
            try:
                num += 1
                if pkt[num].type in ipv4:
                   self.ipv4 += 1
                   if pkt[num].proto==6:
                       self.tcp += 1
                   elif pkt[num].proto==17:
                       self.udp += 1
                       if pkt[num].dport == 53 or pkt[num].sport == 53:     # 如果是udp报文,再判断其应用层协议是否为DNS
                           self.dns += 1
                           timeArray = time.localtime(int(pkt[num].time))
                           nor = time.strftime("%H:%M:%S", timeArray)       # 将时间戳转换为标准格式
                           try:
                                 if(nor == self.stamp[-1]):
                                     self.ratio.pop()                       # 剔除同一时间的数据
                                 else:
                                     self.stamp.append(nor)
                           except:
                               self.stamp.append(nor)
                           self.ratio.append(self.dns/num)
                elif pkt[num].type in ipv6:
                   self.ipv6+=1
                   if pkt[num].nh==6:
                       self.tcp += 1
                   elif pkt[num].nh==17:
                       self.udp += 1
                elif pkt[num].type in arp:
                    self.arp += 1
                else:
                    self.others += 1
            except:
                self.end = pkt[num-1].time
                #del pkt
                break

    # 读取pcap文件
    def sum(self,addr=default):
        if addr == default:         # 打开默认保存的文件
            num = 1
            pkt = rdpcap("pcap1.pcap")  # 循环打开文件
            while True:
                try:
                    num += 1
                    file_name = "pcap%d.pcap" % num
                    pkts = rdpcap(file_name)
                    pkt = pkt + pkts
                    self.stat(pkts)
                except:
                    del pkts
                    gc.collect()        # 释放内存
                    break
        else:
            pkt=rdpcap(addr)        # 打开指定路径文件
            self.stat(pkt)

    # 生成总览表格
    def table(self):
        # 列名
        col = ['IPV4', 'IPV6', 'ARP','Others']
        # 行名
        row = ['num']
        # 表格里面的具体值
        vals = [[self.ipv4, self.ipv6, self.arp, self.others]]
        plt.figure(figsize=(5, 3))
        tab = plt.table(cellText=vals,
                        colLabels=col,
                        rowLabels=row,
                        loc='center',
                        cellLoc='center',
                        rowLoc='center')
        tab.scale(1, 2)
        plt.axis('off')
        # plt.savefig(defaultp)
        plt.show()

    # 生成ipv4,ipv6数据的柱状图
    def bar(self):
        colors = ['#1f77b4', '#ff7f0e', '#2ca02c']
        labels = ['IPV4','IPV6']
        data = [self.ipv4,self.ipv6]
        fig, ax = plt.subplots(figsize=(4, 4))
        bars1 = plt.bar([1, 2],data, 0.3 ,align='center', alpha=0.7, color=colors, tick_label=labels)
        for b in bars1:  # 在柱状图上方显示数据
            height = b.get_height()
            ax.annotate('{}'.format(height),
                        # xy控制的是，标注哪个点，x=x坐标+width/2, y=height，即柱子上平面的中间
                        xy=(b.get_x() + b.get_width() / 2, height),
                        xytext=(0, 3),  # 文本放置的位置，如果有textcoords，则表示是针对xy位置的偏移，否则是图中的固定位置
                        textcoords="offset points",  # 两个选项 'offset pixels'，'offset pixels'
                        va='bottom', ha='center'  # 代表verticalalignment 和horizontalalignment，控制水平对齐和垂直对齐。
                        )
        # plt.savefig(defaultp)
        plt.show()

    # 生成TCP,UDP的饼状图
    def pie(self):
        plt.figure(figsize=(4, 4))
        labels = ['TCP:'+str(self.tcp), 'UDP:'+str(self.udp)]
        sizes = [self.tcp,self.udp]
        colors = ['yellowgreen', 'lightskyblue']
        explode = (0.03, 0.03)  # 分隔
        patches, text1, text2 = plt.pie(sizes,
                                        explode=explode,
                                        labels=labels,
                                        colors=colors,
                                        autopct='%3.2f%%',  # 数值保留固定小数位
                                        shadow=True,  # 阴影设置
                                        startangle=90,  # 逆时针起始角度设置
                                        pctdistance=0.6)  # 数值距圆心半径倍数距离
        # x，y轴刻度设置一致，保证饼图为圆形
        plt.axis('equal')
        # plt.savefig(defaultp)
        plt.show()

    # 生成DNS随时间占比的折线图
    def line(self):
        d = len(self.stamp) // 5   # 控制间隔数量
        plt.rcParams['font.sans-serif'] = ['SimHei']  # 显示中文
        plt.gca().xaxis.set_major_locator(ticker.MultipleLocator(d))    # 横坐标密度
        plt.plot(self.stamp,
                 self.ratio,
                 label='DNS占比随时间走势',
                 linewidth=0.5,
                 color='blue')
        plt.xlabel('时间')
        plt.ylabel('比例')
        # plt.savefig(defaultp)
        plt.show()


s=input('请输入文件路径')
a=pcap()
a.sum(s)
a.table()
a.pie()
a.bar()
a.line()

