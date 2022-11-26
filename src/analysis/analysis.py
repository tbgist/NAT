# coded by 丁志国
import struct
import gc
from scapy.all import *
import matplotlib.ticker as ticker
import matplotlib.pyplot as plt

# 默认包名、保存位置待改
default = './'  # 默认抓包文件的保存处


# 统计包各个报文数量，实现统计图片方法
class pcap():
    def __init__(self):  # 初始化
        self.ipv4 = 0
        self.ipv6 = 0
        self.arp = 0
        self.tcp = 0
        self.udp = 0
        self.dns = 0
        self.others = 0
        self.start = 0
        self.end = 0
        self.ratio = []     # dns比例的列表
        self.stamp = []     # 比例对应的时间列表

    # 统计包各报文数据
    def stat(self, pkt):
        ipv4 = (0x0080, 0x0800)
        ipv6 = (0x86DD, 0xDD68)
        arp = (0x0806,)
        tcp = 6
        udp = 17  # 各个协议的特征字段
        num = -1
        self.start = pkt[0].time  # 头报文的时间戳
        x = self.dns
        while True:
            try:
                num += 1
                if pkt[num].type in ipv4:
                    self.ipv4 += 1
                    if pkt[num].proto == tcp:
                        self.tcp += 1
                    elif pkt[num].proto == udp:
                        self.udp += 1
                        if pkt[num].dport == 53 or pkt[num].sport == 53:  # 如果是udp报文,再判断其应用层协议是否为DNS
                            self.dns += 1
                            timeArray = time.localtime(int(pkt[num].time))
                            nor = time.strftime("%H:%M:%S", timeArray)  # 将时间戳转换为标准格式
                            try:
                                if nor == self.stamp[-1]:
                                    self.ratio.pop()  # 剔除同一时间的数据
                                else:
                                    self.stamp.append(nor)
                            except:  # 空列表的情况
                                self.stamp.append(nor)
                            try:
                                self.ratio.append(self.dns / (num + x / self.ratio[-1]))
                            except:  # 空列表的情况
                                self.ratio.append(self.dns / num)
                elif pkt[num].type in ipv6:
                    self.ipv6 += 1
                    if pkt[num].nh == 6:
                        self.tcp += 1
                    elif pkt[num].nh == 17:
                        self.udp += 1
                elif pkt[num].type in arp:
                    self.arp += 1
                else:
                    self.others += 1
            except:  # 报文读取完毕
                self.end = pkt[num - 1].time  # 最后报文的时间戳
                del pkt
                break

    # 读取pcap文件
    def sum(self, addr=default):
        if addr == default:  # 打开默认保存的文件
            num = 1
            pkt = rdpcap(r"./test1.pcap")  # 循环打开文件
            self.stat(pkt)
            while True:
                try:
                    num += 1
                    file_name = r"./test%.pcap" % num
                    pkt = rdpcap(file_name)
                    self.stat(pkt)
                    del pkt
                    if num % 19 == 0:   # 定期释放内存
                        gc.collect()
                except:
                    gc.collect()
                    break
        else:
            pkt = rdpcap(addr)  # 打开指定路径文件
            self.stat(pkt)

    # 生成最终统计图
    def pic(self):
        # 生成传输层报文总览表格
        plt.figure(figsize=(8, 8))
        plt.figure(1)
        plt.rcParams['font.sans-serif'] = ['SimHei']  # 显示中文
        colors = ['#1f77b4', '#ff7f0e', '#2ca02c']  # 颜色库
        labels = ['IPV4', 'IPV6', 'ARP', 'Others']
        t = self.ipv4 + self.ipv6 + self.arp + self.others
        data = [[self.ipv4, self.ipv6, self.arp, self.others],
                [round(self.ipv4 / t * 100, 3), round(self.ipv6 / t * 100, 3), round(self.arp / t * 100, 3),
                 round(self.others / t * 100, 3)]]
        tab = plt.subplot(221)
        tab.set_title('链路层协议报文统计情况')
        tab = plt.table(cellText=data,
                        colLabels=labels,
                        rowLabels=['数量(个)', '比例(%)'],  # 行标签
                        loc='center',
                        cellLoc='center',
                        rowLoc='center')
        tab.scale(1, 2)  # 子图放大一倍
        plt.axis('off')
        # 生成ipv4,ipv6数据的柱状图
        labels = ['IPV4', 'IPV6']
        data = [self.ipv4, self.ipv6]
        bar = plt.subplot(222)
        bar.set_title('ipv4与ipv6报文统计与对比')
        bar = plt.bar([1, 2],  # 横坐标
                      data,
                      0.3,  # 柱的宽度
                      align='center',
                      alpha=0.7,  # 透明度
                      color=colors,
                      tick_label=labels)
        plt.bar_label(bar, label_type='edge')  # 在柱上添加数量标签
        # 生成TCP,UDP的饼状图
        labels = ['TCP:' + str(self.tcp), 'UDP:' + str(self.udp)]
        data = [self.tcp, self.udp]
        explode = (0.03, 0.03)  # 空隙大小
        pie = plt.subplot(223)
        pie.set_title('TCP与UDP报文统计与对比')
        pie = plt.pie(data,
                      explode=explode,
                      labels=labels,
                      colors=colors,
                      autopct='%3.2f%%',  # 保留小数后两位
                      shadow=True,  # 设置阴影
                      startangle=90,  # 逆时针起始角度设置
                      pctdistance=0.6)  # 数值与圆心距离
        plt.axis('off')
        # 生成DNS随时间占比的折线图
        line = plt.subplot(224)
        if self.dns > 0:        # 有可能没有捕获到dns报文
            line.set_title('DNS报文占比随时间走势')
            line = plt.plot(self.stamp,
                            self.ratio,
                            linewidth=0.5,
                            color='blue')
            plt.xlabel('时间')
            plt.ylabel('比例')
            d = len(self.stamp) // 3 + 1  # 控制横坐标间隔数量
            plt.gca().xaxis.set_major_locator(ticker.MultipleLocator(d))  # 横坐标密度
        else:
            line.set_title('没有捕获到DNS报文!')
        plt.tight_layout()
        plt.show()


if __name__ == '__main__':
    s = input('请输入文件路径')
    a = pcap()
    a.sum(s)
    a.pic()
