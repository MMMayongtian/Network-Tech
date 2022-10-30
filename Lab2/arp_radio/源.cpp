#include <stdio.h>
#include <winsock2.h>
#include <Windows.h>
#include <pcap.h>

#pragma comment(lib, "packet.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib,"WS2_32.lib")

#define ETH_ARP      0x0806   // 以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define ARP_HARDWARE 1        // 硬件类型字段值为表示以太网地址
#define ETH_IP       0x0800   // 协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define ARP_REQUEST  1        // ARP请求
#define ARP_RESPONSE 2        // ARP应答

//14字节以太网首部
struct EthernetHeader
{
	u_char DestMAC[6];    // 目的MAC地址6字节
	u_char SourMAC[6];    // 源MAC地址 6字节
	u_short EthType;      // 上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp  2字节
};

//28字节ARP帧结构
struct ArpHeader
{
	unsigned short hdType;    // 硬件类型
	unsigned short proType;   // 协议类型
	unsigned char hdSize;     // 硬件地址长度
	unsigned char proSize;    // 协议地址长度
	unsigned short op;        // 操作类型，ARP请求（1），ARP应答（2），RARP请求（3），RARP应答（4）。
	u_char smac[6];           // 源MAC地址
	u_char sip[4];            // 源IP地址
	u_char dmac[6];           // 目的MAC地址
	u_char dip[4];            // 目的IP地址
};

//定义整个arp报文包，总长度42字节
struct ArpPacket {
	EthernetHeader ed;
	ArpHeader ah;
};

// 获取到指定网卡的句柄
pcap_t* OpenPcap(int nChoose)
{
	pcap_t* pcap_handle;   //打开网络适配器，捕捉实例,是pcap_open返回的对象
	pcap_if_t* alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];   //错误缓冲区,大小为256

	// 获取到所有设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
		exit(0);
	// 找到指定的网卡设备
	for (int x = 0; x < nChoose - 1; ++x)
		alldevs = alldevs->next;

	if ((pcap_handle = pcap_open(alldevs->name,      // 设备名
		65536,                                       // 每个包长度
		PCAP_OPENFLAG_PROMISCUOUS,                   // 混杂模式
		1000,                                        // 读取超时时间
		NULL,                                        // 远程机器验证
		errbuf                                       // 错误缓冲池
	)) == NULL)
	{
		pcap_freealldevs(alldevs);
		exit(0);
	}
	return pcap_handle;
}

int main(int argc, char* argv[])
{
	pcap_t* handle;            // 打开网络适配器
	EthernetHeader eh;         // 定义以太网包头
	ArpHeader ah;              // 定义ARP包头

	unsigned char sendbuf[42]; // arp包结构大小42个字节
	unsigned char src_mac[6] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xff, 0xff };
	unsigned char src_ip[4] = { 0x01, 0x02, 0x03, 0x04 };

	handle = OpenPcap(3);      // 拿到第三个网卡的句柄

	// 开始填充ARP包
	memset(eh.DestMAC, 0xff, 6);      // 以太网首部目的MAC地址,全为广播地址
	memcpy(eh.SourMAC, src_mac, 6);   // 以太网首部源MAC地址
	memcpy(ah.smac, src_mac, 6);      // ARP字段源MAC地址
	memset(ah.dmac, 0xff, 6);         // ARP字段目的MAC地址
	memcpy(ah.sip, src_ip, 4);        // ARP字段源IP地址
	memset(ah.dip, 0x05, 4);          // ARP字段目的IP地址

	// 赋值MAC地址
	eh.EthType = htons(ETH_ARP);   //htons：将主机的无符号短整形数转换成网络字节顺序
	ah.hdType = htons(ARP_HARDWARE);
	ah.proType = htons(ETH_IP);
	ah.hdSize = 6;
	ah.proSize = 4;
	ah.op = htons(ARP_REQUEST);

	// 构造一个ARP请求
	memset(sendbuf, 0, sizeof(sendbuf));            // ARP清零
	memcpy(sendbuf, &eh, sizeof(eh));               // 首先把eh以太网结构填充上
	memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));  // 接着在eh后面填充arp结构

	// 发送数据包
	if (pcap_sendpacket(handle, sendbuf, 42) == 0)
	{
		printf("发送ARP数据包成功! \n");
	}

	system("pause");
	return 0;
}