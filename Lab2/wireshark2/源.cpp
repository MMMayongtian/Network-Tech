#include"pcap.h"
#include<iostream>
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>
#include <Windows.h>
using namespace std;
#pragma comment(lib, "packet.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib,"ws2_32.lib")

#pragma pack (1)
//进入字 节对齐方式
typedef struct FrameHeader_t {
	BYTE DesMAC[6];
	// 目的地址
	BYTE SrcMAC[6];
	//源地址
	WORD FrameType;
	//帧类型
}FrameHeader_t;
typedef struct IPHeader_t {
	//IP首部
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD Flag_Segment;
	BYTE TTL;
	BYTE Protocol;
	WORD Checksum;
	ULONG SrcIP;
	ULONG DstIP;
} IPHeader_t;
typedef struct Data_t {
	//包含帧首部和IP首部的数据包
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
} Data_t;
#pragma pack() //恢复缺省对齐方式

void PrintFrameHeader(const u_char* packetData)
{

	struct FrameHeader_t* protocol;
	protocol = (struct FrameHeader_t*)packetData;

	u_short ether_type = ntohs(protocol->FrameType);  // 以太网类型
	u_char* ether_src = protocol->SrcMAC;         // 以太网原始MAC地址
	u_char* ether_dst = protocol->DesMAC;         // 以太网目标MAC地址

	printf("	类型: 0x%x \t", ether_type);
	printf("原MAC地址: %02X:%02X:%02X:%02X:%02X:%02X \t",
		ether_src[0], ether_src[1], ether_src[2], ether_src[3], ether_src[4], ether_src[5]);
	printf("目标MAC地址: %02X:%02X:%02X:%02X:%02X:%02X \n",
		ether_dst[0], ether_dst[1], ether_dst[2], ether_dst[3], ether_dst[4], ether_dst[5]);
}
void PrintIPHeader(const u_char* packetData) {
	struct IPHeader_t* ip_protocol;

	// +14 跳过数据链路层
	ip_protocol = (struct IPHeader_t*)(packetData + 14);
	SOCKADDR_IN Src_Addr, Dst_Addr = { 0 };

	u_short check_sum = ntohs(ip_protocol->Checksum);
	int ttl = ip_protocol->TTL;
	int proto = ip_protocol->Protocol;

	Src_Addr.sin_addr.s_addr = ip_protocol->SrcIP;
	Dst_Addr.sin_addr.s_addr = ip_protocol->DstIP;

	char buff1[17];
	::inet_ntop(AF_INET, (const void*)&Src_Addr.sin_addr, buff1, 17);
	printf("	源地址: %s \t", buff1);
	char buff2[17];
	::inet_ntop(AF_INET, (const void*)&Dst_Addr.sin_addr, buff2, 17);
	printf("目标地址: %s \t", buff2);
	printf("校验和 :%5X \t TTL :%4d \t", check_sum, ttl);
	printf("协议类型:");
	switch (ip_protocol->Protocol)
	{
	case 1: printf("ICMP \n"); break;
	case 2: printf("IGMP \n"); break;
	case 6: printf("TCP \n");  break;
	case 17: printf("UDP \n"); break;
	case 89: printf("OSPF \n"); break;
	default: printf("None \n"); break;
	}
}

int main() {
	pcap_if_t* alldevs;
	pcap_if_t* dev;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];
	//获取设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) != -1) {
		cout << "获取设备列表成功" << endl;
	}
	else { 
		cout << "获取设备列表失败" << endl; 
		return 0; 
	}
	//显示获取的设备列表
	int devid = 0;
	for (dev = alldevs; dev != NULL; dev = dev->next) {
		cout << "dev_id: " << ++devid << endl;
		cout << "	dev_name: " << dev->name << endl;
		cout << "	dev_describe: " << dev->description << endl;
		//获取该网络接口设备的IP地址信息
		for(a = dev->addresses; a !=NULL; a = a->next){
			//判断该地址是否为IP地址
			if (a->addr->sa_family == AF_INET) {
				cout << "	IP地址: " << a->addr;
				cout << "	网络掩码: " << a->netmask;
				cout << "	广播地址: " << a->broadaddr;
				cout <<	"	目的地址: " << a->dstaddr << endl;
			}
		}
		cout << "----------------------------------------" << endl;
	}
	cout << "开始侦听:" << endl;
	devid = 0;
	for (pcap_if_t* dev = alldevs; dev != NULL; dev = dev->next) {
		//打开网络接口
		pcap_t* handle = pcap_open(dev->name, 655340, PCAP_OPENFLAG_PROMISCUOUS, 2000, NULL, errbuf);
		//数据包头
		pcap_pkthdr* pkt_header;
		//数据包
		const u_char* pkt_data;
		cout << "dev_id: " << ++devid << endl;
		//捕获数据包
		int retvalue = pcap_next_ex(handle, &pkt_header, &pkt_data);
		cout << "	侦听长度: " << pkt_header->len << endl;
		PrintFrameHeader(pkt_data);
		PrintIPHeader(pkt_data);
		if (retvalue == 0) {
			cout << "	获取报文超时" << endl;
		}
		cout << "----------------------------------------" << endl;
	}
	//释放设备列表
	pcap_freealldevs(alldevs);
}