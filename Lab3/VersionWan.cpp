#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include"pcap.h"
#include <WinSock2.h>
#include <Windows.h>
#include<iostream>
#include<stdio.h>
#include<cstring>
using namespace std;

#pragma comment(lib, "packet.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib,"ws2_32.lib")

#pragma pack (1)//进入字节对齐方式
//以太网帧 14字节
typedef struct FrameHeader_t {
	BYTE DesMAC[6];// 目的地址
	BYTE SrcMAC[6];//源地址
	WORD FrameType;//帧类型
}FrameHeader_t;
//ARP帧 28字节
typedef struct ARPFrame_t {
	FrameHeader_t FrameHeader;//以太网帧头
	WORD HardwareType;//硬件类型
	WORD ProtocolType;//协议类型
	BYTE HLen;//硬件地址长度
	BYTE PLen;//协议地址长度
	WORD Operation;
	BYTE SendHa[6];	//发送端以太网地址
	DWORD SendIP;	//发送端IP地址
	BYTE RecvHa[6];	//目的以太网地址
	DWORD RecvIP;	//目的IP地址
} ARPFrame_t;
#pragma pack ()

//全局
pcap_t* adhandle;				 //捕捉实例,是pcap_open返回的对象
string iplist[100];
int i = 0;                       //适配器计数变量
string ip;
int dev_index;
bool Remote = 0;
//伪造
ARPFrame_t MakeARP(pcap_addr* a) {
	ARPFrame_t ARPFrame;
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;//表示广播
	//将APRFrame.FrameHeader.SrcMAC设置为本机网卡的MAC地址
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.SrcMAC[i] = 0x0f;

	ARPFrame.FrameHeader.FrameType = htons(0x806);//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
	ARPFrame.HLen = 6;//硬件地址长度为6
	ARPFrame.PLen = 4;//协议地址长为4
	ARPFrame.Operation = htons(0x0001);//操作为ARP请求

	//将ARPFrame.SendHa设置为本机网卡的MAC地址
	for (int i = 0; i < 6; i++)
		ARPFrame.SendHa[i] = 0x0f;
	//将ARPFrame.SendIP设置为本机网卡上绑定的IP地址
	//ARPFrame.SendIP = inet_addr("122.122.122.122");
	ARPFrame.SendIP = inet_addr("122.122.122.122");
	//将ARPFrame.RecvHa设置为0
	for (int i = 0; i < 6; i++)
		ARPFrame.RecvHa[i] = 0;//表示目的地址未知
	//将ARPFrame.RecvIP设置为请求的IP地址
	//ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
	ARPFrame.RecvIP = inet_addr(iplist[dev_index].c_str());
	return ARPFrame;
}

bool compare(ARPFrame_t* Packet_1, ARPFrame_t* Packet_2) {
	for (int i = 0; i < 6; i++) {
		if (Packet_1->FrameHeader.DesMAC[0] != Packet_2->FrameHeader.SrcMAC[0]) {
			return false;
		}
	}
	return true;
}

//发包
int Send(pcap_t* adhandle, ARPFrame_t ARPFrame) {
	pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)); //{ cout << "发包失败"; return 1; }// !=0的时候为send发生错误
	//else { return 1; }
	return 1;
}

//收包
ARPFrame_t* Recv(pcap_t* adhandle) {
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	int res;
	while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
		ARPFrame_t* RecPacket = (ARPFrame_t*)pkt_data;
		if (
			*(unsigned short*)(pkt_data + 12) == htons(0x0806)	//0x0806为以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
			&& *(unsigned short*)(pkt_data + 20) == htons(2)	//ARP应答
			&& *(unsigned long*)(pkt_data + 38) == inet_addr("122.122.122.122")
			)
		{
			return RecPacket;
		}
	}
}

void PrintPacket(ARPFrame_t* RecPacket) {
	printf("%s:\t%02x-%02x-%02x-%02x-%02x-%02x\n", "MAC地址",
		RecPacket->FrameHeader.SrcMAC[0],
		RecPacket->FrameHeader.SrcMAC[1],
		RecPacket->FrameHeader.SrcMAC[2],
		RecPacket->FrameHeader.SrcMAC[3],
		RecPacket->FrameHeader.SrcMAC[4],
		RecPacket->FrameHeader.SrcMAC[5]);
	return ;
}

//遍历接口列表
void Devslist(pcap_if_t* alldevs, int ip_i) {
	//ip_i=0 全部显示
	//ip_i!=0 找特定ip
	i = 0;
	for (pcap_if_t* d = alldevs; d != nullptr; d = d->next)//显示接口列表
	{
		//获取该网络接口设备的ip地址信息
		for (pcap_addr* a = d->addresses; a != nullptr; a = a->next)
		{
			if (((struct sockaddr_in*)a->addr)->sin_family == AF_INET && a->addr)
			{//打印ip地址
				i++;
				if (ip_i == 0)
				{
					//打印相关信息
					//inet_ntoa将ip地址转成字符串格式
					printf("%d\n", i);
					printf("%s\t\t%s\n%s\t%s\n", "name:", d->name, "description:", d->description);
					printf("%s\t\t%s\n", "IP地址:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					iplist[i] = inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr);
				}

				//输入IP查看MAC功能
				else if (ip_i == i) {
					printf("%s\t\t%s\n%s\t%s\n", "name:", d->name, "description:", d->description);
					printf("%s\t\t%s\n", "IP地址:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					//在当前网卡上伪造一个包
					ARPFrame_t ARPFrame = MakeARP(a);
					//打开该网卡的网络接口
					adhandle = pcap_open(d->name, 655340, PCAP_OPENFLAG_PROMISCUOUS, 1000, 0, 0);
					if (adhandle == NULL) { cout << "打开接口失败"; }
					//发包
					if (Send(adhandle, ARPFrame) == 0) { break; };
					//收包
					ARPFrame_t* RecPacket = Recv(adhandle);
					
					if (Remote) {
						//更新伪装ARP
						for (int j = 0; j < 6; j++) {
							ARPFrame.FrameHeader.SrcMAC[j] = RecPacket->FrameHeader.SrcMAC[j];
							ARPFrame.SendHa[j] = RecPacket->FrameHeader.SrcMAC[j];
						}
						ARPFrame.RecvIP = inet_addr(ip.c_str());

						//重新发包
						if (Send(adhandle, ARPFrame) == 0) { break; };
						//收包
						struct pcap_pkthdr* pkt_header;
						const u_char* pkt_data;
						int res;
						while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
							ARPFrame_t* RecPacket = (ARPFrame_t*)pkt_data;
						
							if (
								*(unsigned short*)(pkt_data + 12) == htons(0x0806)	//0x0806为以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
								&& *(unsigned short*)(pkt_data + 20) == htons(2)	//ARP应答
								&& compare(RecPacket,&ARPFrame)
								)
							{
								break;
							}
						}
					}
					PrintPacket(RecPacket);
				}
			}
		}
	}
}

int main() {
	pcap_if_t* alldevs;				 //所有网络适配器
	char errbuf[PCAP_ERRBUF_SIZE];   //错误缓冲区,大小为256
	pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf);
	//输入想查询的IP地址
	int ip_i = 0;

	//第一次遍历 显示所有网卡信息
	Devslist(alldevs, 0);

	cout << "请选择网卡: " << endl;
	cin >> dev_index;

	cout << "请输入IP: " << endl;
	cin >> ip;

	cout << "本机 0, 远程 1: " << endl;
	cin >> Remote;
	//查询输入ip并显示所有信息
	Devslist(alldevs, dev_index);
	//释放资源
	pcap_freealldevs(alldevs);
}#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include"pcap.h"
#include <WinSock2.h>
#include <Windows.h>
#include<iostream>
#include<stdio.h>
#include<cstring>
using namespace std;

#pragma comment(lib, "packet.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib,"ws2_32.lib")

#pragma pack (1)//进入字节对齐方式
//以太网帧 14字节
typedef struct FrameHeader_t {
	BYTE DesMAC[6];// 目的地址
	BYTE SrcMAC[6];//源地址
	WORD FrameType;//帧类型
}FrameHeader_t;
//ARP帧 28字节
typedef struct ARPFrame_t {
	FrameHeader_t FrameHeader;//以太网帧头
	WORD HardwareType;//硬件类型
	WORD ProtocolType;//协议类型
	BYTE HLen;//硬件地址长度
	BYTE PLen;//协议地址长度
	WORD Operation;
	BYTE SendHa[6];	//发送端以太网地址
	DWORD SendIP;	//发送端IP地址
	BYTE RecvHa[6];	//目的以太网地址
	DWORD RecvIP;	//目的IP地址
} ARPFrame_t;
#pragma pack ()

//全局
pcap_t* adhandle;				 //捕捉实例,是pcap_open返回的对象
string iplist[100];
int i = 0;                       //适配器计数变量
string ip;
int dev_index;
bool Remote = 0;
//伪造
ARPFrame_t MakeARP(pcap_addr* a) {
	ARPFrame_t ARPFrame;
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;//表示广播
	//将APRFrame.FrameHeader.SrcMAC设置为本机网卡的MAC地址
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.SrcMAC[i] = 0x0f;

	ARPFrame.FrameHeader.FrameType = htons(0x806);//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
	ARPFrame.HLen = 6;//硬件地址长度为6
	ARPFrame.PLen = 4;//协议地址长为4
	ARPFrame.Operation = htons(0x0001);//操作为ARP请求

	//将ARPFrame.SendHa设置为本机网卡的MAC地址
	for (int i = 0; i < 6; i++)
		ARPFrame.SendHa[i] = 0x0f;
	//将ARPFrame.SendIP设置为本机网卡上绑定的IP地址
	//ARPFrame.SendIP = inet_addr("122.122.122.122");
	ARPFrame.SendIP = inet_addr("122.122.122.122");
	//将ARPFrame.RecvHa设置为0
	for (int i = 0; i < 6; i++)
		ARPFrame.RecvHa[i] = 0;//表示目的地址未知
	//将ARPFrame.RecvIP设置为请求的IP地址
	//ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
	ARPFrame.RecvIP = inet_addr(iplist[dev_index].c_str());
	return ARPFrame;
}

bool compare(ARPFrame_t* Packet_1, ARPFrame_t* Packet_2) {
	for (int i = 0; i < 6; i++) {
		if (Packet_1->FrameHeader.DesMAC[0] != Packet_2->FrameHeader.SrcMAC[0]) {
			return false;
		}
	}
	return true;
}

//发包
int Send(pcap_t* adhandle, ARPFrame_t ARPFrame) {
	pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)); //{ cout << "发包失败"; return 1; }// !=0的时候为send发生错误
	//else { return 1; }
	return 1;
}

//收包
ARPFrame_t* Recv(pcap_t* adhandle) {
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	int res;
	while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
		ARPFrame_t* RecPacket = (ARPFrame_t*)pkt_data;
		if (
			*(unsigned short*)(pkt_data + 12) == htons(0x0806)	//0x0806为以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
			&& *(unsigned short*)(pkt_data + 20) == htons(2)	//ARP应答
			&& *(unsigned long*)(pkt_data + 38) == inet_addr("122.122.122.122")
			)
		{
			return RecPacket;
		}
	}
}

void PrintPacket(ARPFrame_t* RecPacket) {
	printf("%s:\t%02x-%02x-%02x-%02x-%02x-%02x\n", "MAC地址",
		RecPacket->FrameHeader.SrcMAC[0],
		RecPacket->FrameHeader.SrcMAC[1],
		RecPacket->FrameHeader.SrcMAC[2],
		RecPacket->FrameHeader.SrcMAC[3],
		RecPacket->FrameHeader.SrcMAC[4],
		RecPacket->FrameHeader.SrcMAC[5]);
	return ;
}

//遍历接口列表
void Devslist(pcap_if_t* alldevs, int ip_i) {
	//ip_i=0 全部显示
	//ip_i!=0 找特定ip
	i = 0;
	for (pcap_if_t* d = alldevs; d != nullptr; d = d->next)//显示接口列表
	{
		//获取该网络接口设备的ip地址信息
		for (pcap_addr* a = d->addresses; a != nullptr; a = a->next)
		{
			if (((struct sockaddr_in*)a->addr)->sin_family == AF_INET && a->addr)
			{//打印ip地址
				i++;
				if (ip_i == 0)
				{
					//打印相关信息
					//inet_ntoa将ip地址转成字符串格式
					printf("%d\n", i);
					printf("%s\t\t%s\n%s\t%s\n", "name:", d->name, "description:", d->description);
					printf("%s\t\t%s\n", "IP地址:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					iplist[i] = inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr);
				}

				//输入IP查看MAC功能
				else if (ip_i == i) {
					printf("%s\t\t%s\n%s\t%s\n", "name:", d->name, "description:", d->description);
					printf("%s\t\t%s\n", "IP地址:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					//在当前网卡上伪造一个包
					ARPFrame_t ARPFrame = MakeARP(a);
					//打开该网卡的网络接口
					adhandle = pcap_open(d->name, 655340, PCAP_OPENFLAG_PROMISCUOUS, 1000, 0, 0);
					if (adhandle == NULL) { cout << "打开接口失败"; }
					//发包
					if (Send(adhandle, ARPFrame) == 0) { break; };
					//收包
					ARPFrame_t* RecPacket = Recv(adhandle);
					
					if (Remote) {
						//更新伪装ARP
						for (int j = 0; j < 6; j++) {
							ARPFrame.FrameHeader.SrcMAC[j] = RecPacket->FrameHeader.SrcMAC[j];
							ARPFrame.SendHa[j] = RecPacket->FrameHeader.SrcMAC[j];
						}
						ARPFrame.RecvIP = inet_addr(ip.c_str());

						//重新发包
						if (Send(adhandle, ARPFrame) == 0) { break; };
						//收包
						struct pcap_pkthdr* pkt_header;
						const u_char* pkt_data;
						int res;
						while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
							ARPFrame_t* RecPacket = (ARPFrame_t*)pkt_data;
						
							if (
								*(unsigned short*)(pkt_data + 12) == htons(0x0806)	//0x0806为以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
								&& *(unsigned short*)(pkt_data + 20) == htons(2)	//ARP应答
								&& compare(RecPacket,&ARPFrame)
								)
							{
								break;
							}
						}
					}
					PrintPacket(RecPacket);
				}
			}
		}
	}
}

int main() {
	pcap_if_t* alldevs;				 //所有网络适配器
	char errbuf[PCAP_ERRBUF_SIZE];   //错误缓冲区,大小为256
	pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf);
	//输入想查询的IP地址
	int ip_i = 0;

	//第一次遍历 显示所有网卡信息
	Devslist(alldevs, 0);

	cout << "请选择网卡: " << endl;
	cin >> dev_index;

	cout << "请输入IP: " << endl;
	cin >> ip;

	cout << "本机 0, 远程 1: " << endl;
	cin >> Remote;
	//查询输入ip并显示所有信息
	Devslist(alldevs, dev_index);
	//释放资源
	pcap_freealldevs(alldevs);
}