#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include"pcap.h"
#include <WinSock2.h>
#include <Windows.h>
#include<iostream>
#include<stdio.h>
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
typedef struct IPHeader_t {//IP首部
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD Flag_Segment;
	BYTE TTL;//生命周期
	BYTE Protocol;
	WORD Checksum;//校验和
	ULONG SrcIP;//源IP
	ULONG DstIP;//目的IP
}IPHeader_t;
typedef struct Data_t {//包含帧首部和IP首部的数据包
	FrameHeader_t FrameHeader;//帧首部
	IPHeader_t IPHeader;//IP首部
}Data_t;
typedef struct ICMP {//包含帧首部和IP首部的数据包
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
	char buf[0x80];
}ICMP_t;
#pragma pack ()


//全局
pcap_t* adhandle;		//捕捉实例,是pcap_open返回的对象
char ipList[20][32];		//存储网卡设备IP地址
char maskList[20][32];
BYTE macList[20][6];

int dev_nums = 0;		//适配器计数变量
BYTE MyMAC[6];			//本机设备MAC地址

bool CompareMAC(BYTE* MAC_1, BYTE* MAC_2) {
	for (int i = 0; i < 6; i++) {
		if (MAC_1[i] != MAC_2[i]) {
			return false;
		}
	}
	return true;
}
void CopyMAC(BYTE* MAC_1, BYTE* MAC_2) {
	for (int i = 0; i < 6; i++) {
		MAC_2[i] = MAC_1[i];
	}
}
void setCheckSum(Data_t* temp)//设置校验和
{
	temp->IPHeader.Checksum = 0;
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;//每16位为一组
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//如果溢出，则进行回卷
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	temp->IPHeader.Checksum = ~sum;//结果取反
}
bool chekCheckSum(Data_t* temp)//检验
{
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//包含原有校验和一起进行相加
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	if (sum == 65535)//源码+反码-》全1
		return 1;//校验和正确
	return 0;
}
class RouteEntry
{
public:
	DWORD destIP;	//目的地址
	DWORD mask;		//子网掩码
	DWORD nextHop;	//下一跳
	bool fault;		//是否为默认路由
	RouteEntry* nextEntry;	//链式存储
	RouteEntry(){
		memset(this, 0, sizeof(*this));//初始化为全0
		nextEntry = NULL;
	}
	void printEntry()//打印表项内容，打印出掩码、目的网络和下一跳IP、类型（是否是直接投递）
	{	
		printf("|||||||||||||||||||||||||||||||||\n");
		unsigned char* pIP = (unsigned char*)&destIP;
		printf("destIP : %u.%u.%u.%u \n", *pIP, *(pIP + 1), *(pIP + 2), *(pIP + 3));
		pIP = (unsigned char*)&mask;
		printf("mask   : %u.%u.%u.%u \n", *pIP, *(pIP + 1), *(pIP + 2), *(pIP + 3));
		pIP = (unsigned char*)&nextHop;
		printf("nextHop: %u.%u.%u.%u \n", *pIP, *(pIP + 1), *(pIP + 2), *(pIP + 3));
	}
};

class RouteTable
{
public:
	RouteEntry* head;
	int routeNum;//条数
	//初始化，添加直接连接的网络
	void init() {
		head = NULL;
		routeNum = 0;
		for (int i = 0; i < 2; i++) {
			RouteEntry* newEntry = new RouteEntry();
			newEntry->destIP = (inet_addr(ipList[i])) & (inet_addr(maskList[i]));//本机网卡的ip和掩码进行按位与即为所在网络
			newEntry->mask = inet_addr(maskList[i]);
			newEntry->fault = 1;//0表示直接投递的网络，不可删除
			this->add(newEntry);//添加表项
		}
	}
	//路由表的添加，直接投递在最前，前缀长的在前面
	void add(RouteEntry* newEntry) {
		if (head == NULL) {
			head = newEntry;
			routeNum++;
			return;
		}

		//RouteEntry* cur = head;
		//while (cur->nextEntry) {
		//	if (cur->fault) {
		//		cur = cur->nextEntry;
		//	}
		//}

		if (newEntry->mask > head->mask) {
			newEntry->nextEntry = head;
			head = newEntry;
			routeNum++;
			return;
		}

		//按掩码由长至短找到合适的位置
		RouteEntry* cur = head;
		while (cur->nextEntry) {
			if (newEntry->mask > cur->nextEntry->mask) {
				break;
			}
			cur = cur->nextEntry;
		}
		newEntry->nextEntry = cur->nextEntry;
		cur->nextEntry = newEntry;
		routeNum++;
		return;
	}
	//删除，type=0不能删除
	void remove(int index) {
		if (index > routeNum) {
			printf("Error! Access out of bounds, no entry exists!\n");
			return;
		}

		int i = 1;
		RouteEntry* cur = head;
		while (i < index - 1) {
			i++;
			cur = cur->nextEntry;
		}

		RouteEntry* t = cur->nextEntry;
		if (t->fault) {
			printf("Error! You cannot delete the default route!\n");
			return;
		}
		cur->nextEntry = t->nextEntry;
		routeNum--;
		delete t;
		return;
	}
	//路由表的打印 mask net next type
	void printTable() {
		printf("---------------------------------------\n");
		RouteEntry* cur = head;
		while (cur) {
			cur->printEntry();
			cur = cur->nextEntry;
		}
		printf("---------------------------------------\n");
		return;
	}
	//查找，最长前缀,返回下一跳的ip
	DWORD lookup(DWORD ip) {
		RouteEntry* cur = head;
		while (cur != NULL) {
			if ((cur->mask & ip) == cur->destIP) {
				if (cur->fault) {
					return 0;
				}
				return cur->nextHop;
			}
			cur = cur->nextEntry;
		}
		return -1;
	}
};

class arpEntry
{
public:
	DWORD ip;//IP
	BYTE mac[6];//MAC
	void printEntry() {
		unsigned char* pIP = (unsigned char*)&ip;
		printf("IP地址: %u.%u.%u.%u \t MAC地址: ", *pIP, *(pIP + 1), *(pIP + 2), *(pIP + 3));
		printf("%02x-%02x-%02x-%02x-%02x-%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	}
};
class ArpTable 
{
public:
	arpEntry arp_table[50];
	ArpTable() {
		arpNum = 0;
	};
	int arpNum = 0;
	void insert(DWORD ip, BYTE mac[6]) {
		arp_table[arpNum].ip = ip;
		CopyMAC(mac, arp_table[arpNum].mac);
		arpNum++;
	}
	void update(DWORD ip, BYTE mac[6]) {
		return;
	}
	int lookup(DWORD ip,BYTE mac[6]) {
		unsigned char* pIP = (unsigned char*)&ip;
		printf("Query ip : %u.%u.%u.%u: \n", *pIP, *(pIP + 1), *(pIP + 2), *(pIP + 3));
		for (int i = 0; i < arpNum; i++) {
			pIP = (unsigned char*)&arp_table[i].ip;
			//printf("Be matched ip : %u.%u.%u.%u: \n", *pIP, *(pIP + 1), *(pIP + 2), *(pIP + 3));
			if (ip == arp_table[i].ip) {
				CopyMAC(arp_table[i].mac, mac);
				return i;
			}
		}
		printf("The entry does not exist in the arp table!\n");
		return -1;
	}
	void printTable () {
		printf("--------------------------------------------\n");
		printf("ARP Table: \n");
		for (int i = 0; i < arpNum; i++) {
			//unsigned char* pIP = (unsigned char*)&arp_table[i].ip;
			//printf("IP地址: %u.%u.%u.%u \t MAC地址: ", *pIP, *(pIP + 1), *(pIP + 2), *(pIP + 3));
			//printf("%02x-%02x-%02x-%02x-%02x-%02x\n",
			//	arp_table[i].mac[0],
			//	arp_table[i].mac[1],
			//	arp_table[i].mac[2],
			//	arp_table[i].mac[3],
			//	arp_table[i].mac[4],
			//	arp_table[i].mac[5]);
			arp_table[i].printEntry();
		}
		printf("--------------------------------------------\n");
	}
};

RouteTable routeTable;
ArpTable arpTable;

//打印MAC地址
void PrintPacketMAC(BYTE* MAC) {
	printf("%s:\t%02x-%02x-%02x-%02x-%02x-%02x\n", "目标MAC地址",
		MAC[0],
		MAC[1],
		MAC[2],
		MAC[3],
		MAC[4],
		MAC[5]);
	return;
}
//遍历接口列表
void DevsList(pcap_if_t* alldevs) {
	for (pcap_if_t* d = alldevs; d != nullptr; d = d->next)//显示接口列表
	{
		//获取该网络接口设备的ip地址信息
		for (pcap_addr* a = d->addresses; a != nullptr; a = a->next)
		{
			if (((struct sockaddr_in*)a->addr)->sin_family == AF_INET && a->addr)
			{//打印ip地址
				//打印相关信息
				//inet_ntoa将ip地址转成字符串格式
				printf("%d\n", dev_nums);
				printf("%s\t\t%s\n%s\t%s\n", "name:", d->name, "description:", d->description);
				printf("%s\t\t%s\n", "IP地址:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				printf("-------------------------------------------------------------------------------------------------------------\n");
				strcpy(ipList[dev_nums], inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				strcpy(maskList[dev_nums++], inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
			}
		}
	}
}

//伪造ARP包
ARPFrame_t MakeARP() {
	ARPFrame_t ARPFrame;
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;//表示广播
	//将APRFrame.FrameHeader.SrcMAC设置为本机网卡的MAC地址
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.SrcMAC[i] = 0x0f;
	//CopyMAC(ARPFrame.FrameHeader.SrcMAC, MyMAC);
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

	//将ARPFrame.RecvHa设置为0
	for (int i = 0; i < 6; i++)
		ARPFrame.RecvHa[i] = 0;//表示目的地址未知
	//将ARPFrame.RecvIP设置为请求的IP地址
	//ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
	return ARPFrame;
}

//发包
int Send(pcap_t* adhandle, ARPFrame_t ARPFrame) {
	pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)); //{ cout << "发包失败"; return 1; }// !=0的时候为send发生错误
	//else { return 1; }
	return 1;
}
//收包
void resend(pcap_t* adhandle,ICMP_t data, BYTE DstMAC[])
{
	printf("start forwarding a message!\n");
	Data_t* temp = (Data_t*)&data;
	memcpy(temp->FrameHeader.SrcMAC, temp->FrameHeader.DesMAC, 6);//源MAC为本机MAC
	memcpy(temp->FrameHeader.DesMAC, DstMAC, 6);//目的MAC为下一跳MAC
	temp->IPHeader.TTL -= 1;//TTL-1
	if (temp->IPHeader.TTL < 0)return;//丢弃
	setCheckSum(temp);//重新设置校验和
	int rtn = pcap_sendpacket(adhandle, (const u_char*)temp, 74);//发送数据报
	if (rtn == 0)
		printf("Forwarding a message!\n");
		//ltable.write2log_ip("转发", temp);//写入日志
}


ICMP RecvIP(pcap_t* adhandle) {
	pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	printf("Enter the function RecvIP...\n");

	while (1) {
		int res = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
		if(res > 0) {
			//printf("capture a packet.\n");
			FrameHeader_t* header = (FrameHeader_t*)pkt_data;
			//PrintPacketMAC(header->DesMAC);
			if (CompareMAC(header->DesMAC, MyMAC))//目的mac是自己的mac
			{
				printf("MAC is same! It is send to me!\n");
				if (ntohs(header->FrameType) == 0x800)//IP格式的数据报
				{
					Data_t* data = (Data_t*)pkt_data;
					//ltable.write2log_ip("接收", data);//将接收内容写入日志

					DWORD DstIP = data->IPHeader.DstIP;
					DWORD routeFind = routeTable.lookup(DstIP);
					printf("Find route...\n");
					if (routeFind == -1) {
						printf("The entry was not found!\n");
						continue;
					}
					if (data->IPHeader.DstIP != inet_addr(ipList[0]) || data->IPHeader.DstIP != inet_addr(ipList[1])) {
						//不是广播消息
						BYTE broadcast[6] = "fffff";
						int t1 = CompareMAC(data->FrameHeader.DesMAC, broadcast);
						int t2 = CompareMAC(data->FrameHeader.SrcMAC, broadcast);
						if (!t1 && !t2)
						{
							printf("Not a broadcast message!\n");
							//ICMP报文包含IP数据包报头和其它内容
							ICMP_t* sendPacket_t = (ICMP_t*)pkt_data;
							ICMP_t sendPacket = *sendPacket_t;
							BYTE mac[6];
							if (routeFind == 0) {
								arpTable.lookup(DstIP, mac);
								printf("The mac of DstIP:");
								PrintPacketMAC(mac);
								resend(adhandle,sendPacket, mac);
							}
							else {
								arpTable.lookup(routeFind,mac);
								printf("The mac of nextHop:");
								PrintPacketMAC(mac);
								resend(adhandle, sendPacket, mac);
							}
							//if (ip_ == 0)//直接投递，查找目的IP的MAc
							//{
							//	//如果ARP表中没有所需内容，则需要获取ARP
							//	if (!arptable::lookup(ip1_, mac))
							//		arptable::insert(ip1_, mac);
							//	resend(temp, mac);//转发
							//}

							//else if (ip_ != -1)//非直接投递，查找下一条IP的MAC
							//{
							//	if (!arptable::lookup(ip_, mac))
							//		arptable::insert(ip_, mac);
							//	resend(temp, mac);
							//}
						}
					}

				}
			}


		}
	}
}
ARPFrame_t* Recv(pcap_t* adhandle) {
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	int res;
	while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
		ARPFrame_t* RecPacket = (ARPFrame_t*)pkt_data;
		//PrintPacketMAC(RecPacket);
		if (
			*(unsigned short*)(pkt_data + 12) == htons(0x0806)	//0x0806为以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
			&& *(unsigned short*)(pkt_data + 20) == htons(2)	//ARP应答
			&&!CompareMAC(RecPacket->FrameHeader.SrcMAC, MyMAC) //若不为发出的ARP包
			)
		{
			return RecPacket;
		}
	}
}

//获取MAC地址
void getLocalMAC(pcap_if_t* alldevs) {
	int index = 0;
	for (pcap_if_t* d = alldevs; d != nullptr; d = d->next){
		for (pcap_addr* a = d->addresses; a != nullptr; a = a->next){
			if (((struct sockaddr_in*)a->addr)->sin_family == AF_INET && a->addr){
					printf("%s\t%s\n", "IP地址:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					//在当前网卡上伪造一个包

					ARPFrame_t ARPFrame = MakeARP();
					ARPFrame.SendIP = inet_addr(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					ARPFrame.RecvIP = inet_addr(ipList[index]);

					//打开该网卡的网络接口
					adhandle = pcap_open(d->name, 655340, PCAP_OPENFLAG_PROMISCUOUS, 1000, 0, 0);
					if (adhandle == NULL) { printf("打开接口失败\n"); return; }

					//发包
					if (Send(adhandle, ARPFrame) == 0) { break; };

					//收包
					ARPFrame_t* RecPacket;
					struct pcap_pkthdr* pkt_header;
					const u_char* pkt_data;
					int res;
					while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
						RecPacket = (ARPFrame_t*)pkt_data;
						//PrintPacketMAC(RecPacket);
						if (!CompareMAC(RecPacket->FrameHeader.SrcMAC, ARPFrame.FrameHeader.SrcMAC)
							&& CompareMAC(RecPacket->FrameHeader.DesMAC, ARPFrame.FrameHeader.SrcMAC)
							&& RecPacket->SendIP == ARPFrame.RecvIP
							) {

							arpTable.insert(inet_addr(ipList[index]), RecPacket->FrameHeader.SrcMAC);
							arpTable.insert(inet_addr(ipList[index+1]), RecPacket->FrameHeader.SrcMAC);
							CopyMAC(RecPacket->FrameHeader.SrcMAC, MyMAC);
							PrintPacketMAC(RecPacket->FrameHeader.SrcMAC);
							index++;
							return;
						}
					}

			}
		}
	}
}

//获取MAC地址
void getRemoteMAC(pcap_if_t* alldevs, DWORD DstIP) {
	int index = 0;
	for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
		for (pcap_addr* a = d->addresses; a != nullptr; a = a->next) {
			if (((struct sockaddr_in*)a->addr)->sin_family == AF_INET && a->addr) {
				//printf("%s\t%s\n", "IP地址:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				unsigned char* pIP = (unsigned char*)&DstIP;
				printf("REMOTE IP地址: %u.%u.%u.%u \n", *pIP, *(pIP + 1), *(pIP + 2), *(pIP + 3));
				//在当前网卡上伪造一个包
				ARPFrame_t ARPFrame = MakeARP();
				//更新伪造的ARP包 将本机的MAC填入
				PrintPacketMAC(MyMAC);
				CopyMAC(MyMAC, ARPFrame.FrameHeader.SrcMAC);
				CopyMAC(MyMAC, ARPFrame.SendHa);
				ARPFrame.SendIP = inet_addr(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				ARPFrame.RecvIP = DstIP;

				//打开该网卡的网络接口
				adhandle = pcap_open(d->name, 655340, PCAP_OPENFLAG_PROMISCUOUS, 1000, 0, 0);
				if (adhandle == NULL) { printf("打开接口失败\n"); return; }

				//发包
				if (Send(adhandle, ARPFrame) == 0) { break; };

				//收包
				ARPFrame_t* RecPacket;
				struct pcap_pkthdr* pkt_header;
				const u_char* pkt_data;
				int res;
				while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
					RecPacket = (ARPFrame_t*)pkt_data;
					if (!CompareMAC(RecPacket->FrameHeader.SrcMAC, ARPFrame.FrameHeader.SrcMAC)
						&& CompareMAC(RecPacket->FrameHeader.DesMAC, ARPFrame.FrameHeader.SrcMAC)
						&& RecPacket->SendIP == ARPFrame.RecvIP
						) {

						arpTable.insert(DstIP, RecPacket->FrameHeader.SrcMAC);
						//return;
						break;
					}
				}
			}
		}
	}
}

int main() {

	pcap_if_t* alldevs;				 //所有网络适配器
	char errbuf[PCAP_ERRBUF_SIZE];   //错误缓冲区,大小为256
	pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf);

	//遍历 显示所有网卡信息 33620430
	DevsList(alldevs);

	getLocalMAC(alldevs);
	//arpTable.printTable();
	printf("start get remote ip :\n");
	char szIP[32] = "206.1.1.2";
	unsigned int ulIP1 = inet_addr(szIP);
	getRemoteMAC(alldevs, ulIP1);
	//arpTable.printTable();

	char szIP1[32] = "206.1.2.2";
	ulIP1 = inet_addr(szIP1);
	getRemoteMAC(alldevs, ulIP1);
	arpTable.printTable();
	routeTable.init();

	RouteEntry* newEntry = new RouteEntry;
	char szIP2[32] = "206.1.3.0";
	ulIP1 = inet_addr(szIP2);
	newEntry->destIP = ulIP1;

	char mask2[32] = "255.255.255.0";
	ulIP1 = inet_addr(mask2);
	newEntry->mask = ulIP1;

	char nextHop[32] = "206.1.2.2";
	ulIP1 = inet_addr(nextHop);
	newEntry->nextHop = ulIP1;

	routeTable.add(newEntry);

	routeTable.printTable();
	//cout << ulIP1 << endl;

	//unsigned char* pIP = (unsigned char*)&ulIP1;
	//printf("IP地址: %u.%u.%u.%u \t MAC地址: ", *pIP, *(pIP + 1), *(pIP + 2), *(pIP + 3));

	//unsigned int ulIP2 = htonl(ulIP1);
	//DWORD resultIP = inet_ntoa(*(in_addr*)(&ulIP2));
	//cout << resultIP << endl;
	

	adhandle = pcap_open(alldevs->name, 655340, PCAP_OPENFLAG_PROMISCUOUS, 1000, 0, 0);
	printf("start to listen ip packet...\n");
	RecvIP(adhandle);

	system("pause");
	//释放资源
	pcap_freealldevs(alldevs);

}