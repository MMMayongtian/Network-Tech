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

#pragma pack (1)//�����ֽڶ��뷽ʽ
//��̫��֡ 14�ֽ�
typedef struct FrameHeader_t {
	BYTE DesMAC[6];// Ŀ�ĵ�ַ
	BYTE SrcMAC[6];//Դ��ַ
	WORD FrameType;//֡����
}FrameHeader_t;
//ARP֡ 28�ֽ�
typedef struct ARPFrame_t {
	FrameHeader_t FrameHeader;//��̫��֡ͷ
	WORD HardwareType;//Ӳ������
	WORD ProtocolType;//Э������
	BYTE HLen;//Ӳ����ַ����
	BYTE PLen;//Э���ַ����
	WORD Operation;
	BYTE SendHa[6];	//���Ͷ���̫����ַ
	DWORD SendIP;	//���Ͷ�IP��ַ
	BYTE RecvHa[6];	//Ŀ����̫����ַ
	DWORD RecvIP;	//Ŀ��IP��ַ
} ARPFrame_t;
typedef struct IPHeader_t {//IP�ײ�
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD Flag_Segment;
	BYTE TTL;//��������
	BYTE Protocol;
	WORD Checksum;//У���
	ULONG SrcIP;//ԴIP
	ULONG DstIP;//Ŀ��IP
}IPHeader_t;
typedef struct Data_t {//����֡�ײ���IP�ײ������ݰ�
	FrameHeader_t FrameHeader;//֡�ײ�
	IPHeader_t IPHeader;//IP�ײ�
}Data_t;
typedef struct ICMP {//����֡�ײ���IP�ײ������ݰ�
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
	char buf[0x80];
}ICMP_t;
#pragma pack ()


//ȫ��
pcap_t* adhandle;		//��׽ʵ��,��pcap_open���صĶ���
char ipList[20][32];		//�洢�����豸IP��ַ
char maskList[20][32];
BYTE macList[20][6];

int dev_nums = 0;		//��������������
BYTE MyMAC[6];			//�����豸MAC��ַ

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
void setCheckSum(Data_t* temp)//����У���
{
	temp->IPHeader.Checksum = 0;
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;//ÿ16λΪһ��
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//������������лؾ�
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	temp->IPHeader.Checksum = ~sum;//���ȡ��
}
bool chekCheckSum(Data_t* temp)//����
{
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//����ԭ��У���һ��������
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	if (sum == 65535)//Դ��+����-��ȫ1
		return 1;//У�����ȷ
	return 0;
}
class RouteEntry
{
public:
	DWORD destIP;	//Ŀ�ĵ�ַ
	DWORD mask;		//��������
	DWORD nextHop;	//��һ��
	bool fault;		//�Ƿ�ΪĬ��·��
	RouteEntry* nextEntry;	//��ʽ�洢
	RouteEntry(){
		memset(this, 0, sizeof(*this));//��ʼ��Ϊȫ0
		nextEntry = NULL;
	}
	void printEntry()//��ӡ�������ݣ���ӡ�����롢Ŀ���������һ��IP�����ͣ��Ƿ���ֱ��Ͷ�ݣ�
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
	int routeNum;//����
	//��ʼ�������ֱ�����ӵ�����
	void init() {
		head = NULL;
		routeNum = 0;
		for (int i = 0; i < 2; i++) {
			RouteEntry* newEntry = new RouteEntry();
			newEntry->destIP = (inet_addr(ipList[i])) & (inet_addr(maskList[i]));//����������ip��������а�λ�뼴Ϊ��������
			newEntry->mask = inet_addr(maskList[i]);
			newEntry->fault = 1;//0��ʾֱ��Ͷ�ݵ����磬����ɾ��
			this->add(newEntry);//��ӱ���
		}
	}
	//·�ɱ����ӣ�ֱ��Ͷ������ǰ��ǰ׺������ǰ��
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

		//�������ɳ������ҵ����ʵ�λ��
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
	//ɾ����type=0����ɾ��
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
	//·�ɱ�Ĵ�ӡ mask net next type
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
	//���ң��ǰ׺,������һ����ip
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
		printf("IP��ַ: %u.%u.%u.%u \t MAC��ַ: ", *pIP, *(pIP + 1), *(pIP + 2), *(pIP + 3));
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
			//printf("IP��ַ: %u.%u.%u.%u \t MAC��ַ: ", *pIP, *(pIP + 1), *(pIP + 2), *(pIP + 3));
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

//��ӡMAC��ַ
void PrintPacketMAC(BYTE* MAC) {
	printf("%s:\t%02x-%02x-%02x-%02x-%02x-%02x\n", "Ŀ��MAC��ַ",
		MAC[0],
		MAC[1],
		MAC[2],
		MAC[3],
		MAC[4],
		MAC[5]);
	return;
}
//�����ӿ��б�
void DevsList(pcap_if_t* alldevs) {
	for (pcap_if_t* d = alldevs; d != nullptr; d = d->next)//��ʾ�ӿ��б�
	{
		//��ȡ������ӿ��豸��ip��ַ��Ϣ
		for (pcap_addr* a = d->addresses; a != nullptr; a = a->next)
		{
			if (((struct sockaddr_in*)a->addr)->sin_family == AF_INET && a->addr)
			{//��ӡip��ַ
				//��ӡ�����Ϣ
				//inet_ntoa��ip��ַת���ַ�����ʽ
				printf("%d\n", dev_nums);
				printf("%s\t\t%s\n%s\t%s\n", "name:", d->name, "description:", d->description);
				printf("%s\t\t%s\n", "IP��ַ:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				printf("-------------------------------------------------------------------------------------------------------------\n");
				strcpy(ipList[dev_nums], inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				strcpy(maskList[dev_nums++], inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
			}
		}
	}
}

//α��ARP��
ARPFrame_t MakeARP() {
	ARPFrame_t ARPFrame;
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;//��ʾ�㲥
	//��APRFrame.FrameHeader.SrcMAC����Ϊ����������MAC��ַ
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.SrcMAC[i] = 0x0f;
	//CopyMAC(ARPFrame.FrameHeader.SrcMAC, MyMAC);
	ARPFrame.FrameHeader.FrameType = htons(0x806);//֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);//Э������ΪIP
	ARPFrame.HLen = 6;//Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4;//Э���ַ��Ϊ4
	ARPFrame.Operation = htons(0x0001);//����ΪARP����

	//��ARPFrame.SendHa����Ϊ����������MAC��ַ
	for (int i = 0; i < 6; i++)
		ARPFrame.SendHa[i] = 0x0f;
	//��ARPFrame.SendIP����Ϊ���������ϰ󶨵�IP��ַ

	//��ARPFrame.RecvHa����Ϊ0
	for (int i = 0; i < 6; i++)
		ARPFrame.RecvHa[i] = 0;//��ʾĿ�ĵ�ַδ֪
	//��ARPFrame.RecvIP����Ϊ�����IP��ַ
	//ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
	return ARPFrame;
}

//����
int Send(pcap_t* adhandle, ARPFrame_t ARPFrame) {
	pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)); //{ cout << "����ʧ��"; return 1; }// !=0��ʱ��Ϊsend��������
	//else { return 1; }
	return 1;
}
//�հ�
void resend(pcap_t* adhandle,ICMP_t data, BYTE DstMAC[])
{
	printf("start forwarding a message!\n");
	Data_t* temp = (Data_t*)&data;
	memcpy(temp->FrameHeader.SrcMAC, temp->FrameHeader.DesMAC, 6);//ԴMACΪ����MAC
	memcpy(temp->FrameHeader.DesMAC, DstMAC, 6);//Ŀ��MACΪ��һ��MAC
	temp->IPHeader.TTL -= 1;//TTL-1
	if (temp->IPHeader.TTL < 0)return;//����
	setCheckSum(temp);//��������У���
	int rtn = pcap_sendpacket(adhandle, (const u_char*)temp, 74);//�������ݱ�
	if (rtn == 0)
		printf("Forwarding a message!\n");
		//ltable.write2log_ip("ת��", temp);//д����־
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
			if (CompareMAC(header->DesMAC, MyMAC))//Ŀ��mac���Լ���mac
			{
				printf("MAC is same! It is send to me!\n");
				if (ntohs(header->FrameType) == 0x800)//IP��ʽ�����ݱ�
				{
					Data_t* data = (Data_t*)pkt_data;
					//ltable.write2log_ip("����", data);//����������д����־

					DWORD DstIP = data->IPHeader.DstIP;
					DWORD routeFind = routeTable.lookup(DstIP);
					printf("Find route...\n");
					if (routeFind == -1) {
						printf("The entry was not found!\n");
						continue;
					}
					if (data->IPHeader.DstIP != inet_addr(ipList[0]) || data->IPHeader.DstIP != inet_addr(ipList[1])) {
						//���ǹ㲥��Ϣ
						BYTE broadcast[6] = "fffff";
						int t1 = CompareMAC(data->FrameHeader.DesMAC, broadcast);
						int t2 = CompareMAC(data->FrameHeader.SrcMAC, broadcast);
						if (!t1 && !t2)
						{
							printf("Not a broadcast message!\n");
							//ICMP���İ���IP���ݰ���ͷ����������
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
							//if (ip_ == 0)//ֱ��Ͷ�ݣ�����Ŀ��IP��MAc
							//{
							//	//���ARP����û���������ݣ�����Ҫ��ȡARP
							//	if (!arptable::lookup(ip1_, mac))
							//		arptable::insert(ip1_, mac);
							//	resend(temp, mac);//ת��
							//}

							//else if (ip_ != -1)//��ֱ��Ͷ�ݣ�������һ��IP��MAC
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
			*(unsigned short*)(pkt_data + 12) == htons(0x0806)	//0x0806Ϊ��̫��֡���ͱ�ʾ�������ݵ����ͣ�����ARP�����Ӧ����˵�����ֶε�ֵΪx0806
			&& *(unsigned short*)(pkt_data + 20) == htons(2)	//ARPӦ��
			&&!CompareMAC(RecPacket->FrameHeader.SrcMAC, MyMAC) //����Ϊ������ARP��
			)
		{
			return RecPacket;
		}
	}
}

//��ȡMAC��ַ
void getLocalMAC(pcap_if_t* alldevs) {
	int index = 0;
	for (pcap_if_t* d = alldevs; d != nullptr; d = d->next){
		for (pcap_addr* a = d->addresses; a != nullptr; a = a->next){
			if (((struct sockaddr_in*)a->addr)->sin_family == AF_INET && a->addr){
					printf("%s\t%s\n", "IP��ַ:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					//�ڵ�ǰ������α��һ����

					ARPFrame_t ARPFrame = MakeARP();
					ARPFrame.SendIP = inet_addr(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					ARPFrame.RecvIP = inet_addr(ipList[index]);

					//�򿪸�����������ӿ�
					adhandle = pcap_open(d->name, 655340, PCAP_OPENFLAG_PROMISCUOUS, 1000, 0, 0);
					if (adhandle == NULL) { printf("�򿪽ӿ�ʧ��\n"); return; }

					//����
					if (Send(adhandle, ARPFrame) == 0) { break; };

					//�հ�
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

//��ȡMAC��ַ
void getRemoteMAC(pcap_if_t* alldevs, DWORD DstIP) {
	int index = 0;
	for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
		for (pcap_addr* a = d->addresses; a != nullptr; a = a->next) {
			if (((struct sockaddr_in*)a->addr)->sin_family == AF_INET && a->addr) {
				//printf("%s\t%s\n", "IP��ַ:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				unsigned char* pIP = (unsigned char*)&DstIP;
				printf("REMOTE IP��ַ: %u.%u.%u.%u \n", *pIP, *(pIP + 1), *(pIP + 2), *(pIP + 3));
				//�ڵ�ǰ������α��һ����
				ARPFrame_t ARPFrame = MakeARP();
				//����α���ARP�� ��������MAC����
				PrintPacketMAC(MyMAC);
				CopyMAC(MyMAC, ARPFrame.FrameHeader.SrcMAC);
				CopyMAC(MyMAC, ARPFrame.SendHa);
				ARPFrame.SendIP = inet_addr(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				ARPFrame.RecvIP = DstIP;

				//�򿪸�����������ӿ�
				adhandle = pcap_open(d->name, 655340, PCAP_OPENFLAG_PROMISCUOUS, 1000, 0, 0);
				if (adhandle == NULL) { printf("�򿪽ӿ�ʧ��\n"); return; }

				//����
				if (Send(adhandle, ARPFrame) == 0) { break; };

				//�հ�
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

	pcap_if_t* alldevs;				 //��������������
	char errbuf[PCAP_ERRBUF_SIZE];   //���󻺳���,��СΪ256
	pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf);

	//���� ��ʾ����������Ϣ 33620430
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
	//printf("IP��ַ: %u.%u.%u.%u \t MAC��ַ: ", *pIP, *(pIP + 1), *(pIP + 2), *(pIP + 3));

	//unsigned int ulIP2 = htonl(ulIP1);
	//DWORD resultIP = inet_ntoa(*(in_addr*)(&ulIP2));
	//cout << resultIP << endl;
	

	adhandle = pcap_open(alldevs->name, 655340, PCAP_OPENFLAG_PROMISCUOUS, 1000, 0, 0);
	printf("start to listen ip packet...\n");
	RecvIP(adhandle);

	system("pause");
	//�ͷ���Դ
	pcap_freealldevs(alldevs);

}