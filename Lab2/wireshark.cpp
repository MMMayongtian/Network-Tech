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
//������ �ڶ��뷽ʽ
typedef struct FrameHeader_t {
	BYTE DesMAC[6];
	// Ŀ�ĵ�ַ
	BYTE SrcMAC[6];
	//Դ��ַ
	WORD FrameType;
	//֡����
}FrameHeader_t;
typedef struct IPHeader_t {
	//IP�ײ�
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
	//����֡�ײ���IP�ײ������ݰ�
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
} Data_t;
#pragma pack() //�ָ�ȱʡ���뷽ʽ

void PrintFrameHeader(const u_char* packetData)
{

	struct FrameHeader_t* protocol;
	protocol = (struct FrameHeader_t*)packetData;

	u_short ether_type = ntohs(protocol->FrameType);  // ��̫������
	u_char* ether_src = protocol->SrcMAC;         // ��̫��ԭʼMAC��ַ
	u_char* ether_dst = protocol->DesMAC;         // ��̫��Ŀ��MAC��ַ

	printf("	����: 0x%x \t", ether_type);
	printf("ԭMAC��ַ: %02X:%02X:%02X:%02X:%02X:%02X \t",
		ether_src[0], ether_src[1], ether_src[2], ether_src[3], ether_src[4], ether_src[5]);
	printf("Ŀ��MAC��ַ: %02X:%02X:%02X:%02X:%02X:%02X \n",
		ether_dst[0], ether_dst[1], ether_dst[2], ether_dst[3], ether_dst[4], ether_dst[5]);
}
void PrintIPHeader(const u_char* packetData) {
	struct IPHeader_t* ip_protocol;

	// +14 ����������·��
	ip_protocol = (struct IPHeader_t*)(packetData + 14);
	SOCKADDR_IN Src_Addr, Dst_Addr = { 0 };

	u_short check_sum = ntohs(ip_protocol->Checksum);
	int ttl = ip_protocol->TTL;
	int proto = ip_protocol->Protocol;

	Src_Addr.sin_addr.s_addr = ip_protocol->SrcIP;
	Dst_Addr.sin_addr.s_addr = ip_protocol->DstIP;

	char buff1[17];
	::inet_ntop(AF_INET, (const void*)&Src_Addr.sin_addr, buff1, 17);
	printf("	Դ��ַ: %s \t", buff1);
	char buff2[17];
	::inet_ntop(AF_INET, (const void*)&Dst_Addr.sin_addr, buff2, 17);
	printf("Ŀ���ַ: %s \t", buff2);
	printf("У��� :%5X \t TTL :%4d \t", check_sum, ttl);
	printf("Э������:");
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
	//��ȡ�豸�б�
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) != -1) {
		cout << "��ȡ�豸�б�ɹ�" << endl;
	}
	else { 
		cout << "��ȡ�豸�б�ʧ��" << endl; 
		return 0; 
	}
	//��ʾ��ȡ���豸�б�
	int devid = 0;
	for (dev = alldevs; dev != NULL; dev = dev->next) {
		cout << "dev_id: " << ++devid << endl;
		cout << "	dev_name: " << dev->name << endl;
		cout << "	dev_describe: " << dev->description << endl;
		//��ȡ������ӿ��豸��IP��ַ��Ϣ
		for(a = dev->addresses; a !=NULL; a = a->next){
			//�жϸõ�ַ�Ƿ�ΪIP��ַ
			if (a->addr->sa_family == AF_INET) {
				cout << "	IP��ַ: " << a->addr;
				cout << "	��������: " << a->netmask;
				cout << "	�㲥��ַ: " << a->broadaddr;
				cout <<	"	Ŀ�ĵ�ַ: " << a->dstaddr << endl;
			}
		}
		cout << "----------------------------------------" << endl;
	}
	cout << "��ʼ����:" << endl;
	devid = 0;
	for (pcap_if_t* dev = alldevs; dev != NULL; dev = dev->next) {
		//������ӿ�
		pcap_t* handle = pcap_open(dev->name, 655340, PCAP_OPENFLAG_PROMISCUOUS, 2000, NULL, errbuf);
		//���ݰ�ͷ
		pcap_pkthdr* pkt_header;
		//���ݰ�
		const u_char* pkt_data;
		cout << "dev_id: " << ++devid << endl;
		//�������ݰ�
		int retvalue = pcap_next_ex(handle, &pkt_header, &pkt_data);
		cout << "	��������: " << pkt_header->len << endl;
		PrintFrameHeader(pkt_data);
		PrintIPHeader(pkt_data);
		if (retvalue == 0) {
			cout << "	��ȡ���ĳ�ʱ" << endl;
		}
		cout << "----------------------------------------" << endl;
	}
	//�ͷ��豸�б�
	pcap_freealldevs(alldevs);
}