#include <stdio.h>
#include <winsock2.h>
#include <Windows.h>
#include <pcap.h>

#pragma comment(lib, "packet.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib,"WS2_32.lib")

#define ETH_ARP      0x0806   // ��̫��֡���ͱ�ʾ�������ݵ����ͣ�����ARP�����Ӧ����˵�����ֶε�ֵΪx0806
#define ARP_HARDWARE 1        // Ӳ�������ֶ�ֵΪ��ʾ��̫����ַ
#define ETH_IP       0x0800   // Э�������ֶα�ʾҪӳ���Э���ַ����ֵΪx0800��ʾIP��ַ
#define ARP_REQUEST  1        // ARP����
#define ARP_RESPONSE 2        // ARPӦ��

//14�ֽ���̫���ײ�
struct EthernetHeader
{
	u_char DestMAC[6];    // Ŀ��MAC��ַ6�ֽ�
	u_char SourMAC[6];    // ԴMAC��ַ 6�ֽ�
	u_short EthType;      // ��һ��Э�����ͣ���0x0800������һ����IPЭ�飬0x0806Ϊarp  2�ֽ�
};

//28�ֽ�ARP֡�ṹ
struct ArpHeader
{
	unsigned short hdType;    // Ӳ������
	unsigned short proType;   // Э������
	unsigned char hdSize;     // Ӳ����ַ����
	unsigned char proSize;    // Э���ַ����
	unsigned short op;        // �������ͣ�ARP����1����ARPӦ��2����RARP����3����RARPӦ��4����
	u_char smac[6];           // ԴMAC��ַ
	u_char sip[4];            // ԴIP��ַ
	u_char dmac[6];           // Ŀ��MAC��ַ
	u_char dip[4];            // Ŀ��IP��ַ
};

//��������arp���İ����ܳ���42�ֽ�
struct ArpPacket {
	EthernetHeader ed;
	ArpHeader ah;
};

// ��ȡ��ָ�������ľ��
pcap_t* OpenPcap(int nChoose)
{
	pcap_t* pcap_handle;   //����������������׽ʵ��,��pcap_open���صĶ���
	pcap_if_t* alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];   //���󻺳���,��СΪ256

	// ��ȡ�������豸�б�
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
		exit(0);
	// �ҵ�ָ���������豸
	for (int x = 0; x < nChoose - 1; ++x)
		alldevs = alldevs->next;

	if ((pcap_handle = pcap_open(alldevs->name,      // �豸��
		65536,                                       // ÿ��������
		PCAP_OPENFLAG_PROMISCUOUS,                   // ����ģʽ
		1000,                                        // ��ȡ��ʱʱ��
		NULL,                                        // Զ�̻�����֤
		errbuf                                       // ���󻺳��
	)) == NULL)
	{
		pcap_freealldevs(alldevs);
		exit(0);
	}
	return pcap_handle;
}

int main(int argc, char* argv[])
{
	pcap_t* handle;            // ������������
	EthernetHeader eh;         // ������̫����ͷ
	ArpHeader ah;              // ����ARP��ͷ

	unsigned char sendbuf[42]; // arp���ṹ��С42���ֽ�
	unsigned char src_mac[6] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xff, 0xff };
	unsigned char src_ip[4] = { 0x01, 0x02, 0x03, 0x04 };

	handle = OpenPcap(3);      // �õ������������ľ��

	// ��ʼ���ARP��
	memset(eh.DestMAC, 0xff, 6);      // ��̫���ײ�Ŀ��MAC��ַ,ȫΪ�㲥��ַ
	memcpy(eh.SourMAC, src_mac, 6);   // ��̫���ײ�ԴMAC��ַ
	memcpy(ah.smac, src_mac, 6);      // ARP�ֶ�ԴMAC��ַ
	memset(ah.dmac, 0xff, 6);         // ARP�ֶ�Ŀ��MAC��ַ
	memcpy(ah.sip, src_ip, 4);        // ARP�ֶ�ԴIP��ַ
	memset(ah.dip, 0x05, 4);          // ARP�ֶ�Ŀ��IP��ַ

	// ��ֵMAC��ַ
	eh.EthType = htons(ETH_ARP);   //htons�����������޷��Ŷ�������ת���������ֽ�˳��
	ah.hdType = htons(ARP_HARDWARE);
	ah.proType = htons(ETH_IP);
	ah.hdSize = 6;
	ah.proSize = 4;
	ah.op = htons(ARP_REQUEST);

	// ����һ��ARP����
	memset(sendbuf, 0, sizeof(sendbuf));            // ARP����
	memcpy(sendbuf, &eh, sizeof(eh));               // ���Ȱ�eh��̫���ṹ�����
	memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));  // ������eh�������arp�ṹ

	// �������ݰ�
	if (pcap_sendpacket(handle, sendbuf, 42) == 0)
	{
		printf("����ARP���ݰ��ɹ�! \n");
	}

	system("pause");
	return 0;
}