// Copyright 2020 Liv.
// Author: Liv (1319923129@qq.com)
// This is the project need's header and class statement.
// �������������������������������������ҵ���Ƿ���;����������ɾ����뱾���޹ء�
#pragma once
#include <iostream>
#include <vector>
#include <WinSock2.h>
#include <Windows.h>
#include <fstream>
#include <time.h>
#include <string>
#include <mstcpip.h>

#pragma comment(lib, "ws2_32.lib")

const auto IP_ERROR = "ANALYSISL_IP_ERROR";

class IP {//class start
 public:

	 typedef struct _IPHeader {
		 unsigned char     iphVerLen;		    // �汾�ź�ͷ����
		 unsigned char     ipTOS;				    // ��������
		 unsigned short    ipLength;            // ����ܳ��ȣ�������IP���ĳ���
		 unsigned short    ipID;                    // �����ʶ��Ωһ��ʶ���͵�ÿһ�����ݱ�
		 unsigned short    ipFlags;               // ��־
		 unsigned char     ipTTL;                  // ����ʱ�䣬����TTL
		 unsigned char     ipProtocol;          // Э�飬TCP��UDP��ICMP��
		 unsigned short    ipChecksum;       // У���
		 unsigned long     ipSource;            // ԴIP��ַ
		 unsigned long     ipDestination;     // Ŀ��IP��ַ
	 } IPHeader, * PIPHeader;

 private:
	bool FilterIP(const string& str);
	bool CheckRepeatIP(const string& str);
	bool CheckFeatures(PIPHeader pIPHeader);
	string GetNowTime();

 public:
	void SetIPInformation(const string& IP);
	string AnalysisIP(char* pData);
	SOCKET* init();

 private:
	std::vector<string> ip_datas_;
	std::vector<string> filter_ip_segment_={ "192.168","255.255" };
	std::vector<int> ip_features_ = { 25600 ,4,128,17 };

};//class end
