// Copyright 2020 Liv.
// Author: Liv (1319923129@qq.com)
// This is the project need's header and class statement.
// 免责声明：软件仅供技术交流，请勿用于商业及非法用途，如产生法律纠纷与本人无关。
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
		 unsigned char     iphVerLen;		    // 版本号和头长度
		 unsigned char     ipTOS;				    // 服务类型
		 unsigned short    ipLength;            // 封包总长度，即整个IP报的长度
		 unsigned short    ipID;                    // 封包标识，惟一标识发送的每一个数据报
		 unsigned short    ipFlags;               // 标志
		 unsigned char     ipTTL;                  // 生存时间，就是TTL
		 unsigned char     ipProtocol;          // 协议，TCP、UDP、ICMP等
		 unsigned short    ipChecksum;       // 校验和
		 unsigned long     ipSource;            // 源IP地址
		 unsigned long     ipDestination;     // 目标IP地址
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
