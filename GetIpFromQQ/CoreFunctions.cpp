// Copyright 2020 Liv.
// Author: Liv (1319923129@qq.com)
// these are the main functional implementations.
// 免责声明：软件仅供技术交流，请勿用于商业及非法用途，如产生法律纠纷与本人无关。
#include "IP.h"

string IP::GetNowTime()
{
	tm* ptm;
	time_t time_ts = time(0);
	ptm = localtime(&time_ts);
	string Buffer = std::to_string(ptm->tm_year + 1900).append("年");
	Buffer.append(std::to_string(ptm->tm_mon + 1)).append("月");
	Buffer.append(std::to_string(ptm->tm_mday)).append("日");
	Buffer.append(std::to_string(ptm->tm_hour + 1)).append("时");
	Buffer.append(std::to_string(ptm->tm_min)).append("分");
	Buffer.append(std::to_string(ptm->tm_sec)).append("秒");
	return Buffer;
}

void IP::SetIPInformation(const string& IP)
{
	//储存获取到的IP信息格式：IP+Address+Time,储存到log中
	std::fstream logtext;
	logtext.open("log.txt", std::ios::app | std::ios::out);
	logtext << "IP：" << IP << std::endl;
	logtext << GetNowTime() << std::endl;
	logtext << "-------------------------------" << std::endl;
	logtext.close();
}

bool IP::FilterIP(const string& str)
{
	//过滤本地IP，可重写或添加过滤项
	for (auto Address : filter_ip_segment_) {
		if (str.substr(0, 7) == Address) {
			return false;
		}
	}
	return true;
}

bool IP::CheckRepeatIP(const string& str)
{
	//检查重复IP
	for (auto Address : ip_datas_) {
		if (str == Address) {
			return false;
		}
	}
	return true;
}

bool IP::CheckFeatures(PIPHeader pIPHeader)
{
	int result=0;
	int size = ip_features_.size();
	for (int i = 0; i < size ; ++i) {
		switch (i) {
		  case 0 :
			  //检查长度
			  ((pIPHeader->ipLength == ip_features_.at(i)) ? result++ : result = false);
			  break;
		  case 1 :
			  //检查版本号
			  (((pIPHeader->iphVerLen >> 4) == ip_features_.at(i)) ? result++ : result = false);
			  break;
		  case 2 :
			  //检查生存周期
			  ((static_cast<int>(pIPHeader->ipTTL) == ip_features_.at(i)) ? result++ : result = false);
			  break;
		  case 3 :
			  //检查协议类型
			  ((static_cast<int>(pIPHeader->ipProtocol) == ip_features_.at(i)) ? result++ : result = false);
			  break;
		  default: {
			  return false;
		  }
		}
	}
	return (result == size ? true : false);
}

string IP::AnalysisIP(char* pData)
{
	PIPHeader ip_header = reinterpret_cast<PIPHeader>(pData);
	string address;
	//检查特征并过滤
	if (CheckFeatures(ip_header)) {
		/*32位的IPv4地址*/
		in_addr temp_addr;
		/*取出目的IP地址*/
		temp_addr.S_un.S_addr = ip_header->ipDestination;
		/*存储目的IP地址*/
		string dest_ip = inet_ntoa(temp_addr);
		if (FilterIP(dest_ip) && CheckRepeatIP(dest_ip)) {
			ip_datas_.push_back(dest_ip);
			return dest_ip;
		}
	}
	return IP_ERROR;
}

SOCKET* IP::init()
{
	WSADATA wsa_data;
	SOCKET* p_socket=new SOCKET;
	char hostname[56];
	hostent* p_host;
	DWORD value = 1;
	SOCKADDR_IN addr_in;
	//初始化
	WSAStartup(MAKEWORD(2, 2), &wsa_data);
	*p_socket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	gethostname(hostname, 56);
	p_host = gethostbyname(static_cast<char*>(hostname));
	//设置
	addr_in.sin_family = AF_INET;
	addr_in.sin_port = htons(8000);
	addr_in.sin_addr.S_un.S_addr = *reinterpret_cast<ULONG*>(p_host->h_addr_list[0]);
	//绑定
	std::cout << "Bindding :" << inet_ntoa(addr_in.sin_addr) << std::endl;
	bind(*p_socket, reinterpret_cast<PSOCKADDR>(&addr_in), sizeof(addr_in));
	//设置混杂模式 以便接收网卡所有数据
	ioctlsocket(*p_socket, SIO_RCVALL, &value);
	return p_socket;
}