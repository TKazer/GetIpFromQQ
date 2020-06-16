// Copyright 2020 Liv.
// Author: Liv (1319923129@qq.com)
// This is a test.
// 免责声明：软件仅供技术交流，请勿用于商业及非法用途，如产生法律纠纷与本人无关。
#include "IP.h"

int main() {
	IP ipclass;
	SOCKET* p_socket = ipclass.init();
	string ip;
	char buffer[1024];
	int ret;
	while (true) {
		ret = recv(*p_socket, buffer, 1024, 0);
		if (ret > 0) {
			//调用该函数对IP封包进行解析
			ip = ipclass.AnalysisIP(buffer);
			if (ip != IP_ERROR) {
				//储存信息
				ipclass.SetIPInformation(ip);
				//输出信息
				std::cout << "-------------------------------------------------------------------------" << std::endl;
				std::cout << "IP >" << ip << std::endl;
			}
		}
	}
	closesocket(*p_socket);
	delete p_socket;
	system("pause");
	return 0;
}
