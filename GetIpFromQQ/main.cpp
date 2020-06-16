// Copyright 2020 Liv.
// Author: Liv (1319923129@qq.com)
// This is a test.
// �������������������������������������ҵ���Ƿ���;����������ɾ����뱾���޹ء�
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
			//���øú�����IP������н���
			ip = ipclass.AnalysisIP(buffer);
			if (ip != IP_ERROR) {
				//������Ϣ
				ipclass.SetIPInformation(ip);
				//�����Ϣ
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
