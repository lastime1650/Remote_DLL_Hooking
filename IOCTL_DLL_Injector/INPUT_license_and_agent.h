#pragma warning(disable:4996)


#include <stdio.h>
#include <Windows.h>

#include "ioctl.h";


COMMUNICATION_IOCTL_ENUM input_license_agent(
	PUCHAR License_ID,
	PUCHAR Agent_ID
) {

	ULONG32 yes_or_no = 0;

	while (1) {


		// ���̼��� ID �Է� �˻�
		printf("���̼��� ID�� �Է����ֽʽÿ�: ");
		scanf("%128s", License_ID);

		if (strlen((PCHAR)License_ID) != 128) {
			printf(" ���̼��� �Է��� ���� 128�� �ƴմϴ�. �̺��� ũ�ų� ���� �� �����ϴ�;;\n ");
			continue;
		}


		// ������Ʈ ID�Է� �˻�
		while (1) {
			printf("������Ʈ ID�� �Է����ֽʽÿ�: ");
			scanf("%128s", Agent_ID);

			if (strlen((PCHAR)Agent_ID) < 128) {
				printf(" ������Ʈ �Է��� ���� 128�� �ƴմϴ�. �̷� ��쿡�� AGENT_ID�� ���� ����� ���Դϴ�. [�ٽ� �Է��Ͻðڽ��ϱ�? -> (1): yes / (2) no(register)]\n ");
				scanf("%ld", &yes_or_no);
				if (yes_or_no == 1) {
					continue;
				}
				else {
					return REQUESET_without_AGENT_ID; // ������Ʈ ���� �Ҵ�䱸
				}
			}
			if (strlen((PCHAR)Agent_ID) > 128) {
				printf(" ������Ʈ �Է��� ���� 128�� �ʰ��մϴ�. �̷� ��쿡�� AGENT_ID�� ���� ����ϰų� �ٽ� �Է��ؾ߸��մϴ�. [�ٽ� �Է��Ͻðڽ��ϱ�? -> (1): yes / (2) no(register)]\n ");
				scanf("%ld", &yes_or_no);
				if (yes_or_no == 1) {
					continue;
				}
				else {
					return REQUESET_without_AGENT_ID; // ������Ʈ ���� �Ҵ�䱸
				}
			}
			else {
				return REQUEST_all; //������Ʈ ���� �� ���
			}
		}

	}

}

