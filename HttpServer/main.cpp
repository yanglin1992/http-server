#include <winsock2.h>
#include <windows.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#pragma comment (lib,"ws2_32")
#define uPort 80
#define MAX_BUFFER   100000
#define SENDBLOCK   200000
#define SERVERNAME   "AcIDSoftWebServer/0.1b"
#define FileName   "HelloWorld.html"

typedef struct _NODE_
{
	SOCKET s;
	sockaddr_in Addr;
	_NODE_* pNext;
}Node, *pNode;


//���̴߳������ͻ��˵�����
typedef struct _THREAD_
{
	DWORD ThreadID;
	HANDLE hThread;
	_THREAD_* pNext;
}Thread, *pThread;

pNode pHead = NULL;
pNode pTail = NULL;
pThread pHeadThread = NULL;
pThread pTailThread = NULL;

bool InitSocket();//�̺߳���
DWORD WINAPI AcceptThread(LPVOID lpParam);
DWORD WINAPI ClientThread(LPVOID lpParam);
bool IoComplete(char* szRequest);     //���ݰ���У�麯��
bool AddClientList(SOCKET s, sockaddr_in addr);
bool AddThreadList(HANDLE hThread, DWORD ThreadID);
bool ParseRequest(char* szRequest, char* szResponse, BOOL &bKeepAlive);

//���Ǵ��Html�ļ���Ŀ¼
char HtmlDir[512] = { 0 };

void main()
{
	if (!InitSocket())
	{
		printf("InitSocket Error\n");
		return;
	}

	GetCurrentDirectory(512, HtmlDir);
	strcat(HtmlDir, "\\HTML\\");
	strcat(HtmlDir, FileName);

	//����һ�������߳�
	HANDLE hAcceptThread = CreateThread(NULL, 0, AcceptThread, NULL, 0, NULL);

	// ʹ���¼�ģ����ʵ�����ǵ�Web������
	WaitForSingleObject(hAcceptThread, INFINITE);
}

DWORD WINAPI AcceptThread(LPVOID lpParam)   //�����߳�
{
	//����һ�������׽���
	SOCKET sListen = WSASocketW(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED); //ʹ���¼��ص����׽���
	if (sListen == INVALID_SOCKET)
	{
		printf("Create Listen Error\n");
		return -1;
	}
	//��ʼ�����������ĵ�ַ
	sockaddr_in LocalAddr;
	LocalAddr.sin_addr.S_un.S_addr = INADDR_ANY;
	LocalAddr.sin_family = AF_INET;
	LocalAddr.sin_port = htons(2000);
	//���׽��� 80�˿�
	int Ret = bind(sListen, (sockaddr*)&LocalAddr, sizeof(LocalAddr));
	if (Ret == SOCKET_ERROR)
	{
		printf("Bind Error\n");
		return -1;
	}
	//����
	listen(sListen, 5);
	//����һ���¼�
	WSAEVENT Event = WSACreateEvent();
	if (Event == WSA_INVALID_EVENT)
	{
		printf("Create WSAEVENT Error\n");
		closesocket(sListen);
		CloseHandle(Event);     //�����¼�ʧ�� �ر��׽��� �ر��¼�
		return -1;
	}
	//�����ǵļ����׽��������ǵ��¼����й�������ΪAccept
	WSAEventSelect(sListen, Event, FD_ACCEPT);
	WSANETWORKEVENTS NetWorkEvent;
	sockaddr_in ClientAddr;
	int nLen = sizeof(ClientAddr);
	DWORD dwIndex = 0;
	while (1)
	{
		dwIndex = WSAWaitForMultipleEvents(1, &Event, FALSE, WSA_INFINITE, FALSE);
		dwIndex = dwIndex - WAIT_OBJECT_0;
		if (dwIndex == WSA_WAIT_TIMEOUT || dwIndex == WSA_WAIT_FAILED)
		{
			continue;
		}
		//������������¼����Ǿͽ����ж�
		WSAEnumNetworkEvents(sListen, Event, &NetWorkEvent);
		ResetEvent(&Event);   //
		if (NetWorkEvent.lNetworkEvents == FD_ACCEPT)
		{
			if (NetWorkEvent.iErrorCode[FD_ACCEPT_BIT] == 0)
			{
				//����ҪΪ�µ����ӽ��н��ܲ������ڴ����������
				SOCKET sClient = WSAAccept(sListen, (sockaddr*)&ClientAddr, &nLen, NULL, NULL);
				if (sClient == INVALID_SOCKET)
				{
					continue;
				}
				else
				{
					//������ճɹ�����Ҫ���û���������Ϣ��ŵ�������
					if (!AddClientList(sClient, ClientAddr))
					{
						continue;
					}
				}
			}
		}
	}
	return 0;
}

void ResponseClient(char *msg, int sClient)
{
	DWORD NumberOfBytesSent = 0;
	DWORD dwBytesSent = 0;
	WSABUF buffers;

	int ret = 0;
	do
	{
		buffers.len = (strlen(msg) - dwBytesSent) >= SENDBLOCK ? SENDBLOCK : strlen(msg) - dwBytesSent;
		buffers.buf = (char*)((DWORD)msg + dwBytesSent);
		ret = WSASend(sClient, &buffers, 1, &NumberOfBytesSent, 0, 0, NULL);
		if (SOCKET_ERROR != ret)
			dwBytesSent += NumberOfBytesSent;
	} while ((dwBytesSent < strlen(msg)) && SOCKET_ERROR != ret);
}

DWORD WINAPI ClientThread0(LPVOID lpParam)
{
	//���ǽ�ÿ���û�����Ϣ�Բ�������ʽ���뵽���߳�
	pNode pTemp = (pNode)lpParam;
	SOCKET sClient = pTemp->s; //����ͨ���׽���
	WSAEVENT Event = WSACreateEvent(); //���¼�����ͨ���׽��ֹ������ж��¼�������
	WSANETWORKEVENTS NetWorkEvent;
	char szRequest[1024] = { 0 }; //������
	char szResponse[1024] = { 0 }; //��Ӧ����
	BOOL bKeepAlive = FALSE; //�Ƿ��������
	if (Event == WSA_INVALID_EVENT)
	{
		return -1;
	}
	int Ret = WSAEventSelect(sClient, Event, FD_READ | FD_WRITE | FD_CLOSE); //�����¼����׽���
	DWORD dwIndex = 0;
	while (1)
	{
		dwIndex = WSAWaitForMultipleEvents(1, &Event, FALSE, WSA_INFINITE, FALSE);
		dwIndex = dwIndex - WAIT_OBJECT_0;
		if (dwIndex == WSA_WAIT_TIMEOUT || dwIndex == WSA_WAIT_FAILED)
		{
			continue;
		}
		// ����ʲô�����¼�����
		Ret = WSAEnumNetworkEvents(sClient, Event, &NetWorkEvent);
		//�������
		if (!NetWorkEvent.lNetworkEvents)
		{
			continue;
		}
		if (NetWorkEvent.lNetworkEvents & FD_READ) //���������˼��
		{
			DWORD NumberOfBytesRecvd;
			WSABUF Buffers;
			DWORD dwBufferCount = 1;
			char szBuffer[MAX_BUFFER]= {0};
			DWORD Flags = 0;
			Buffers.buf = szBuffer;
			Buffers.len = MAX_BUFFER;
			Ret = WSARecv(sClient, &Buffers, dwBufferCount, &NumberOfBytesRecvd, &Flags, NULL, NULL);

			printf("%s", szBuffer);

			//����������Ҫ����Ƿ�õ�����������
			memcpy(szRequest, szBuffer, NumberOfBytesRecvd);
			if (!IoComplete(szRequest)) //У�����ݰ�
			{
				continue;
			}
			if (!ParseRequest(szRequest, szResponse, bKeepAlive)) //�������ݰ�
			{
				//��������ͽ����˼򵥵Ĵ���
				continue;
			}
			// ������Ӧ���ͻ���
			ResponseClient(szResponse, sClient);

			closesocket(sClient);
			break;
		}

		if (NetWorkEvent.lNetworkEvents & FD_CLOSE)
		{
			//��������û�д�������Ҫ���ڴ�����ͷŷ����ڴ�й¶
		}

	}
	return 0;
}

DWORD WINAPI ClientThread(LPVOID lpParam)
{
	// ���ǽ�ÿ���û�����Ϣ�Բ�������ʽ���뵽���߳�
	pNode pTemp = (pNode)lpParam;
	SOCKET sClient = pTemp->s;
	char szRequest[1024] = { 0 }; //������
	char szResponse[1024] = { 0 }; //��Ӧ����
	BOOL bKeepAlive = FALSE; //�Ƿ��������

	DWORD NumberOfBytesRecvd;
	WSANETWORKEVENTS NetWorkEvent;

	WSABUF buffers;// ��ſͻ��˴�����������
	DWORD dwBufferCount = 1;
	char szBuffer[MAX_BUFFER] = { 0 };
	DWORD Flags = 0;
	buffers.buf = szBuffer;
	buffers.len = MAX_BUFFER;

	WSAEVENT Event = WSACreateEvent();
	int ret = WSAEventSelect(sClient, Event, FD_READ | FD_CLOSE);

	while (1)
	{
		ret = WSAEnumNetworkEvents(sClient, Event, &NetWorkEvent);
		if (NetWorkEvent.lNetworkEvents & FD_READ)
		{
			ret = WSARecv(sClient, &buffers, dwBufferCount, &NumberOfBytesRecvd, &Flags, NULL, NULL);
			if (ret == 0)
			{
				// ����Ƿ�õ�����������
				memcpy(szRequest, szBuffer, NumberOfBytesRecvd);
				if (IoComplete(szRequest) && ParseRequest(szRequest, szResponse, bKeepAlive)) // У�����ݰ�
				{
					ResponseClient(szResponse, sClient);// ������Ӧ���ͻ���
				}
			}

			closesocket(sClient);
			break;
		}
		else if (NetWorkEvent.lNetworkEvents & FD_CLOSE)
		{
			closesocket(sClient);
			break;
		}
	}

	return 0;
}

bool InitSocket()
{
	WSADATA wsadata;
	if (WSAStartup(MAKEWORD(2, 2), &wsadata) == 0)    //ʹ��Socketǰ������� ���� ���� ����ֵ
	{
		return true;
	}
	return false;
}

bool AddClientList(SOCKET s, sockaddr_in addr)
{
	pNode pTemp = (pNode)malloc(sizeof(Node));
	HANDLE hThread = NULL;
	DWORD ThreadID = 0;
	if (pTemp == NULL)
	{
		printf("No Memory\n");
		return false;
	}
	else
	{
		pTemp->s = s;
		pTemp->Addr = addr;
		pTemp->pNext = NULL;
		if (pHead == NULL)
		{
			pHead = pTail = pTemp;
		}
		else
		{
			pTail->pNext = pTemp;
			pTail = pTail->pNext;
		}
		//����ҪΪ�û������µ��߳�
		hThread = CreateThread(NULL, 0, ClientThread, (LPVOID)pTemp, 0, &ThreadID);
		if (hThread == NULL)
		{
			free(pTemp);
			return false;
		}
		if (!AddThreadList(hThread, ThreadID))
		{
			free(pTemp);
			return false;
		}
	}
	return true;
}

bool AddThreadList(HANDLE hThread, DWORD ThreadID)
{
	pThread pTemp = (pThread)malloc(sizeof(Thread));
	if (pTemp == NULL)
	{
		printf("No Memory\n");
		return false;
	}
	else
	{
		pTemp->hThread = hThread;
		pTemp->ThreadID = ThreadID;
		pTemp->pNext = NULL;
		if (pHeadThread == NULL)
		{
			pHeadThread = pTailThread = pTemp;
		}
		else
		{
			pTailThread->pNext = pTemp;
			pTailThread = pTailThread->pNext;
		}
	}
	return true;
}

//У�����ݰ�
bool IoComplete(char* szRequest)
{
	char* pTemp = NULL;   //������ʱ��ָ��
	int nLen = strlen(szRequest); //�������ݰ�����
	pTemp = szRequest;
	pTemp = pTemp + nLen - 4; //��λָ��
	if (strcmp(pTemp, "\r\n\r\n") == 0)   //У������ͷ����ĩβ�Ļس����Ʒ��ͻ��з��Լ�����
	{
		return true;
	}
	return false;
}

// ������ͷ�л�ȡ������Դ���ļ���
void GetRqstFileName(char *rqstHeader, char *fileName)
{
	char *str1 = strstr(rqstHeader, " ");
	str1++;
	char *str2 = strstr(str1, " ");
	memcpy(fileName, str1, str2 - str1);
}

// ��Ӧ�ͻ���body������
void AddTestContent(char *resBody)
{
	static int i = 0;
	sprintf(resBody, "hello world %d\n", i);
	i++;
}

//�������ݰ�
bool ParseRequest(char* szRequest, char* szResponse, BOOL &bKeepAlive)
{
	char fileName[20] = { 0 };
	GetRqstFileName(szRequest, fileName);
	if (strcmp(fileName, "/") != 0)
		return false;

	//����һ������ͷ
	char pResponseHeader[512] = { 0 };
	char szStatusCode[20] = { 0 };
	char szContentType[20] = { 0 };
	strcpy(szStatusCode, "200 OK");
	strcpy(szContentType, "text/html");

	char date[128] = "Sat, 11 Mar 2017 21:49 : 51 GMT";

	char resBody[100] = { 0 };
	AddTestContent(resBody);

	sprintf(pResponseHeader, "HTTP/1.0 %s\r\nDate: %s\r\nServer: %s\r\nAccept-Ranges: bytes\r\nContent-Length: %d\r\nConnection: %s\r\nContent-Type: %s\r\n\r\n",
		szStatusCode, date, SERVERNAME, strlen(resBody), "close", szContentType);   //��Ӧ����

	strcpy(szResponse, pResponseHeader);
	strcat(szResponse, resBody);
	printf("%s", szResponse);

	return true;
}