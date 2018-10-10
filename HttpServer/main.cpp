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


//多线程处理多个客户端的连接
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

bool InitSocket();//线程函数
DWORD WINAPI AcceptThread(LPVOID lpParam);
DWORD WINAPI ClientThread(LPVOID lpParam);
bool IoComplete(char* szRequest);     //数据包的校验函数
bool AddClientList(SOCKET s, sockaddr_in addr);
bool AddThreadList(HANDLE hThread, DWORD ThreadID);
bool ParseRequest(char* szRequest, char* szResponse, BOOL &bKeepAlive);

//我们存放Html文件的目录
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

	//启动一个接受线程
	HANDLE hAcceptThread = CreateThread(NULL, 0, AcceptThread, NULL, 0, NULL);

	// 使用事件模型来实现我们的Web服务器
	WaitForSingleObject(hAcceptThread, INFINITE);
}

DWORD WINAPI AcceptThread(LPVOID lpParam)   //接收线程
{
	//创建一个监听套接字
	SOCKET sListen = WSASocketW(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED); //使用事件重叠的套接字
	if (sListen == INVALID_SOCKET)
	{
		printf("Create Listen Error\n");
		return -1;
	}
	//初始化本服务器的地址
	sockaddr_in LocalAddr;
	LocalAddr.sin_addr.S_un.S_addr = INADDR_ANY;
	LocalAddr.sin_family = AF_INET;
	LocalAddr.sin_port = htons(2000);
	//绑定套接字 80端口
	int Ret = bind(sListen, (sockaddr*)&LocalAddr, sizeof(LocalAddr));
	if (Ret == SOCKET_ERROR)
	{
		printf("Bind Error\n");
		return -1;
	}
	//监听
	listen(sListen, 5);
	//创建一个事件
	WSAEVENT Event = WSACreateEvent();
	if (Event == WSA_INVALID_EVENT)
	{
		printf("Create WSAEVENT Error\n");
		closesocket(sListen);
		CloseHandle(Event);     //创建事件失败 关闭套接字 关闭事件
		return -1;
	}
	//将我们的监听套接字与我们的事件进行关联属性为Accept
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
		//如果有真正的事件我们就进行判断
		WSAEnumNetworkEvents(sListen, Event, &NetWorkEvent);
		ResetEvent(&Event);   //
		if (NetWorkEvent.lNetworkEvents == FD_ACCEPT)
		{
			if (NetWorkEvent.iErrorCode[FD_ACCEPT_BIT] == 0)
			{
				//我们要为新的连接进行接受并申请内存存入链表中
				SOCKET sClient = WSAAccept(sListen, (sockaddr*)&ClientAddr, &nLen, NULL, NULL);
				if (sClient == INVALID_SOCKET)
				{
					continue;
				}
				else
				{
					//如果接收成功我们要把用户的所有信息存放到链表中
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
	//我们将每个用户的信息以参数的形式传入到该线程
	pNode pTemp = (pNode)lpParam;
	SOCKET sClient = pTemp->s; //这是通信套接字
	WSAEVENT Event = WSACreateEvent(); //该事件是与通信套接字关联以判断事件的种类
	WSANETWORKEVENTS NetWorkEvent;
	char szRequest[1024] = { 0 }; //请求报文
	char szResponse[1024] = { 0 }; //响应报文
	BOOL bKeepAlive = FALSE; //是否持续连接
	if (Event == WSA_INVALID_EVENT)
	{
		return -1;
	}
	int Ret = WSAEventSelect(sClient, Event, FD_READ | FD_WRITE | FD_CLOSE); //关联事件和套接字
	DWORD dwIndex = 0;
	while (1)
	{
		dwIndex = WSAWaitForMultipleEvents(1, &Event, FALSE, WSA_INFINITE, FALSE);
		dwIndex = dwIndex - WAIT_OBJECT_0;
		if (dwIndex == WSA_WAIT_TIMEOUT || dwIndex == WSA_WAIT_FAILED)
		{
			continue;
		}
		// 分析什么网络事件产生
		Ret = WSAEnumNetworkEvents(sClient, Event, &NetWorkEvent);
		//其他情况
		if (!NetWorkEvent.lNetworkEvents)
		{
			continue;
		}
		if (NetWorkEvent.lNetworkEvents & FD_READ) //这里很有意思的
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

			//我们在这里要检测是否得到的完整请求
			memcpy(szRequest, szBuffer, NumberOfBytesRecvd);
			if (!IoComplete(szRequest)) //校验数据包
			{
				continue;
			}
			if (!ParseRequest(szRequest, szResponse, bKeepAlive)) //分析数据包
			{
				//我在这里就进行了简单的处理
				continue;
			}
			// 发送响应到客户端
			ResponseClient(szResponse, sClient);

			closesocket(sClient);
			break;
		}

		if (NetWorkEvent.lNetworkEvents & FD_CLOSE)
		{
			//在这里我没有处理，我们要将内存进行释放否则内存泄露
		}

	}
	return 0;
}

DWORD WINAPI ClientThread(LPVOID lpParam)
{
	// 我们将每个用户的信息以参数的形式传入到该线程
	pNode pTemp = (pNode)lpParam;
	SOCKET sClient = pTemp->s;
	char szRequest[1024] = { 0 }; //请求报文
	char szResponse[1024] = { 0 }; //响应报文
	BOOL bKeepAlive = FALSE; //是否持续连接

	DWORD NumberOfBytesRecvd;
	WSANETWORKEVENTS NetWorkEvent;

	WSABUF buffers;// 存放客户端传过来的数据
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
				// 检测是否得到的完整请求
				memcpy(szRequest, szBuffer, NumberOfBytesRecvd);
				if (IoComplete(szRequest) && ParseRequest(szRequest, szResponse, bKeepAlive)) // 校验数据包
				{
					ResponseClient(szResponse, sClient);// 发送响应到客户端
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
	if (WSAStartup(MAKEWORD(2, 2), &wsadata) == 0)    //使用Socket前必须调用 参数 作用 返回值
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
		//我们要为用户开辟新的线程
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

//校验数据包
bool IoComplete(char* szRequest)
{
	char* pTemp = NULL;   //定义临时空指针
	int nLen = strlen(szRequest); //请求数据包长度
	pTemp = szRequest;
	pTemp = pTemp + nLen - 4; //定位指针
	if (strcmp(pTemp, "\r\n\r\n") == 0)   //校验请求头部行末尾的回车控制符和换行符以及空行
	{
		return true;
	}
	return false;
}

// 从请求头中获取请求资源的文件名
void GetRqstFileName(char *rqstHeader, char *fileName)
{
	char *str1 = strstr(rqstHeader, " ");
	str1++;
	char *str2 = strstr(str1, " ");
	memcpy(fileName, str1, str2 - str1);
}

// 响应客户端body的内容
void AddTestContent(char *resBody)
{
	static int i = 0;
	sprintf(resBody, "hello world %d\n", i);
	i++;
}

//分析数据包
bool ParseRequest(char* szRequest, char* szResponse, BOOL &bKeepAlive)
{
	char fileName[20] = { 0 };
	GetRqstFileName(szRequest, fileName);
	if (strcmp(fileName, "/") != 0)
		return false;

	//定义一个回显头
	char pResponseHeader[512] = { 0 };
	char szStatusCode[20] = { 0 };
	char szContentType[20] = { 0 };
	strcpy(szStatusCode, "200 OK");
	strcpy(szContentType, "text/html");

	char date[128] = "Sat, 11 Mar 2017 21:49 : 51 GMT";

	char resBody[100] = { 0 };
	AddTestContent(resBody);

	sprintf(pResponseHeader, "HTTP/1.0 %s\r\nDate: %s\r\nServer: %s\r\nAccept-Ranges: bytes\r\nContent-Length: %d\r\nConnection: %s\r\nContent-Type: %s\r\n\r\n",
		szStatusCode, date, SERVERNAME, strlen(resBody), "close", szContentType);   //响应报文

	strcpy(szResponse, pResponseHeader);
	strcat(szResponse, resBody);
	printf("%s", szResponse);

	return true;
}