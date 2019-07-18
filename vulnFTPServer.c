


#include "winsock.h"
#include "windows.h"
#include <stdio.h>
#include <string.h>

//load windows socket
#pragma comment(lib, "wsock32.lib")

//Define Return Messages
#define SS_ERROR 1
#define SS_OK 0

WORD sockVersion;
WSADATA wsaData;
int rVal;
char Message[5000]=" ";
char buf[2000]=" ";
int iSendResult;
int iResult;
SOCKET serverSocket;
SOCKADDR_IN sin;
SOCKET clientSocket;
int bytesRecv = SOCKET_ERROR;
char UserName[31]=" ";
char Password[31]=" ";
char FTPcommand[100] = " ";
char lpFullDirectory[1000]; /* LPSTR = chat */
char lpDirectoryOnly[1000];
char lpDirCmd[1000] = "dir ";
char lpQuote[2] = "\x22\x00";
char lpDirResult[2000];
char lpDirResult2[2000];
char c2[3];
char c3[4];
char c4[5];
char c5[6];
char c6[7];
DWORD nSize;


int GetLocalDirectory()
{

	GetModuleFileName(NULL, lpFullDirectory, 1000);

	//printf("\n");
	//printf(lpFullDirectory);
	//printf("\n");
	GetPathOnly();
	return 0;

}

int GetPathOnly()
{

	char c;
	int i;
	int f;
	int s=0;

	for (i=0; i<1000; i++)
	{
		c = lpFullDirectory[i];
		if (c==0)
		{
			
			//printf("found end of string at position %d\n",i);
			f=i;
			break;

		}
		if (c==92)
		{
			//printf("found slash at position %d\n",i);
			s=i;
		}

	}
	if (s>0 )
	{
		strncpy(lpDirectoryOnly,lpFullDirectory,s);
		//printf("lpdirectoryonly = %s\n",lpDirectoryOnly);
		strcat(lpDirCmd,lpQuote);
		strcat(lpDirCmd,lpDirectoryOnly);
		strcat(lpDirCmd,lpQuote);
		//printf("executing %s\n",lpDirCmd);
		
		//FILE *ls = _popen(lpDirCmd,"r");
		FILE *ls = _popen("dir","r");
		while (fgets(lpDirResult2,128,ls))
		{
			printf(lpDirResult2);
			// ^^^^ this lpDirResult can be used to pipe the output of the popen command
			// to a buffer - you can then use it to print the result to your winsock channel
			strcat(lpDirResult,lpDirResult2);
			s=0;
			
		}
		_pclose(ls);
	} 


}


void sendbanner()
{

	const char *sendbanner = "220 VulnFTP Ready\x0d\x0aUSER: ";
	iSendResult = send(clientSocket, sendbanner, strlen(sendbanner), 0);
    if (iSendResult == SOCKET_ERROR) 
	{
		printf("send failed: %d\n", WSAGetLastError());
        closesocket(clientSocket);
        WSACleanup();
        return 1;
	}

}

void sendpasswordrequest()
{
	const char *sendpasswordrequest = "\x0d\x0aPASSWORD: ";
	iSendResult = send(clientSocket, sendpasswordrequest, strlen(sendpasswordrequest), 0);
    if (iSendResult == SOCKET_ERROR) 
	{
		printf("send failed: %d\n", WSAGetLastError());
        closesocket(clientSocket);
        WSACleanup();
        return 1;
	}

}

void sendFTPprompt()
{
	const char *sendFTPprompt = "\x0d\x0aftp> ";
	iSendResult = send(clientSocket, sendFTPprompt, strlen(sendFTPprompt), 0);
    if (iSendResult == SOCKET_ERROR) 
	{
		printf("send failed: %d\n", WSAGetLastError());
        closesocket(clientSocket);
        WSACleanup();
        return 1;
	}

}

void sendanonymousbanner()
{
	const char *sendanonymousbanner = "\x0d\x0a331 Anonymous access allowed, send identity (e-mail name) as password.";
	iSendResult = send(clientSocket,sendanonymousbanner , strlen(sendanonymousbanner), 0);
    if (iSendResult == SOCKET_ERROR) 
	{
		printf("send failed: %d\n", WSAGetLastError());
        closesocket(clientSocket);
        WSACleanup();
        return 1;
	}

}

void sendloggedinbanner()
{
	const char *sendanonymousbanner = "\x0d\x0a230 User logged in.\n";
	
	iSendResult = send(clientSocket, "\x0d\x0a230 User logged in.\n", strlen("\x0d\x0a230 User logged in.\n"), 0);
    if (iSendResult == SOCKET_ERROR) 
	{
		printf("send failed: %d\n", WSAGetLastError());
        closesocket(clientSocket);
        WSACleanup();
        return 1;
	}


}

void sendlsbanner()
{
//lpDirResult

	iSendResult = send(clientSocket, lpDirResult, strlen(lpDirResult), 0);
	//printf(lpDirResult);
    if (iSendResult == SOCKET_ERROR) 
	{
		printf("send failed: %d\n", WSAGetLastError());
        closesocket(clientSocket);
        WSACleanup();
        return 1;
	}


}

void getusername()
{

	bytesRecv = SOCKET_ERROR;
	while( bytesRecv == SOCKET_ERROR )
	{
	   //receive the data that is being sent by the client max limit to 5000 bytes.
	   bytesRecv = recv( clientSocket, UserName, 30, 0 );

	   if ( bytesRecv == 0 || bytesRecv == WSAECONNRESET )
	   {
	      printf( "\nNo Username received. Connection Closed.\n");
	      break;
	   }
	   else
		{
			int lusername = 0;
			lusername =  strlen(UserName);
			if (lusername > 8) 
			{
				char *c3 = malloc(10);
				strncpy(c3,UserName,9);
				if (strcmp(c3,"anonymous")==0)
				{
					printf("\nanonymous");
					sendanonymousbanner();
				}

			}


		}
	}

}

void getpassword()
{

	bytesRecv = SOCKET_ERROR;
	while( bytesRecv == SOCKET_ERROR )
	{
	   //receive the data that is being sent by the client max limit to 5000 bytes.
	   bytesRecv = recv( clientSocket, Password, 30, 0 );

	   if ( bytesRecv == 0 || bytesRecv == WSAECONNRESET )
	   {
	      printf( "\nNo Password received. Connection Closed.\n");
	      break;
	   }
	   else
		{


		}
	}

}

void getFTPcommand()
{

	bytesRecv = SOCKET_ERROR;
	while( bytesRecv == SOCKET_ERROR )
	{
	   //receive the data that is being sent by the client max limit to 1000 bytes.
	   bytesRecv = recv( clientSocket, FTPcommand, 1000, 0 );

	   if ( bytesRecv == 0 || bytesRecv == WSAECONNRESET )
	   {
	      printf( "\nNo FTP Command received. Connection Closed.\n");
	      break;
	   }
	   else
		{

			int lFTPcommand = 0;
			lFTPcommand =  strlen(FTPcommand);
			
			
			//char *c6 = malloc(7);
			//char *c5 = malloc(6);
			//char *c4 = malloc(5);
			//char *c2 = malloc(3);
			//char *c3 = malloc(4);
			strncpy(c4,FTPcommand,4);
			strncpy(c2,FTPcommand,2);
			strncpy(c3,FTPcommand,3);
			if (strcmp(c2,"LS")==0)
			{
				printf("\nLS\n");
				sendlsbanner();
				if (lFTPcommand>5)
				{
					overflow(FTPcommand);
				}
			}

			if (strcmp(c3,"DEL")==0)
			{
				printf("\nDEL\n");
				//sendhelpbanner();
				if (lFTPcommand>5)
				{
					overflow(FTPcommand);
				}
			}

			if (strcmp(c3,"PUT")==0)
			{
				printf("\nPUT\n");
				//sendhelpbanner();
				if (lFTPcommand>5)
				{
					overflow(FTPcommand);
				}
			}

			if (strcmp(c3,"PWD")==0)
			{
				printf("\nPWD\n");
				//sendhelpbanner();
				if (lFTPcommand>5)
				{
					overflow(FTPcommand);
				}
			}

			if (strcmp(c3,"GET")==0)
			{
				printf("\nGET\n");
				//sendhelpbanner();
				if (lFTPcommand>5)
				{
					overflow(FTPcommand);
				}
			}


			if (strcmp(c4,"HELP")==0)
			{
				printf("\nHELP requested\n");
				sendhelpbanner();
				if (lFTPcommand>5)
				{
					overflow(FTPcommand);
				}
			}

			if (strcmp(c4,"SEND")==0)
			{
				printf("\nSENDing file\n");
				//sendsendbanner();
				if (lFTPcommand>5)
				{
					overflow(FTPcommand);
				}
			}

			if (strcmp(c4,"RECV")==0)
			{
				printf("\nRECVing file\n");
				//sendRECVbanner();
				if (lFTPcommand>5)
				{
					overflow(FTPcommand);
				}
			}

			if (strcmp(c4,"OPEN")==0)
			{
				printf("\nOPENing connection\n");
				//sendRECVbanner();
				if (lFTPcommand>5)
				{
					overflow(FTPcommand);
				}
			}

			if (strcmp(c4,"QUIT")==0)
			{
				printf("\nGoodbye\n");
				if (lFTPcommand>5)
				{
					overflow(FTPcommand);
				}
				sendgoodbye();
			}


			


		}
	}

}

int sendhelpbanner()
{
	const char *helpbanner = "\nDEL\tSEND\tHELP\tLS\tPUT\nSTATUS\tAPPEND\tPWD\tTRACE\tASCII\nBINARY\t\GET\tQUIT\tRECV\tOPEN";
	iSendResult = send(clientSocket, helpbanner, strlen(helpbanner), 0);
    if (iSendResult == SOCKET_ERROR) 
	{
		printf("send failed: %d\n", WSAGetLastError());
        closesocket(clientSocket);
        WSACleanup();
        return 1;
	}
}

int sendgoodbye()
{
	const char *Goodbye = "221 GOODBYE.\n";

	iSendResult = send(clientSocket, Goodbye , strlen(Goodbye), 0);
    if (iSendResult == SOCKET_ERROR) 
	{
		printf("send failed: %d\n", WSAGetLastError());
        closesocket(clientSocket);
        WSACleanup();
        return 1;
		exit(0);
	}
	exit(0);

}



int overflow( char *str)
{
   char buf2[100]=" ";
   strcpy(buf2,str);
   return(0);
}



void sError(char *str)
{
   printf("Error %s",str);
   WSACleanup();
}

int main()
{
u_short LocalPort;
LocalPort = 21;

HINSTANCE hinstLib; 
 
// Get a handle to the DLL module.
 
hinstLib = LoadLibrary(TEXT("vulnserverdll.dll")); 

GetLocalDirectory();

//wsock32 initialized for usage
sockVersion = MAKEWORD(1,1);
WSAStartup(sockVersion, &wsaData);

//create server socket
//SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
serverSocket = socket(AF_INET, SOCK_STREAM, 0);

if(serverSocket == INVALID_SOCKET)
{
   sError("Failed socket()");
   return SS_ERROR;
}

//SOCKADDR_IN sin;
sin.sin_family = PF_INET;
sin.sin_port = htons(LocalPort);
sin.sin_addr.s_addr = INADDR_ANY;

//bind the socket
rVal = bind(serverSocket, (LPSOCKADDR)&sin, sizeof(sin));
if(rVal == SOCKET_ERROR)
{
   sError("Failed bind()");
   WSACleanup();
   return SS_ERROR;
}

//get socket to listen
rVal = listen(serverSocket, 10);
if(rVal == SOCKET_ERROR)
{
   sError("Failed listen()");
   WSACleanup();
   return SS_ERROR;
}



//wait for a client to connect
printf("VulnFTP Ready\n");
//SOCKET clientSocket;
clientSocket = accept(serverSocket, NULL, NULL);
if(clientSocket == INVALID_SOCKET)
{
   sError("Failed accept()");
   WSACleanup();
   return SS_ERROR;
}
else
{

	// successful socket opened so send the banner
	sendbanner();
	getusername();
	sendpasswordrequest();
	getpassword();
	sendloggedinbanner();
	sendFTPprompt();
	while (1)
	{
		getFTPcommand();
		sendFTPprompt();
	}
}

//int bytesRecv = SOCKET_ERROR;
bytesRecv = SOCKET_ERROR;
while( bytesRecv == SOCKET_ERROR )
{
   //receive the data that is being sent by the client max limit to 5000 bytes.
   bytesRecv = recv( clientSocket, Message, 5000, 0 );

   if ( bytesRecv == 0 || bytesRecv == WSAECONNRESET )
   {
      printf( "\nConnection Closed.\n");
      break;
   }
   else
	{


	}
}

int l;
int i;
char c;

l = strlen(Message);


//printf("Message is %d\n",l);

//insert badchars: \x0A
for (i=0;i<l;i++)
{
	//printf("looping %d\n",i);
	c = (int)Message[i];

	if (c=='\x0A' || c== '\xEF'  || c=='\x00' || c=='x\OD')
	{
			Message[i]= '\xB0';
	} 	
}

//Pass the data received to the function pr
overflow(Message);

//close client socket
closesocket(clientSocket);
//close server socket
closesocket(serverSocket);

WSACleanup();

return SS_OK;
}

void func1()
{
	int a;
__asm{
	jmp esp
	}
}
