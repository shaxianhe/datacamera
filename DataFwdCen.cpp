#include <iostream>	// cin,cout��
#include <iomanip>	// setw��
#include <mysql.h>	// mysql����
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/stat.h>   
#include <sys/prctl.h>  
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <fstream>
#include <time.h>
#include <regex.h>
#include "SqlCtl.h"
#define CLNTNUM 10						//���10���û�
#define CAMNUM 10						//���10������ͷ
#define TEMPNUM 50
using namespace std;

char BUF[1000000];						//���ջ�����
char BUF1[1000000];
int place;								//ĳ���ͻ��˷��õ�λ��
int sndLen, rcvLen;
char ipAddr[INET_ADDRSTRLEN];
string transI_P;
char TIME[20];
string loginHtml;
string errorUserHtml;					//��Ȼ����loginHtmlֻ�Ƕ��˱����һ�仰,
										//����Ϊ�˼����ı�����(Ҫ���㳤��)
										//��ȡ�����ȡһ���ļ�
string errorCamHtml;
string temp;
sql_ctl mariaDB;
int STATUS = 0;							//�û�post����״̬

struct CLNT
{
	int sock;							//�û�ÿ�ε����ҳ�����ڱ�
	int port;
	/*�û��������벻һ������,���û����ܻ�û��ע��*/
	string username;					//��¼���û��� �����ݿ�Ҫ��
	string password;					//��¼������
	char ipAddr[INET_ADDRSTRLEN];		//����û�ip
	bool identified;					//����û��Ƿ񾭹��˱�����֤,��¼֮�������޸�����
	int cameraNum;						//����ͷ���(��������ͷ��socket)
										//ĳ���û����ڷ��ʵ�����ͷ����
	bool isWatching;					//�Ѿ��ڿ���,û�а���һ����
	bool isSignUp;						//����ע��״̬ ע����ɺ���0
	bool isChgPwd;						//���ڸ�����״̬ �޸���ɺ���0
	bool isBreakDown;					//�ǶϿ���ʱ������,����get��ת������ͷ
	string camcid;						//���û�������ͷ��Ϣ,���û���¼�ɹ�֮�󼴿ɻ�֪
	int STATUS;
}clnt[CLNTNUM];

struct CAMERA
{
	int sock;
	char ipAddr[INET_ADDRSTRLEN];		//������ӵ�����ͷ��IP
	int port;							//�˿ں�
	bool cidAnnounced;					//������ͷ�Ƿ���������cid
	string camcid;						//����ͷ��������cid
}cam[CAMNUM];

struct _TEMP
{
	int sock;
	char ipAddr[INET_ADDRSTRLEN];
	int port;
}_temp[TEMPNUM];

/*��ʼ��Ϊ�ػ�����*/
bool InitDaemon()
{
	pid_t pid;
	
	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGHUP,  SIG_IGN);

	if (pid = fork()) { 
		exit(0); 
	}
	else if (pid < 0) {
		perror("fork");
		exit(EXIT_FAILURE);
	}

	signal(SIGCHLD, SIG_IGN);		

	return 0;
}

void GetTime()
{
	time_t now;
	struct tm * tm_now;
	time(&now);
	tm_now = localtime(&now);
	sprintf(TIME, "%04d-%02d-%02d %02d:%02d:%02d", tm_now->tm_year + 1900, 
							tm_now->tm_mon + 1, tm_now->tm_mday,tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec);
}

void ReadConf(const char * attribute,char *ip,char *port)
{
	FILE *fp;
	fp = fopen("a.conf", "r");	
	char buf[1000];
	while (1)
	{
		fgets(buf, 1000, fp);
		if (strncmp(buf, attribute, strlen(attribute)) == 0)
			break;
	}
	//cout << buf << endl;
	//cout << "buf��ӡ���" << endl;
	int i = 0, j = 0;
	for (; buf[j] != '/'; j++)
		;
	j++;
	for (; buf[j] != ':'; j++, i++)
		ip[i] = buf[j];
	ip[i] = '\0';
	j++;
	for (i = 0; buf[j] != 'D'; j++, i++)
		port[i] = buf[j];

	port[i] = '\0';
	fclose(fp);
	//cout << "ip" << ip << endl;
	//cout << "port" << port << endl;
}

void Loop(const char * html,string &target)
{
	ifstream in(html, ios::in);
	while (getline(in, temp))
	{
		target += temp;
		target += '\n';
	}
	in.close();
	temp = "HTTP/1.1 200 OK\r\n";
	temp += "Server: Apache/2.4.6 (Red Hat Enterprise Linux) PHP/5.4.16\r\n";
	temp += "X-Powered-By: PHP/5.4.16\r\n";
	temp += "Content-Length: ";
	char contentLen[10];
	sprintf(contentLen, "%d", target.length());
	temp += contentLen;
	temp += "\r\n";
	temp += "Content-Type: text/html; charset=gbk\r\n";
	temp += "\r\n";
	temp += target;
	target = temp;
}

void InitHtml()
{
	Loop("login.html", loginHtml);
	Loop("errorUser.html", errorUserHtml);
	Loop("errorCam.html", errorCamHtml);
}

void ConnTable()
{
	//�����û���֤��
	cout << "�������ݿ�" << endl;
	mariaDB.connect("root", "1002.lkj555", "localhost",  0, "G1552157");
}

/*��Ϊ����������*/
bool SetBlock(int sock, bool isblock)
{
	int re = 0;
	int flags = fcntl(sock, F_GETFL, 0);
	if (flags < 0)
		return false;
	if (isblock)
		flags = flags & ~O_NONBLOCK;
	else
		flags = flags | O_NONBLOCK;

	re = fcntl(sock, F_SETFL, flags);
	if (re != 0)
		return false;
	return true;
}

int SearchEmptyTemp()
{
	int i;
	for (i = 0; i < TEMPNUM; i++)
		if (_temp[i].ipAddr[0] == '*')
			return i;
	return -1;
}

int SearchPlaceTemp(int sock)
{
	int i;
	for (i = 0; i < TEMPNUM; i++)
		if (_temp[i].sock == sock)
			return i;
	return -1;
}

int SearchEmpty(bool flag)
{
	int i;
	if (flag = 0)
	{
		for (i = 0; i < CLNTNUM; i++)
			if (clnt[i].ipAddr[0] == '*')
				return i;
		return -1;	

	}
	else
	{
		for (i = 0; i < CAMNUM; i++)
			if (cam[i].ipAddr[0] == '*')
				return i;
		return -1;
	}
}

int SearchPlace(const char *ipAddr,bool flag,int port = -1)
{
	int i;
	if (flag == 0)
	{
		for (i = 0; i < CLNTNUM; i++)
			if (strncmp(clnt[i].ipAddr, ipAddr, strlen(ipAddr)) == 0)
				return i;
		return -1;
	}
	else
	{
		for (i = 0; i < CAMNUM; i++)
			if (strncmp(cam[i].ipAddr, ipAddr, strlen(ipAddr)) == 0 && cam[i].port == port)
				return i;
		return -1;
	}
}

/*����ҳ*/
void SendSignUp(int sock)
{
	string signUpHtml;
	Loop("signup.html", signUpHtml);
	sndLen = send(sock, signUpHtml.c_str(), signUpHtml.length(), 0);
}

void SendChgPwd(int sock)
{
	string chgPwdHtml;
	Loop("changePwd.html", chgPwdHtml);
	sndLen = send(sock, chgPwdHtml.c_str(), chgPwdHtml.length(), 0);
}

/*�û������ڱ���*/
void SendUsernameExist(int sock)
{
	string usernameExist;
	Loop("usernameExist.html", usernameExist);
	sndLen = send(sock, usernameExist.c_str(), usernameExist.length(), 0);
}
/*�û�ע���NCID��δ��ת������ע�ᱨ��*/
void SendNoNcId(int sock)
{
	string noNcId;
	Loop("noNcId.html", noNcId);
	sndLen = send(sock, noNcId.c_str(), noNcId.length(), 0);
}
/*�޸������ԭ�û��������벻��ȷ*/
void SendErrorChg(int sock)
{
	string errorChg;
	Loop("errorChg.html", errorChg);
	sndLen = send(sock, errorChg.c_str(), errorChg.length(), 0);
}
/*�����޸����ݿ�,ʧ�ܱ���,�ɹ��ص���¼ҳ��*/
bool SignUp(int sock, int clntPlace)
{
	cout << "�û�ע��:" << endl;
	string username, pwd, cid;
	char *ptr;
	ptr = strstr(BUF, "USERNAME=");
	ptr = ptr + 9;
	int i = 0;
	for (; ptr[i] != '&'; i++)
		username += ptr[i];
	i = i + 10;
	for (; ptr[i] != '&';i++)
		pwd += ptr[i];
	i = i + 5;
	for (; ptr[i] != '%'; i++)
		cid += ptr[i];
	/*��ҳ�����,����Խ��*/
	if (ptr[i] == '%' && ptr[i + 1] == '3' && ptr[i + 2] == 'A')	
		cid += ':';
	i = i + 3;
	for (; ptr[i] != '&'; i++)
		cid += ptr[i];

	cout << "username=" << username << endl;
	cout << "password=" << pwd << endl;
	cout << "     cid=" << cid << endl;

	//encoding(pwd, pwd);
	//cout << "��������֮��" << pwd << endl;
	/* �����ַ���������������ַ����룬��ʹ/etc/my.cnf������Ҳ���� */
	mysql_set_character_set(&mariaDB.myCont, "gbk");
	if (mariaDB.userexist(username) == 0)
	{
		if (mariaDB.cameraxist(cid) > 0)
		{
			cout << "���ݿ�ע��" << endl;
			mariaDB.signup(username,pwd,cid);
			clnt[clntPlace].username = username;
			clnt[clntPlace].camcid = cid;
			clnt[clntPlace].isSignUp = 0;
			return 1;			
		}
		else
		{
			SendNoNcId(sock);
			return 0;
		}
	}
	else
	{
		SendUsernameExist(sock);
		return 0;
	}
}

/*�޸���������޸ĵ��û�����������ԭ���벻��ȷ���ݲ�����*/
bool ChgPwd(int sock, int clntPlace)
{
	cout << "�û��޸�����:" << endl;
	string username, oldpwd, newpwd;
	char *ptr;
	ptr = strstr(BUF, "\"USERNAME\"");
	ptr = ptr + 14;
	int i = 0;
	for (; ptr[i] != '\r'; i++)
		username += ptr[i];
	ptr = strstr(BUF, "\"oldpassword\"");
	ptr = ptr + 17;
	for (i = 0; ptr[i] != '\r'; i++)
		oldpwd += ptr[i];
	ptr = strstr(BUF, "\"newpassword1\"");
	ptr = ptr + 18;
	for (i = 0; ptr[i] != '\r'; i++)
		newpwd += ptr[i];

	cout << "username=" << username << endl;
	cout << " oldpwd="  << oldpwd   << endl;
	cout << " newpwd="  << newpwd   << endl;

	//encoding(oldpwd, oldpwd);
	//cout << "��������֮��" << oldpwd << endl;
	//encoding(newpwd, newpwd);
	//cout << "��������֮��" << newpwd << endl;
	if (mariaDB.changePwd(username, oldpwd, newpwd) > 0)
	{
		cout << "�޸�����ɹ�" << endl;
		clnt[clntPlace].username = username;
		clnt[clntPlace].password = newpwd;
		clnt[clntPlace].isChgPwd = 0;
		return 1;  //main�������ص�¼��ҳ
	}
	else
	{
		cout << "�޸�����ʧ��" << endl;
		SendErrorChg(sock);
		return 0;
	}
}

bool RegisterCam(string cid)
{
	if (mariaDB.cameraxist(cid) > 0)
	{
		cout << "����ͷ���ϵ�Ψһ��ID�Ѿ�ע��" << endl;
		FILE *fp;
		fp = fopen("����ͷ����ע����־.log", "a");		
		GetTime();
		fwrite(TIME, 19, 1, fp);
		fprintf(fp, " ����ͷ���ϵ�Ψһ��ID�Ѿ�ע��\r\n");
		fclose(fp);
		return 0;
	}
	else
	{
		cout << "����ͷע�ᱨ�ϵ�Ψһ��ID�ɹ�" << endl;
		mariaDB.insertcid(cid);
		FILE *fp;
		fp = fopen("����ͷ����ע����־.log", "a");					//׷��д
		GetTime();
		fwrite(TIME, 19, 1, fp);
		fprintf(fp, " ����ͷע�ᱨ�ϵ�Ψһ��ID�ɹ�\r\n");
		fclose(fp);
		return 1;
	}
}

bool IsGet()
{
	if (strstr(BUF, "GET / HTTP/1.1"))
		return 1;
	return 0;
}

bool IsPost(int clntPlace)
{
	if (strstr(BUF, "POST / HTTP/1.1"))
	{
		if (strstr(BUF, "username") || strstr(BUF, "login"))
			clnt[clntPlace].STATUS = 0;
		else if (strstr(BUF, "SIGNUP"))
			clnt[clntPlace].STATUS = 1;
		else if (strstr(BUF, "CHGPWD"))
			clnt[clntPlace].STATUS = 2;
		else
			clnt[clntPlace].STATUS = 3;		//����ȷ��
		return 1;
	}
	return 0;

}

void InitBind(int &sock,const char * ipAddr,const int port)
{
	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
	{
		cout << "create socket failed" << endl;
		exit(0);
	}

	/*�˿ڸ���*/
	int reuse = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

	/*��ʼ����ַ��Ϣ*/
	struct sockaddr_in Addr;
	bzero(&Addr, sizeof(Addr));
	Addr.sin_family = AF_INET;
	Addr.sin_addr.s_addr = inet_addr(ipAddr);
	Addr.sin_port = htons(port);

	/*�����ص�ַ�󶨵����������׽�����*/
	if (bind(sock, (struct sockaddr *)&Addr, sizeof(Addr)) == -1)
	{
		cout << "bind socket failed" << endl;
		perror("bind");
		exit(0);
	}
}

bool Accept(int & sock, int & connect_fd, 
		struct sockaddr_in &connect_addr, socklen_t &connect_len)
{
	connect_fd = accept(sock,
		(struct sockaddr*)&connect_addr, &connect_len);
	inet_ntop(AF_INET, &(connect_addr.sin_addr), ipAddr, sizeof(ipAddr));
	if (connect_fd == -1)
	{
		if (errno == 11)		//ʱ���жϿ��ܻᵼ���������
			return 0;
		else
		{
			cout << "accept failed" << endl;
			exit(1);			//������
		}
	}
	return 1;
}

bool RecordCam(int place,int rcvLen)
{
	cam[place].camcid = BUF;
	FILE *fp;
	fp = fopen("����ͷ����ע����־.log", "a");					//׷��д
	GetTime();
	fwrite(TIME, 19, 1, fp);
	fprintf(fp, " ���ӵ�����ͷ��Ϣ:%s:%d\r\n", cam[place].ipAddr, cam[place].port);
	fprintf(fp, " ���ӵ�����ͷ���ϵ�Ψһ��IDΪ:%s\r\n", cam[place].camcid.c_str());

	int _status;
	int cflags = REG_EXTENDED;
	regmatch_t pmatch[1];
	const size_t nmatch = 1;
	regex_t regex;
	const char pattern1[] = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]).){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$";
	int j = 0;
	char buf[30];
	char port[10];
	for (;; j++)
	{
		if (BUF[j] != ':')
			buf[j] = BUF[j];
		else
			break;
		if (j > 15)
			break;
	}
	if (j > 15)
	{
		cout << "����ͷΨһ��ID���Ϸ�" << endl;
		fprintf(fp, " ����ͷΨһ��ID���Ϸ�\r\n");
		fclose(fp);
		//sleep(20);
		return 0;
	}
	buf[j] = '\0';
	cout << "Ψһ��ip" << buf << endl;
	j++;	//ָ��port
	/*���ж�ip�Բ���*/
	regcomp(&regex, pattern1, cflags);
	_status = regexec(&regex, buf, nmatch, pmatch, 0);
	if (_status == REG_NOMATCH)
	{
		cout << "����ͷΨһ��ID���Ϸ�" << endl;
		fprintf(fp, " ����ͷΨһ��ID���Ϸ�\r\n");
		fclose(fp);
		//sleep(20);
		return 0;
	}
	else if (_status == 0)
	{
		//cout << "Ψһ��ip��ȷ" << endl;
		int k = 0;
		bool wrong = 0;
		for (;j < rcvLen; k++, j++)
		{
			if (BUF[j] != '\0' && BUF[j] >= '0' && BUF[j] <= '9')
				port[k] = BUF[j];
			else
			{
				if ((BUF[j] < '0' || BUF[j] > '9')&& BUF[j] != '\0')
				{
					cout << "BUF[j] = " << BUF[j] <<"*" << endl;
					wrong = 1;
				}
				break;
			}
			if (k > 5)
				break;
		}
		port[k] = '\0';
		//cout << "Ψһ��port" << port << endl;
		if (j >= rcvLen || k > 5 || atoi(port) > 65535 || atoi(port) < 1 || wrong)
		{
			cout << "����ͷΨһ��ID�Ϸ�" << endl;
			fprintf(fp, " ����ͷΨһ��ID���Ϸ�\r\n");
			fclose(fp);
			//sleep(20);
			return 0;
		}
		else
		{
			cout << "����ͷΨһ��ID�Ϸ�" << endl;
			RegisterCam(cam[place].camcid);
			fprintf(fp, " ����ͷΨһ��ID�Ϸ�\r\n");
			fclose(fp);
			return 1;
		}
	}
}

void RecordIP(struct sockaddr_in &addr, int connect_fd)
{
	/*��¼��ip��ַ�Լ�port*/
	place = SearchEmpty(1);
	inet_ntop(AF_INET, &(addr.sin_addr), cam[place].ipAddr, sizeof(cam[place].ipAddr));
	cout << "���ӵ�����ͷipΪ    :" << cam[place].ipAddr << endl;
	cout << "���ӵ�����ͷ��portΪ:" << ntohs(addr.sin_port) << endl;;

	cam[place].port = ntohs(addr.sin_port);
	cam[place].sock = connect_fd;
}

bool IsCam(int sock)
{
	int i;
	for (i = 0; i < CAMNUM; i++)
		if (cam[i].sock == sock)
			return 1;
	return 0;
}

int IsConnect(string &cid, int place, bool flag = 0)
{
	int i;
	for (i = 0; i < CAMNUM; i++)
		if (cam[i].camcid == cid && cam[i].ipAddr[0] != '*')
		{
			if (flag)
				return i;
			else if (place != i)
				return i;
		}
	return -1;
}

int CamToUser(int cameraNum)
{
	int i;
	for (i = 0; i < CLNTNUM; i++)
		if (clnt[i].cameraNum == cameraNum)
			return i;
	return -1;	//��Ӧ�ó����������
}

void SendIdentifyWeb(int sock,int ST = 0)
{
	cout << "������֤��ҳ" << endl;
	if (ST == 0)
		temp = loginHtml;
	else if (ST == 1)
		temp = errorUserHtml;
	else if (ST == 2)
		temp = errorCamHtml;
	else
		cout << "����bug" << endl;
	sndLen = send(sock, temp.c_str(), temp.length(), 0);
}

bool UserIdentify(int clntPlace)
{
	/*��֤ʧ��ֱ�Ӹ�֪��Ϣ,��֤�ɹ������и��û��󶨵�����ͷ��Ϣ���ظ��û�*/
	cout << "�����û���֤" << endl;
	string username, password;
	char *ptr;
	ptr = strstr(BUF, "username=");
	ptr = ptr + 9;
	int i;
	for (i = 0;ptr[i] != '&'; i++)
		username += ptr[i];
	i += 10;
	for (; ptr[i] != '&'; i++)
		password += ptr[i];
	
	cout << "username:" << username << endl;
	cout << "password:" << password << endl;
	clnt[clntPlace].username = username;
	clnt[clntPlace].password = password;

	/* �����ַ���������������ַ����룬��ʹ/etc/my.cnf������Ҳ���� */
	mysql_set_character_set(&mariaDB.myCont, "gbk");
	if (mariaDB.confirm(username, password) == 1)
	{
		/*�����֤ͨ��,���͸��û��󶨵�����ͷ����ҳ*/
		cout << "�û�" << username << "��֤ͨ��" << endl;
		clnt[clntPlace].identified = 1;
		/*�õ�cid*/
		mariaDB.findcam(username, clnt[clntPlace].camcid);
		return 1;
	}
	cout << "�û�" << username << "��֤ʧ��" << endl;
	/*��֤ʧ��,����ʧ�ܸ�֪��ҳ*/
	return 0;
}

void GetCamInfo(int sock,int clntPlace)
{
	//���Ӧsocket������ͷ��������������ͷ��Ϣ����get��
	string Get;
	Get = "GET / HTTP/1.1\r\n";
	Get += "Host: ";
	Get += transI_P;
	Get += "\r\n";
	/*Get += clnt[clntPlace].ipAddr;
	Get += ":";
	char port[10];
	sprintf(port, "%d", clnt[clntPlace].port);
	Get += port;
	Get += "\r\n";*/
	Get += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0\r\n";
	Get += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
	Get += "Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\n";
	Get += "Accept-Encoding: gzip, deflate\r\n";
	Get += "Connection: keep-alive\r\n";
	Get += "Upgrade-Insecure-Requests: 1\r\n\r\n";
	
	sndLen = send(sock, Get.c_str(), Get.length(), 0);
	cout << "������ͷ��ȡҳ��" << endl;
}

void BindCam(int clntPlace)
{
	cout << "�û�" << clnt[clntPlace].sock << "�󶨵�����ͷΪ:" << clnt[clntPlace].camcid << endl;
	
	place = IsConnect(clnt[clntPlace].camcid, clntPlace, 1);

	if (place < 0)
	{
		cout << "��NC������" << endl;
		clnt[clntPlace].identified = 0;	//��ʾ����֤ʧ�ܡ�
		/*������ʾ��ҳ*/
		SendIdentifyWeb(clnt[clntPlace].sock, 2);
	}
	else
	{
		clnt[clntPlace].cameraNum = place;
		clnt[clntPlace].isWatching = 1;
		GetCamInfo(cam[place].sock,clntPlace);	//֮�󽫻Ὺʼ����ת��
	}
}

int main(int argc, char* argv[])
{
	int i;
	InitDaemon();

	InitHtml();

	ConnTable();
	//һ���ṩ���ͻ�����,һ���ṩ��ÿ������ͷ����������
	int sockForClnt, sockForCam;
	char _ip[20], _port[6];
	ReadConf("sockForClnt", _ip, _port);
	InitBind(sockForClnt, _ip, int(atoi(_port)));
	//ReadConf("sockForCam", _ip, _port);
	//InitBind(sockForCam, _ip, int(atoi(_port)));
	SetBlock(sockForClnt, 0);			//��Ϊ������
	//SetBlock(sockForCam, 0);			//��Ϊ������
	ReadConf("IPTRANS", _ip, _port);
	transI_P = _ip;
	transI_P += _port;
	
	//�������Ÿ��ͻ��Ķ˿�
	if (listen(sockForClnt, CLNTNUM) == -1)
	{
		cout << "listen socket failed" << endl;
		exit(0);
	}
	cout << "��ʼ�����˿�����" << endl;
	//�������Ÿ�����ͷ�������Ķ˿�
	/*if (listen(sockForCam, CAMNUM) == -1)
	{
		cout << "listen socket failed" << endl;
		exit(0);
	}
	cout << "��ʼ��������ͷ����" << endl;
	*/
	//��ʼ���ͻ�����Ϣ
	for (i = 0; i < CLNTNUM; i++)
	{
		clnt[i].ipAddr[0] = '*';
		clnt[i].identified = 0;
		clnt[i].cameraNum = -1;
		clnt[i].isWatching = 0;
		clnt[i].isSignUp = 0;
		clnt[i].isChgPwd = 0;
		clnt[i].isBreakDown = 0;
		clnt[i].STATUS = 0;
	}
	//��ʼ������ͷ��Ϣ
	for (i = 0; i < CAMNUM; i++)
	{
		cam[i].ipAddr[0] = '*';
		cam[i].cidAnnounced = 0;
	}
	//��ʼ����ʱ������Ϣ
	for (i = 0; i < TEMPNUM; i++)
	{
		_temp[i].sock = -1;
		_temp[i].ipAddr[0] = '*';
	}

	fd_set rfd;
	fd_set rfdb;	//����
	int res;
	//int maxfd = max(sockForClnt,sockForCam);
	int maxfd = sockForClnt;
	int maxfdb = maxfd;
	struct timeval timeout;
	FD_ZERO(&rfdb);
	FD_SET(sockForClnt, &rfdb);
	//FD_SET(sockForCam,  &rfdb);
	//���ӵ���Ϣ
	int connect_fd;
	struct sockaddr_in connect_addr;
	socklen_t connect_len;
	char connect_ip[INET_ADDRSTRLEN];
	cout << "����socket:" << sockForClnt << endl;
	//cout << "����ͷ����socket:" << sockForCam << endl;
	int sumSen = 0;
	int sumRcv = 0;
	int ccc = 0;

	while (1)
	{
		rfd = rfdb;
		timeout.tv_sec = 100;
		timeout.tv_usec = 0;
		maxfd = maxfdb;
		cout << "maxfd:" << maxfd << endl;
		res = select(maxfd + 1, &rfd, NULL, NULL, &timeout);
		if (res == 0)
		{
			cout << "��ʱ" << endl;
			continue;
		}
		if (res < 0)
		{
			cout << errno << endl;
			sleep(100);
		}
		connect_len = sizeof(connect_addr);
		if (res > 0)
		{
			for (i = 3; i <= maxfd; i++)
			{
				if (FD_ISSET(i, &rfd))
				{
					//if (i == sockForCam)
					//{
					//	cout << "������ͷ��������" << endl;
					//	/*ĳ������ͷ���볣����*/
					//	if (!Accept(sockForCam, connect_fd, connect_addr, connect_len))
					//		continue;
					//	SetBlock(connect_fd, 0);
					//	
					//	/*��¼�´�����ͷ��IP�Լ�PORT ����ͱ������Ĳ�һ��һ��*/
					//	RecordIP(connect_addr, connect_fd);
					//	
					//	/*������������*/
					//	FD_SET(connect_fd, &rfdb);
					//	if (maxfdb < connect_fd)
					//		maxfdb = connect_fd;
					//	cout << "����ͷ"<< connect_fd <<"���ӳɹ�"  << endl;
					//	
					////	GetCamInfo(connect_fd, 0);
					//	continue;
					//}
					//else if (i == sockForClnt)
					//{
					//	cout << "���û���������" << endl;
					//	/*ĳ���û�����������*/
					//	/*bug?һ���û�������,��һֱռ�ӣ�����ռsock����ռ��¼��*/
					//	/*��ip�����������û���¼��Ҳ����˵*/
					//	if (!Accept(sockForClnt, connect_fd, connect_addr, connect_len))
					//		continue;
					//	SetBlock(connect_fd, 0);
					//	/*�жϸ��û��Ƿ��Ѿ���������֤,
					//	 *��ҳ����һ��ʱ����Զ��Ͽ�,
					//	 *���ﲻ��cookie����¼�û�״̬*/
					//	if (maxfdb < connect_fd)
					//		maxfdb = connect_fd;
					//	FD_SET(connect_fd, &rfdb);
					//	cout << "�û�" << connect_fd << "���ӳɹ�" << endl;
					//	place = SearchPlace(ipAddr, 0);
					//	if (place >= 0)
					//	{
					//		/*���û��Ѿ����ӹ�,������ҳ�������Զ��Ͽ������Ӷ���,
					//		 *������ֻ��Ҫ���±����socket
					//		 */
					//		clnt[place].sock = connect_fd;
					//		clnt[place].port = ntohs(connect_addr.sin_port);
					//		cout << "�û�"<<connect_fd<<"�������ӹ�" << endl;
					//		if(!clnt[place].identified && !clnt[place].isSignUp)
					//			SendIdentifyWeb(i, 0);			//�����ע��,��������֤��ҳ
					//		else if (clnt[place].isSignUp)
					//			SendSignUp(i);
					//		else if (clnt[place].isChgPwd)
					//			SendChgPwd(i);
					//		else
					//		{
					//			cout << "�ۿ�����ͷ��ʱ��Ͽ�����" << endl;
					//			clnt[place].isBreakDown = 1;
					//			//BindCam(place);
					//			//cout << "������ͷ����GET�������" << endl;
					//			//continue;
					//		}
					//	}
					//	else
					//	{
					//		/*��Ǹ��û�����Ϣ,��Ҫ��֤*/
					//		place = SearchEmpty(0);
					//		if (place < 0)
					//			continue;	//������,���ɵ��û�����
					//		clnt[place].sock = connect_fd;
					//		strcpy(clnt[place].ipAddr, ipAddr);
					//		clnt[place].port = ntohs(connect_addr.sin_port);
					//		//cout << "place=" << place << endl;
					//		//cout << clnt[place].ipAddr << endl;
					//		cout << "���Ǹ��û��ĵ�һ������" << endl;
					//	}
					//}
					//
					if (i == sockForClnt)
					{
						cout << "���µ���������" << endl;
						/*������������temp�еĿ���λ��*/
						if (!Accept(sockForClnt, connect_fd, connect_addr, connect_len))
							continue;
						SetBlock(connect_fd, 0);
						if (maxfdb < connect_fd)
							maxfdb = connect_fd;
						FD_SET(connect_fd, &rfdb);
						place = SearchEmptyTemp();
						_temp[place].sock = connect_fd;
						strcpy(_temp[place].ipAddr, ipAddr);
						_temp[place].port = ntohs(connect_addr.sin_port);
						cout << "������socket" << connect_fd << endl;
					}
					else if ((place = SearchPlaceTemp(i)) >= 0)
					{
						cout << "place=" << place << endl;
						/*��ʱ�˿ڽ��յ���Ϣ��*/
						cout << "��ʱ�˿ڽ��յ���Ϣ" << endl;
						res = getpeername(i, (struct sockaddr*)&connect_addr, &connect_len);
						inet_ntop(AF_INET, &(connect_addr.sin_addr), ipAddr, sizeof(ipAddr));
						rcvLen = recv(i, BUF, sizeof(BUF), 0);
						cout << "��ʱ�˿ڽ��ճ���" << rcvLen << endl;
						cout << BUF << endl;
						if (rcvLen < 30)
						{
							/*��ʱ�˿�������ͷ*/
							/*��һ���յ�cam��¼�´�����ͷ��IP�Լ�PORT ����ͱ������Ĳ�һ��һ��*/
							RecordIP(connect_addr, i);
							cout << "����ͷ" << i << "���ӳɹ�" << endl;
							_temp[place].sock = -1;
							_temp[place].ipAddr[0] = '*';
							goto JUDGE;
						}
						else
						{
							/*��ʱ�˿����û�*/
							cout << "place=" << place << endl;
							cout << "�û�" << i << "���ӳɹ�" << endl;
							int clntPlace = SearchPlace(ipAddr, 0);
							if (clntPlace >= 0)
							{
								/*���û��Ѿ����ӹ�,������ҳ�������Զ��Ͽ������Ӷ���,
								 *������ֻ��Ҫ���±����socket
								 */
								clnt[clntPlace].sock = i;
								clnt[clntPlace].port = ntohs(connect_addr.sin_port);
							/*	cout << "�û�"<< i <<"�������ӹ�" << endl;
								if(!clnt[clntPlace].identified && !clnt[clntPlace].isSignUp)
									SendIdentifyWeb(i, 0);			//�����ע��,��������֤��ҳ
								else if (clnt[clntPlace].isSignUp)
									SendSignUp(i);
								else if (clnt[clntPlace].isChgPwd)
									SendChgPwd(i);
								else
								{
									cout << "�ۿ�����ͷ��ʱ��Ͽ�����" << endl;
									clnt[clntPlace].isBreakDown = 1;
									_temp[place].sock = -1;
									_temp[place].ipAddr[0] = '*';
									goto JUDGE;
									//BindCam(place);
									//cout << "������ͷ����GET�������" << endl;
									//continue;
								}*/
								_temp[place].sock = -1;
								_temp[place].ipAddr[0] = '*';
								goto JUDGE;
								continue;
							}
							else
							{
								/*��Ǹ��û�����Ϣ,��Ҫ��֤*/
								clntPlace = SearchEmpty(0);
								clnt[clntPlace].sock = i;
								strcpy(clnt[clntPlace].ipAddr, ipAddr);
								clnt[clntPlace].port = ntohs(connect_addr.sin_port);
								//cout << "place=" << place << endl;
								//cout << clnt[place].ipaddr << endl;
								cout << "����" << i << "�û��ĵ�һ������" << endl;
								_temp[place].sock = -1;
								_temp[place].ipAddr[0] = '*';
								goto JUDGE;
							}
						}
					}
					else
					{
						cout << "-----------------place=" << place << endl;
						rcvLen = recv(i, BUF, sizeof(BUF), 0);
						BUF[rcvLen] = '\0';
						/*�õ�������Ϣ��sock��ip����˿ں�*/
						res = getpeername(i, (struct sockaddr*)&connect_addr, &connect_len);
						inet_ntop(AF_INET, &(connect_addr.sin_addr), ipAddr, sizeof(ipAddr));
					JUDGE:
						if (IsCam(i))
						{
							place = SearchPlace(ipAddr, 1, ntohs(connect_addr.sin_port));
							if (!cam[place].cidAnnounced)
							{
								cam[place].cidAnnounced = 1;
								/*BUF���Ǹ�����ͷ��������cid*/
								cout << "����ͷ" << i << "��������cidΪ" << BUF << endl;
								cout << "����Ϊ:" << rcvLen << endl;
								if (RecordCam(place, rcvLen))
								{
									if (IsConnect(cam[place].camcid,place) >= 0)
									{
										/*�Ѿ���һ������ͷ��ǰ���������Ψһ�Ա�־*/
										/*�Ͽ�������ͷ*/
										FILE *fp;
										fp = fopen("����ͷ����ע����־.log", "a");					//׷��д
										GetTime();
										fwrite(TIME, 19, 1, fp);
										fprintf(fp, " ������ͷ���ϵ�Ψһ��ID�Ѿ�������ͷռ��\r\n");
										fclose(fp);
										FD_CLR(i, &rfdb);
										close(i);
										if (i == maxfdb)
											maxfdb--;
										cout << "�غ���������ͷ" << i << endl;
										cam[place].ipAddr[0] = '*';
										cam[place].cidAnnounced = 0;
										continue;
									}
									cout << "����ͷ" << i << "��¼����" << endl;
									FILE *fp;
									fp = fopen("����ͷ����ע����־.log", "a");					//׷��д
									GetTime();
									fwrite(TIME, 19, 1, fp);
									fprintf(fp, " ����ͷ%d��¼����\r\n",i);
									fclose(fp);
									sndLen = send(i, "end", 4, 0);
									cout << "������ͷ�ظ����Ѿ�����" << sndLen << endl;
									continue;
								}
								else
								{
									/*��������Id���Ϸ�,�Ͽ�����*/
									FD_CLR(i, &rfdb);
									close(i);
									if (i == maxfdb)
										maxfdb--;
									cout << "�طǷ�����ͷ" << i << endl;
									cam[place].ipAddr[0] = '*';
									cam[place].cidAnnounced = 0;
									continue;
								}
							}
							cout << "��"<< i <<"����ͷ������Ϊ"<<rcvLen<<" �İ�" << endl;
							sumRcv += rcvLen;
							//cout << BUF << endl;
							/*����ͷi���͹�����Ϣ*/
							place = SearchPlace(ipAddr, 1, ntohs(connect_addr.sin_port));

							if (rcvLen == 0)
							{
								cout << "����ͷ" << i << "�����ر�" << endl;
								FD_CLR(i, &rfdb);
								close(i);
								if (i == maxfdb)
									maxfdb--;
								cout << "������ͷ" << i << endl;
								cam[place].ipAddr[0] = '*';
								cam[place].cidAnnounced = 0;
								continue;
							}
							
							/*����ٶ�ֻ��һ���û����ڷ����������ͷ*/
							place = CamToUser(place);
							/*��Ӧ�û���������ô��*/
							if (clnt[place].sock == -1)
							{
								cout << "������ͷ��Ӧ���û�������" << endl;
								continue;		//������ͷ����end��
							}
							int sum_send = 0;
							while (1)
							{
								/*һ�������д����*/
								sndLen = send(clnt[place].sock, BUF + sum_send, rcvLen - sum_send, 0);
								if (sndLen < 0)
								{
									cout << errno << endl;
									break;
								}
								sumSen += sndLen;
								sum_send += sndLen;
								//cout << "rcvLen=" << rcvLen << "    senLen=" << sndLen << endl;
								//cout << "sumRcv=" << sumRcv << "    sumSnd=" << sumSen << endl;
								if (sum_send >= rcvLen)
									break;
							}
							cout << "��������ͷ" << i <<" " << sumSen << "�ֽ�����" << endl;
							cout << "��������ͷ" << i <<" " << sumRcv << "�ֽ�����" << endl;
						}
						else
						{
							/*�û�socket-i���͹�����Ϣ*/
							place = SearchPlace(ipAddr, 0);
							if (rcvLen == 0)
							{
								cout << "�û�" << i << "�����ر�" << endl;
								clnt[place].sock = -1;
								FD_CLR(i, &rfdb);
								close(i);
								if (i == maxfdb)
									maxfdb--;
								cout << "�ر��û�" << i << endl;
								continue;
							}
							else
							{
								cout << "��" << i << "�û�������Ϊ" << rcvLen << " �İ�:" << endl;
								cout << BUF << endl;
								if (!clnt[place].identified)
								{
									/*δ������֤���û�*/
									if (IsGet())
									{
										/*��һ�η�����ҳ*/
										SendIdentifyWeb(i, 0);
										continue;
									}
									else if (IsPost(place))
									{
										cout << "��POST��" << endl;
										STATUS = clnt[place].STATUS;
										cout << STATUS << endl;
										/*���ݰ������ݽ��в���*/
										/*�����¼��ȥ��֤ STATUS = 0*/
										/*���ע������ת��ע��ҳ�� STATUS = 1*/
										/*����޸�����,��ת���޸�����ҳ�� STATUS = 2*/
										switch (STATUS)
										{
										case 0:
											if (UserIdentify(place) == true)
											{
												/*������ͷ�Ƿ�����,����ֱ�ӿ�ʼת��*/
												BindCam(place);
											}
											else
											{
												cout << "������֤ʧ��ҳ��" << endl;
												SendIdentifyWeb(i, 1);
											}
											break;
										case 1:
											cout << "�û�ѡ��ע��" << endl;
											clnt[place].isSignUp = 1;
											SendSignUp(i);
											break;
										case 2:
											cout << "�û�ѡ���޸�����" << endl;
											clnt[place].isChgPwd = 1;
											SendChgPwd(i);
											break;
										default:
											if (clnt[place].isSignUp)	//�����ύ����ע�����Ϣ��ҳ��
											{
												cout << "�û�ע����Ϣ�ύ" << endl;
												if (SignUp(i, place))
												{
													/*������֤��¼��ҳ*/
													SendIdentifyWeb(i, 0);
												}
											}
											else if (clnt[place].isChgPwd)
											{
												cout << "�û��޸�������Ϣ�ύ" << endl;
												if (ChgPwd(i, place))
												{
													/*������֤��¼��ҳ*/
													SendIdentifyWeb(i, 0);
												}
											}
											else
											{
												cout << "   place = " << place << endl;
												cout << "isSignUp = " << clnt[place].isSignUp << endl;
												cout << "isChgPwd = " << clnt[place].isChgPwd << endl;
											}
											break;
										}
										continue;
									}
									cout << "δ������¼��֤���û������˷�POST��GET���͵İ�" << endl;
									continue;
								}
								else
								{
									/*�Ѿ�ͨ������֤ȫ������ת������ͷ����*/
									/*�ҵ����û�ѡ�������ͷ,ת��*/
									string temp;
									if (clnt[place].isBreakDown  && IsGet())	
									{
										cout << "�Ͽ����������ӵ�GET��" << endl;
										clnt[place].isBreakDown = 0;
										BindCam(place);
										continue;
									}
									/*�ҵ����û���Ӧ������ͷ,����ת����Ϣ*/
									place = clnt[place].cameraNum;

									int j = 0, k = 0;
									/*�����û�����POST��GET����IP��Ҫ�����滻*/
									if (strstr(BUF, "POST") || strstr(BUF, "GET"))
									{
										for (;; j++)
										{
											temp += BUF[j];
											if (BUF[j] == '\r' && BUF[j + 1] == '\n')
												for (j++;; j++)
												{
													if (BUF[j] == '1')
													{
														temp += transI_P;
														temp += "\r\n";
														for (j++;; j++)
														{
															if (BUF[j] == '\r' && BUF[j + 1] == '\n')
															{
																j += 2;
																goto done;
															}
														}
													}
													temp += BUF[j];
												}
										}
									done:
										temp += (BUF + j);
										cout << "�����޸�ip�Ľ�Ҫ��������ͷ������:" << endl;
										cout << temp << endl;
										rcvLen = temp.length();
										memcpy(BUF1, temp.c_str(), temp.length());
									}
									else
										memcpy(BUF1, BUF, rcvLen);
									sndLen = send(cam[place].sock, BUF1, rcvLen, 0);
									cout << "���͸�����ͷ��Ϊ" << sndLen << "������" << endl;
								}
							}
						}
					}
				}
			}
		}
	}
    return 0;
}