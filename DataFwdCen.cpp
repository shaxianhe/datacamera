#include <iostream>	// cin,cout等
#include <iomanip>	// setw等
#include <mysql.h>	// mysql特有
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
#define CLNTNUM 10						//最多10个用户
#define CAMNUM 10						//最多10个摄像头
#define TEMPNUM 50
using namespace std;

char BUF[1000000];						//接收缓冲区
char BUF1[1000000];
int place;								//某个客户端放置的位置
int sndLen, rcvLen;
char ipAddr[INET_ADDRSTRLEN];
string transI_P;
char TIME[20];
string loginHtml;
string errorUserHtml;					//虽然比起loginHtml只是多了报错的一句话,
										//但是为了减少文本处理(要计算长度)
										//采取另外读取一个文件
string errorCamHtml;
string temp;
sql_ctl mariaDB;
int STATUS = 0;							//用户post包的状态

struct CLNT
{
	int sock;							//用户每次点击网页可能在变
	int port;
	/*用户名和密码不一定存在,新用户可能还没有注册*/
	string username;					//登录的用户名 查数据库要用
	string password;					//登录的密码
	char ipAddr[INET_ADDRSTRLEN];		//标记用户ip
	bool identified;					//标记用户是否经过了本地认证,登录之后不允许修改密码
	int cameraNum;						//摄像头编号(不是摄像头的socket)
										//某个用户正在访问的摄像头数据
	bool isWatching;					//已经在看了,没有绑定这一操作
	bool isSignUp;						//正在注册状态 注册完成后清0
	bool isChgPwd;						//正在改密码状态 修改完成后清0
	bool isBreakDown;					//是断开的时候重连,发的get包转给摄像头
	string camcid;						//该用户的摄像头信息,该用户登录成功之后即可获知
	int STATUS;
}clnt[CLNTNUM];

struct CAMERA
{
	int sock;
	char ipAddr[INET_ADDRSTRLEN];		//标记连接的摄像头的IP
	int port;							//端口号
	bool cidAnnounced;					//该摄像头是否声明了其cid
	string camcid;						//摄像头报上来的cid
}cam[CAMNUM];

struct _TEMP
{
	int sock;
	char ipAddr[INET_ADDRSTRLEN];
	int port;
}_temp[TEMPNUM];

/*初始化为守护进程*/
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
	//cout << "buf打印完毕" << endl;
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
	//连接用户认证表
	cout << "连接数据库" << endl;
	mariaDB.connect("root", "1002.lkj555", "localhost",  0, "G1552157");
}

/*设为阻塞非阻塞*/
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

/*推网页*/
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

/*用户名存在报错*/
void SendUsernameExist(int sock)
{
	string usernameExist;
	Loop("usernameExist.html", usernameExist);
	sndLen = send(sock, usernameExist.c_str(), usernameExist.length(), 0);
}
/*用户注册的NCID还未在转发中心注册报错*/
void SendNoNcId(int sock)
{
	string noNcId;
	Loop("noNcId.html", noNcId);
	sndLen = send(sock, noNcId.c_str(), noNcId.length(), 0);
}
/*修改密码的原用户名或密码不正确*/
void SendErrorChg(int sock)
{
	string errorChg;
	Loop("errorChg.html", errorChg);
	sndLen = send(sock, errorChg.c_str(), errorChg.length(), 0);
}
/*两个修改数据库,失败报错,成功回到登录页面*/
bool SignUp(int sock, int clntPlace)
{
	cout << "用户注册:" << endl;
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
	/*网页处理过,不会越界*/
	if (ptr[i] == '%' && ptr[i + 1] == '3' && ptr[i + 2] == 'A')	
		cid += ':';
	i = i + 3;
	for (; ptr[i] != '&'; i++)
		cid += ptr[i];

	cout << "username=" << username << endl;
	cout << "password=" << pwd << endl;
	cout << "     cid=" << cid << endl;

	//encoding(pwd, pwd);
	//cout << "加密密码之后" << pwd << endl;
	/* 设置字符集，否则读出的字符乱码，即使/etc/my.cnf中设置也不行 */
	mysql_set_character_set(&mariaDB.myCont, "gbk");
	if (mariaDB.userexist(username) == 0)
	{
		if (mariaDB.cameraxist(cid) > 0)
		{
			cout << "数据库注册" << endl;
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

/*修改密码如果修改的用户名、或者是原密码不正确，暂不处理*/
bool ChgPwd(int sock, int clntPlace)
{
	cout << "用户修改密码:" << endl;
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
	//cout << "加密密码之后" << oldpwd << endl;
	//encoding(newpwd, newpwd);
	//cout << "加密密码之后" << newpwd << endl;
	if (mariaDB.changePwd(username, oldpwd, newpwd) > 0)
	{
		cout << "修改密码成功" << endl;
		clnt[clntPlace].username = username;
		clnt[clntPlace].password = newpwd;
		clnt[clntPlace].isChgPwd = 0;
		return 1;  //main函数返回登录网页
	}
	else
	{
		cout << "修改密码失败" << endl;
		SendErrorChg(sock);
		return 0;
	}
}

bool RegisterCam(string cid)
{
	if (mariaDB.cameraxist(cid) > 0)
	{
		cout << "摄像头报上的唯一性ID已经注册" << endl;
		FILE *fp;
		fp = fopen("摄像头连接注册日志.log", "a");		
		GetTime();
		fwrite(TIME, 19, 1, fp);
		fprintf(fp, " 摄像头报上的唯一性ID已经注册\r\n");
		fclose(fp);
		return 0;
	}
	else
	{
		cout << "摄像头注册报上的唯一性ID成功" << endl;
		mariaDB.insertcid(cid);
		FILE *fp;
		fp = fopen("摄像头连接注册日志.log", "a");					//追加写
		GetTime();
		fwrite(TIME, 19, 1, fp);
		fprintf(fp, " 摄像头注册报上的唯一性ID成功\r\n");
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
			clnt[clntPlace].STATUS = 3;		//自由确认
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

	/*端口复用*/
	int reuse = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

	/*初始化地址信息*/
	struct sockaddr_in Addr;
	bzero(&Addr, sizeof(Addr));
	Addr.sin_family = AF_INET;
	Addr.sin_addr.s_addr = inet_addr(ipAddr);
	Addr.sin_port = htons(port);

	/*将本地地址绑定到所创建的套接字上*/
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
		if (errno == 11)		//时钟中断可能会导致这个问题
			return 0;
		else
		{
			cout << "accept failed" << endl;
			exit(1);			//很严重
		}
	}
	return 1;
}

bool RecordCam(int place,int rcvLen)
{
	cam[place].camcid = BUF;
	FILE *fp;
	fp = fopen("摄像头连接注册日志.log", "a");					//追加写
	GetTime();
	fwrite(TIME, 19, 1, fp);
	fprintf(fp, " 连接的摄像头信息:%s:%d\r\n", cam[place].ipAddr, cam[place].port);
	fprintf(fp, " 连接的摄像头报上的唯一性ID为:%s\r\n", cam[place].camcid.c_str());

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
		cout << "摄像头唯一性ID不合法" << endl;
		fprintf(fp, " 摄像头唯一性ID不合法\r\n");
		fclose(fp);
		//sleep(20);
		return 0;
	}
	buf[j] = '\0';
	cout << "唯一性ip" << buf << endl;
	j++;	//指向port
	/*先判断ip对不对*/
	regcomp(&regex, pattern1, cflags);
	_status = regexec(&regex, buf, nmatch, pmatch, 0);
	if (_status == REG_NOMATCH)
	{
		cout << "摄像头唯一性ID不合法" << endl;
		fprintf(fp, " 摄像头唯一性ID不合法\r\n");
		fclose(fp);
		//sleep(20);
		return 0;
	}
	else if (_status == 0)
	{
		//cout << "唯一性ip正确" << endl;
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
		//cout << "唯一性port" << port << endl;
		if (j >= rcvLen || k > 5 || atoi(port) > 65535 || atoi(port) < 1 || wrong)
		{
			cout << "摄像头唯一性ID合法" << endl;
			fprintf(fp, " 摄像头唯一性ID不合法\r\n");
			fclose(fp);
			//sleep(20);
			return 0;
		}
		else
		{
			cout << "摄像头唯一性ID合法" << endl;
			RegisterCam(cam[place].camcid);
			fprintf(fp, " 摄像头唯一性ID合法\r\n");
			fclose(fp);
			return 1;
		}
	}
}

void RecordIP(struct sockaddr_in &addr, int connect_fd)
{
	/*记录好ip地址以及port*/
	place = SearchEmpty(1);
	inet_ntop(AF_INET, &(addr.sin_addr), cam[place].ipAddr, sizeof(cam[place].ipAddr));
	cout << "连接的摄像头ip为    :" << cam[place].ipAddr << endl;
	cout << "连接的摄像头的port为:" << ntohs(addr.sin_port) << endl;;

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
	return -1;	//不应该出现这种情况
}

void SendIdentifyWeb(int sock,int ST = 0)
{
	cout << "发送认证网页" << endl;
	if (ST == 0)
		temp = loginHtml;
	else if (ST == 1)
		temp = errorUserHtml;
	else if (ST == 2)
		temp = errorCamHtml;
	else
		cout << "程序bug" << endl;
	sndLen = send(sock, temp.c_str(), temp.length(), 0);
}

bool UserIdentify(int clntPlace)
{
	/*认证失败直接告知信息,认证成功则将所有该用户绑定的摄像头信息返回给用户*/
	cout << "进行用户认证" << endl;
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

	/* 设置字符集，否则读出的字符乱码，即使/etc/my.cnf中设置也不行 */
	mysql_set_character_set(&mariaDB.myCont, "gbk");
	if (mariaDB.confirm(username, password) == 1)
	{
		/*如果认证通过,推送该用户绑定的摄像头的网页*/
		cout << "用户" << username << "认证通过" << endl;
		clnt[clntPlace].identified = 1;
		/*得到cid*/
		mariaDB.findcam(username, clnt[clntPlace].camcid);
		return 1;
	}
	cout << "用户" << username << "认证失败" << endl;
	/*认证失败,推送失败告知网页*/
	return 0;
}

void GetCamInfo(int sock,int clntPlace)
{
	//向对应socket的摄像头服务器发送摄像头信息请求get包
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
	cout << "向摄像头获取页面" << endl;
}

void BindCam(int clntPlace)
{
	cout << "用户" << clnt[clntPlace].sock << "绑定的摄像头为:" << clnt[clntPlace].camcid << endl;
	
	place = IsConnect(clnt[clntPlace].camcid, clntPlace, 1);

	if (place < 0)
	{
		cout << "该NC不在线" << endl;
		clnt[clntPlace].identified = 0;	//表示“认证失败”
		/*给出提示网页*/
		SendIdentifyWeb(clnt[clntPlace].sock, 2);
	}
	else
	{
		clnt[clntPlace].cameraNum = place;
		clnt[clntPlace].isWatching = 1;
		GetCamInfo(cam[place].sock,clntPlace);	//之后将会开始数据转发
	}
}

int main(int argc, char* argv[])
{
	int i;
	InitDaemon();

	InitHtml();

	ConnTable();
	//一个提供给客户连接,一个提供给每个摄像头服务器连接
	int sockForClnt, sockForCam;
	char _ip[20], _port[6];
	ReadConf("sockForClnt", _ip, _port);
	InitBind(sockForClnt, _ip, int(atoi(_port)));
	//ReadConf("sockForCam", _ip, _port);
	//InitBind(sockForCam, _ip, int(atoi(_port)));
	SetBlock(sockForClnt, 0);			//设为非阻塞
	//SetBlock(sockForCam, 0);			//设为非阻塞
	ReadConf("IPTRANS", _ip, _port);
	transI_P = _ip;
	transI_P += _port;
	
	//监听开放给客户的端口
	if (listen(sockForClnt, CLNTNUM) == -1)
	{
		cout << "listen socket failed" << endl;
		exit(0);
	}
	cout << "开始监听端口连接" << endl;
	//监听开放给摄像头服务器的端口
	/*if (listen(sockForCam, CAMNUM) == -1)
	{
		cout << "listen socket failed" << endl;
		exit(0);
	}
	cout << "开始监听摄像头连接" << endl;
	*/
	//初始化客户端信息
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
	//初始化摄像头信息
	for (i = 0; i < CAMNUM; i++)
	{
		cam[i].ipAddr[0] = '*';
		cam[i].cidAnnounced = 0;
	}
	//初始化临时接收信息
	for (i = 0; i < TEMPNUM; i++)
	{
		_temp[i].sock = -1;
		_temp[i].ipAddr[0] = '*';
	}

	fd_set rfd;
	fd_set rfdb;	//备份
	int res;
	//int maxfd = max(sockForClnt,sockForCam);
	int maxfd = sockForClnt;
	int maxfdb = maxfd;
	struct timeval timeout;
	FD_ZERO(&rfdb);
	FD_SET(sockForClnt, &rfdb);
	//FD_SET(sockForCam,  &rfdb);
	//连接的信息
	int connect_fd;
	struct sockaddr_in connect_addr;
	socklen_t connect_len;
	char connect_ip[INET_ADDRSTRLEN];
	cout << "监听socket:" << sockForClnt << endl;
	//cout << "摄像头监听socket:" << sockForCam << endl;
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
			cout << "超时" << endl;
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
					//	cout << "新摄像头发起连接" << endl;
					//	/*某个摄像头加入常连接*/
					//	if (!Accept(sockForCam, connect_fd, connect_addr, connect_len))
					//		continue;
					//	SetBlock(connect_fd, 0);
					//	
					//	/*记录下此摄像头的IP以及PORT 这个和报上来的不一定一样*/
					//	RecordIP(connect_addr, connect_fd);
					//	
					//	/*加入描述符集*/
					//	FD_SET(connect_fd, &rfdb);
					//	if (maxfdb < connect_fd)
					//		maxfdb = connect_fd;
					//	cout << "摄像头"<< connect_fd <<"连接成功"  << endl;
					//	
					////	GetCamInfo(connect_fd, 0);
					//	continue;
					//}
					//else if (i == sockForClnt)
					//{
					//	cout << "新用户发起连接" << endl;
					//	/*某个用户发起了连接*/
					//	/*bug?一旦用户访问了,就一直占坑（不是占sock而是占记录）*/
					//	/*该ip不允许其他用户登录了也就是说*/
					//	if (!Accept(sockForClnt, connect_fd, connect_addr, connect_len))
					//		continue;
					//	SetBlock(connect_fd, 0);
					//	/*判断该用户是否已经经过了认证,
					//	 *网页请求一定时间会自动断开,
					//	 *这里不用cookie来记录用户状态*/
					//	if (maxfdb < connect_fd)
					//		maxfdb = connect_fd;
					//	FD_SET(connect_fd, &rfdb);
					//	cout << "用户" << connect_fd << "连接成功" << endl;
					//	place = SearchPlace(ipAddr, 0);
					//	if (place >= 0)
					//	{
					//		/*该用户已经连接过,不过网页服务器自动断开了连接而已,
					//		 *在这里只需要更新保存的socket
					//		 */
					//		clnt[place].sock = connect_fd;
					//		clnt[place].port = ntohs(connect_addr.sin_port);
					//		cout << "用户"<<connect_fd<<"曾经连接过" << endl;
					//		if(!clnt[place].identified && !clnt[place].isSignUp)
					//			SendIdentifyWeb(i, 0);			//如果是注册,不推送认证网页
					//		else if (clnt[place].isSignUp)
					//			SendSignUp(i);
					//		else if (clnt[place].isChgPwd)
					//			SendChgPwd(i);
					//		else
					//		{
					//			cout << "观看摄像头的时候断开重连" << endl;
					//			clnt[place].isBreakDown = 1;
					//			//BindCam(place);
					//			//cout << "向摄像头发送GET请求结束" << endl;
					//			//continue;
					//		}
					//	}
					//	else
					//	{
					//		/*标记该用户的信息,需要认证*/
					//		place = SearchEmpty(0);
					//		if (place < 0)
					//			continue;	//不管了,容纳的用户满了
					//		clnt[place].sock = connect_fd;
					//		strcpy(clnt[place].ipAddr, ipAddr);
					//		clnt[place].port = ntohs(connect_addr.sin_port);
					//		//cout << "place=" << place << endl;
					//		//cout << clnt[place].ipAddr << endl;
					//		cout << "这是该用户的第一次连接" << endl;
					//	}
					//}
					//
					if (i == sockForClnt)
					{
						cout << "有新的连接请求" << endl;
						/*接收下来放在temp中的空闲位置*/
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
						cout << "连接了socket" << connect_fd << endl;
					}
					else if ((place = SearchPlaceTemp(i)) >= 0)
					{
						cout << "place=" << place << endl;
						/*临时端口接收到信息了*/
						cout << "临时端口接收到消息" << endl;
						res = getpeername(i, (struct sockaddr*)&connect_addr, &connect_len);
						inet_ntop(AF_INET, &(connect_addr.sin_addr), ipAddr, sizeof(ipAddr));
						rcvLen = recv(i, BUF, sizeof(BUF), 0);
						cout << "临时端口接收长度" << rcvLen << endl;
						cout << BUF << endl;
						if (rcvLen < 30)
						{
							/*临时端口是摄像头*/
							/*找一个空的cam记录下此摄像头的IP以及PORT 这个和报上来的不一定一样*/
							RecordIP(connect_addr, i);
							cout << "摄像头" << i << "连接成功" << endl;
							_temp[place].sock = -1;
							_temp[place].ipAddr[0] = '*';
							goto JUDGE;
						}
						else
						{
							/*临时端口是用户*/
							cout << "place=" << place << endl;
							cout << "用户" << i << "连接成功" << endl;
							int clntPlace = SearchPlace(ipAddr, 0);
							if (clntPlace >= 0)
							{
								/*该用户已经连接过,不过网页服务器自动断开了连接而已,
								 *在这里只需要更新保存的socket
								 */
								clnt[clntPlace].sock = i;
								clnt[clntPlace].port = ntohs(connect_addr.sin_port);
							/*	cout << "用户"<< i <<"曾经连接过" << endl;
								if(!clnt[clntPlace].identified && !clnt[clntPlace].isSignUp)
									SendIdentifyWeb(i, 0);			//如果是注册,不推送认证网页
								else if (clnt[clntPlace].isSignUp)
									SendSignUp(i);
								else if (clnt[clntPlace].isChgPwd)
									SendChgPwd(i);
								else
								{
									cout << "观看摄像头的时候断开重连" << endl;
									clnt[clntPlace].isBreakDown = 1;
									_temp[place].sock = -1;
									_temp[place].ipAddr[0] = '*';
									goto JUDGE;
									//BindCam(place);
									//cout << "向摄像头发送GET请求结束" << endl;
									//continue;
								}*/
								_temp[place].sock = -1;
								_temp[place].ipAddr[0] = '*';
								goto JUDGE;
								continue;
							}
							else
							{
								/*标记该用户的信息,需要认证*/
								clntPlace = SearchEmpty(0);
								clnt[clntPlace].sock = i;
								strcpy(clnt[clntPlace].ipAddr, ipAddr);
								clnt[clntPlace].port = ntohs(connect_addr.sin_port);
								//cout << "place=" << place << endl;
								//cout << clnt[place].ipaddr << endl;
								cout << "这是" << i << "用户的第一次连接" << endl;
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
						/*得到发来信息的sock的ip及其端口号*/
						res = getpeername(i, (struct sockaddr*)&connect_addr, &connect_len);
						inet_ntop(AF_INET, &(connect_addr.sin_addr), ipAddr, sizeof(ipAddr));
					JUDGE:
						if (IsCam(i))
						{
							place = SearchPlace(ipAddr, 1, ntohs(connect_addr.sin_port));
							if (!cam[place].cidAnnounced)
							{
								cam[place].cidAnnounced = 1;
								/*BUF里是该摄像头报上来的cid*/
								cout << "摄像头" << i << "报上来的cid为" << BUF << endl;
								cout << "长度为:" << rcvLen << endl;
								if (RecordCam(place, rcvLen))
								{
									if (IsConnect(cam[place].camcid,place) >= 0)
									{
										/*已经有一个摄像头提前声明了这个唯一性标志*/
										/*断开此摄像头*/
										FILE *fp;
										fp = fopen("摄像头连接注册日志.log", "a");					//追加写
										GetTime();
										fwrite(TIME, 19, 1, fp);
										fprintf(fp, " 该摄像头报上的唯一性ID已经有摄像头占用\r\n");
										fclose(fp);
										FD_CLR(i, &rfdb);
										close(i);
										if (i == maxfdb)
											maxfdb--;
										cout << "关后连接摄像头" << i << endl;
										cam[place].ipAddr[0] = '*';
										cam[place].cidAnnounced = 0;
										continue;
									}
									cout << "摄像头" << i << "登录在线" << endl;
									FILE *fp;
									fp = fopen("摄像头连接注册日志.log", "a");					//追加写
									GetTime();
									fwrite(TIME, 19, 1, fp);
									fprintf(fp, " 摄像头%d登录在线\r\n",i);
									fclose(fp);
									sndLen = send(i, "end", 4, 0);
									cout << "向摄像头回复它已经在线" << sndLen << endl;
									continue;
								}
								else
								{
									/*报上来的Id不合法,断开连接*/
									FD_CLR(i, &rfdb);
									close(i);
									if (i == maxfdb)
										maxfdb--;
									cout << "关非法摄像头" << i << endl;
									cam[place].ipAddr[0] = '*';
									cam[place].cidAnnounced = 0;
									continue;
								}
							}
							cout << "从"<< i <<"摄像头读到长为"<<rcvLen<<" 的包" << endl;
							sumRcv += rcvLen;
							//cout << BUF << endl;
							/*摄像头i发送过来信息*/
							place = SearchPlace(ipAddr, 1, ntohs(connect_addr.sin_port));

							if (rcvLen == 0)
							{
								cout << "摄像头" << i << "主动关闭" << endl;
								FD_CLR(i, &rfdb);
								close(i);
								if (i == maxfdb)
									maxfdb--;
								cout << "关摄像头" << i << endl;
								cam[place].ipAddr[0] = '*';
								cam[place].cidAnnounced = 0;
								continue;
							}
							
							/*这里假定只有一个用户正在访问这个摄像头*/
							place = CamToUser(place);
							/*对应用户下线了怎么办*/
							if (clnt[place].sock == -1)
							{
								cout << "该摄像头对应的用户已下线" << endl;
								continue;		//向摄像头发送end？
							}
							int sum_send = 0;
							while (1)
							{
								/*一次性如果写不完*/
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
							cout << "发送摄像头" << i <<" " << sumSen << "字节数据" << endl;
							cout << "接收摄像头" << i <<" " << sumRcv << "字节数据" << endl;
						}
						else
						{
							/*用户socket-i发送过来信息*/
							place = SearchPlace(ipAddr, 0);
							if (rcvLen == 0)
							{
								cout << "用户" << i << "主动关闭" << endl;
								clnt[place].sock = -1;
								FD_CLR(i, &rfdb);
								close(i);
								if (i == maxfdb)
									maxfdb--;
								cout << "关闭用户" << i << endl;
								continue;
							}
							else
							{
								cout << "从" << i << "用户读到长为" << rcvLen << " 的包:" << endl;
								cout << BUF << endl;
								if (!clnt[place].identified)
								{
									/*未经过认证的用户*/
									if (IsGet())
									{
										/*第一次访问网页*/
										SendIdentifyWeb(i, 0);
										continue;
									}
									else if (IsPost(place))
									{
										cout << "是POST包" << endl;
										STATUS = clnt[place].STATUS;
										cout << STATUS << endl;
										/*根据包的内容进行操作*/
										/*点击登录则去认证 STATUS = 0*/
										/*点击注册则跳转到注册页面 STATUS = 1*/
										/*点击修改密码,跳转到修改密码页面 STATUS = 2*/
										switch (STATUS)
										{
										case 0:
											if (UserIdentify(place) == true)
											{
												/*看摄像头是否在线,在线直接开始转发*/
												BindCam(place);
											}
											else
											{
												cout << "推送认证失败页面" << endl;
												SendIdentifyWeb(i, 1);
											}
											break;
										case 1:
											cout << "用户选择注册" << endl;
											clnt[place].isSignUp = 1;
											SendSignUp(i);
											break;
										case 2:
											cout << "用户选择修改密码" << endl;
											clnt[place].isChgPwd = 1;
											SendChgPwd(i);
											break;
										default:
											if (clnt[place].isSignUp)	//表明提交的是注册后信息的页面
											{
												cout << "用户注册信息提交" << endl;
												if (SignUp(i, place))
												{
													/*推送认证登录网页*/
													SendIdentifyWeb(i, 0);
												}
											}
											else if (clnt[place].isChgPwd)
											{
												cout << "用户修改密码信息提交" << endl;
												if (ChgPwd(i, place))
												{
													/*推送认证登录网页*/
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
									cout << "未经过登录认证的用户发送了非POST、GET类型的包" << endl;
									continue;
								}
								else
								{
									/*已经通过了认证全部包都转给摄像头即可*/
									/*找到该用户选择的摄像头,转发*/
									string temp;
									if (clnt[place].isBreakDown  && IsGet())	
									{
										cout << "断开后请求连接的GET包" << endl;
										clnt[place].isBreakDown = 0;
										BindCam(place);
										continue;
									}
									/*找到该用户对应的摄像头,向其转发信息*/
									place = clnt[place].cameraNum;

									int j = 0, k = 0;
									/*所有用户来的POST、GET包的IP都要经过替换*/
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
										cout << "经过修改ip的将要发给摄像头的数据:" << endl;
										cout << temp << endl;
										rcvLen = temp.length();
										memcpy(BUF1, temp.c_str(), temp.length());
									}
									else
										memcpy(BUF1, BUF, rcvLen);
									sndLen = send(cam[place].sock, BUF1, rcvLen, 0);
									cout << "发送给摄像头长为" << sndLen << "的内容" << endl;
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