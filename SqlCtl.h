#include<sstream>
#include<string>
#include<iostream>
using namespace std;
class sql_ctl{
public:
    MYSQL myCont;
    MYSQL_RES *result;
    MYSQL_ROW sql_row;
    int res;
public:
    int Sql_error;
    sql_ctl();
    ~sql_ctl();
    int connect(string username,string password,string host,int port,string table);
    int confirm(const string& username,const string& password);
    int findcam(const string& username,string& cid);
    int signup(const string& username,const string& password,const string& cid);
    int isexist(const string& id,const string tablename,const string key);
    int userexist(const string& username);
    int cameraxist(const string& cid);
    int changePwd(const string& username,const string& exPwd,const string& newPwd);
    int insert(const string& username, const string& password, const string& cid);
    int insertcid(const string& cid);
    void query(string query_str);
};
const string table1_rows_str[]={"username","password","cid"};//Array of row data
enum table1_rows_enu{user,pwd,camera};
const string table2_rows_str[]={"cid"};
enum table2_rows_enu{cid};
static const char BASE_CODE[] = { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" };
void encoding(const string& ClearText, string& EncryptedText);
