#define database "sdfafas"
#define table1 "user_pwd_camera"
#define table2 "camera"
#include<mysql.h>
#include <string.h>
#include "SqlCtl.h"
using namespace std;

/*Function to decoding EncryptedText*/
void decoding(const string& EncryptedText,string& ClearText)
{
    ClearText=EncryptedText;
}
/*Function to encoding ClearText*/
void encoding(const string& ClearText,string& EncryptedText)
{
    //EncryptedText=ClearText;
	int orgLen = ClearText.length();
	const char * orgData = ClearText.c_str();
	char newData[70];
	char *p1 = NULL;
	char changed[4];
	int temp = 0, t = 0, prepare = 0;

	if (orgData == NULL || orgLen == 0)
		return;

	p1 = newData;
	bzero(p1, 70);
	//cout << "len = " << orgLen << endl;
	while (orgLen > t)
	{
		temp = 0;
		prepare = 0;
		memset(changed, '\0', 4);
		while (temp < 3)
		{
			if (t >= orgLen)
				break;
			prepare = ((prepare << 8) | (orgData[t] & 0xFF));
			t++;
			temp++;
		}
		prepare = (prepare << ((3 - temp) * 8));
		for (int i = 0; i < 4; i++)
		{
			if (temp < i)
				changed[i] = 0x40;
			else
				changed[i] = (prepare >> ((3 - i) * 6)) & 0x3F;
			*p1 = BASE_CODE[changed[i]];
			//cout << BASE_CODE[changed[i]] << endl;
			p1++;
		}
	}
	*p1 = '\0';
	EncryptedText = newData;
	//cout << newData << endl;
}
sql_ctl::sql_ctl()
{
    mysql_init(&myCont);
}
sql_ctl::~sql_ctl()
{
    if (result != NULL)
        mysql_free_result(result);
    mysql_close(&myCont);
}
int sql_ctl::findcam(const string& username,string& cid)
{
	cout << "Start to query camera" << endl;
	string query_str = "select cid from ";
	query_str += table1;
    query_str+=" where username=\"";
    query_str+=username;
    query_str+="\";";
    query(query_str);
	  if(Sql_error==1){
		  cout << "mysql_query failed(" << mysql_error(&myCont) << ")" << endl;
		  return -1;
	  }
    //get data
    sql_row=mysql_fetch_row(result);
    if(NULL==sql_row)
        return 0;
    cid=sql_row[0];
	mysql_free_result(result);
	cout << "Query end" << endl;
    return 1;
}
/*Function to change password.*/
int sql_ctl::changePwd(const string& username,const string& exPwd,const string& newPwd)
{
	cout<<"Start to changePwd"<<endl;
    string query_str;
    query_str=string("select password from ")+string(table1)+string(" where username=\"")+string(username)+string("\";");
	cout << query_str << endl;
    res=mysql_query(&myCont,query_str.c_str());
    if(res)
        return 0;
    result = mysql_store_result(&myCont);
    sql_row=mysql_fetch_row(result);
    string password=sql_row[0];
	//decoding
	string tar_exPwd, tar_newPwd;
	encoding(exPwd, tar_exPwd);
	cout << tar_exPwd << endl << password << endl;
	encoding(newPwd, tar_newPwd);
    if(password== tar_exPwd)
    {
        query_str=string("update ")+string(table1)+string(" set password=\"")+string(tar_newPwd)+string("\" where username=\"")+string(username)+string("\";");
        mysql_query(&myCont,query_str.c_str());
        return 1;
    }
    mysql_free_result(result);
    return 0;
}
int sql_ctl::connect(string username,string password,string host,int port,string table)
{
    return (mysql_real_connect(&myCont, host.c_str(), username.c_str(), password.c_str(), table.c_str(), 0, NULL, 0)==NULL)?0:1;
}
/*Functions to query data from database
  Num of result will be stored in res while result will be stored in result.
  You can use "while (sql_row = mysql_fetch_row(result))" to obtain data from
  result.
  If error, Sql_error wil be set.*/
void sql_ctl::query(string query_str)
{
	  cout<<"Start to query "<<query_str<<endl;
      res=mysql_query(&myCont, query_str.c_str());
      if (!res)
        if ((result = mysql_store_result(&myCont))==NULL) {
            Sql_error=1;
			cout << "mysql_store_result failed" << endl;
    	}
		else
			cout << "select return " << (int)mysql_num_rows(result) << " records" << endl;
      else
          Sql_error=1;
	  cout<<"End query "<< Sql_error<<endl;
}
/*Functions to verify user identity.
  para:
    username:string of username.
    password:string of password
  Note:
    At the end of the function, result will be released.
    */
int sql_ctl::confirm(const string& username,const string& password)
{
	  cout<<"Start to confirm"<<endl;
      table1_rows_enu d=pwd;
      string target_pwd,cleartext;
      string query_str="select password from ";
	  query_str+=table1;
	  query_str+=" where username=\"";
	  query_str+=username;
	  query_str+="\";";
      query(query_str);
	  if(Sql_error==1){
		  cout << "mysql_query failed(" << mysql_error(&myCont) << ")" << endl;
		  return -1;
	  }
      //get data
      sql_row=mysql_fetch_row(result);
      if(NULL==sql_row)
          return 0;
      target_pwd=sql_row[0];
      //decoding
	  encoding(password, cleartext);
	  cout << "cleartext" << cleartext << endl;

      //free result
      mysql_free_result(result);
      //confirm
	  cout<<"Finish confirm"<<endl;
      if (target_pwd ==cleartext)
          return 1;
      return 0;
}
/*Function to handle request of signup of new user*/
int sql_ctl::signup(const string& username,const string& password,const string& cid)
{
      string query_str="select password from ";
	  query_str+=table1;
	  query_str+=" where username=\"";
	  query_str+=username;
	  query_str+="\";";
      query(query_str);
      //get data
      unsigned int num_fields;
      num_fields = mysql_num_fields(result);
	  cout << "fields=" << num_fields << endl;
      if((int)mysql_num_rows(result)>0)
          return 0;
      mysql_free_result(result);
      string encoded;
      encoding(password,encoded);
	  query_str = "insert into ";
	  query_str += table1;
	  query_str += " (";
	  query_str += table1_rows_str[0];
	  query_str += ',';
	  query_str += table1_rows_str[1];
	  query_str += ',';
	  query_str += table1_rows_str[2];
	  query_str += ") values ";
	  query_str += "(\"";
	  query_str += username;
	  query_str += "\",\"";
	  query_str += encoded;
	  query_str += "\",\"";
	  query_str += cid;
	  query_str += "\");";
      query(query_str);

	  cout << "²åÈë" << endl;
	  query_str = "insert into ";
	  query_str += table2;
	  query_str += " (";
	  query_str += table2_rows_str[0];
	  query_str += ") values ";
	  query_str += "(\"";
	  query_str += cid;
	  query_str += "\");";
      query(query_str);
	  Sql_error = 0;
      return 1;
}
int sql_ctl::userexist(const string& username)
{
    return isexist(username,table1,table1_rows_str[0]);
}
int sql_ctl::cameraxist(const string& cid)
{
    return isexist(cid,table2,table2_rows_str[0]);
}
/*
Function to obtain camera with certern cid from database.
*/
int sql_ctl::isexist(const string& id,const string tablename,const string key)
{
	  cout<<"Start to query cameraList"<<endl;
    string query_str;
    query_str="select * from ";
	  query_str+=tablename;
	  query_str+=" where ";
	  query_str+=key;
	  query_str+="=\"";
	  query_str+=id;
	  query_str+="\";";
    query(query_str);
    if(Sql_error==1){
        mysql_free_result(result);
        return -1;
    }
    sql_row=mysql_fetch_row(result);
    if(sql_row==NULL)
        return 0;
    return 1;
}
/*function to change user's camera in database*/
int sql_ctl::insert(const string& username, const string& password, const string& cid)
{
    cout<<"Start to insert camera data for user"<<endl;
    string query_str = "INSERT INTO ";
    query_str+=table1;
    query_str+=" VALUES (\"";
    query_str+=username;
    query_str+="\",\"";
    query_str+=password;
    query_str+="\",\"";
    query_str+=cid;
    query_str+="\");";
    query(query_str);
	Sql_error = 0;
    return 1;
}int sql_ctl::insertcid(const string& cid)
{
    cout<<"Start to insert camera data"<<endl;
    string query_str = "INSERT INTO ";
    query_str+=table2;
    query_str+=" VALUES (\"";
    query_str+=cid;
    query_str+="\");";
    query(query_str);
	Sql_error = 0;
    return 1;
}
