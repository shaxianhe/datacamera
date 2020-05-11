.PHONY:all
all :x install 
	
x:DataFwdCen.cpp SqlCtl.cpp SqlCtl.h
	g++ -o DataFwdCen DataFwdCen.cpp SqlCtl.cpp -I/usr/include/mysql/ -L/usr/lib64/mysql/ -lmysqlclient -std=c++11

install:install.cpp
	g++ -o install install.cpp -I/usr/include/mysql/ -L/usr/lib64/mysql/ -lmysqlclient
	./install
e:
	./DataFwdCen
